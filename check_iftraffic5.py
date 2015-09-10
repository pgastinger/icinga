#!/usr/bin/python
#
# Python script for checking Cisco (and other vendors) interface statistics
#
# Depends on pysnmp for polling SNMP oids and sqlalchemy to store the last measured 
# interface statistics in a sqlite database (easy to change to MySQL)
#
# Returns critical if the admin state is up and the oper state down
# Returns warning, if an interface value is > warning threshold
# Returns critical, if an interface value is > critical threshold
#
#
# usage:
#
# - add new device to database (SNMP credentials will be stored)
# pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1 -s 2 -C snmpcommunity
# Hostname: rt-01
# IP: 10.20.20.1
# Sysdescr: Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.2(4)M2, RELEASE SOFTWARE (fc2)
# Technical Support: http://www.cisco.com/techsupport
# Copyright (c) 1986-2012 by Cisco Systems, Inc.
# Compiled Wed 07-Nov-12 12:45 by prod_rel_team
# Interfaces:
# <Interface(id='1', name='Gi0/1.2',idx='11',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='954559747129',ifoutoctets='954559760053')
# <Interface(id='2', name='Gi0/1.1',idx='10',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='113471333482',ifoutoctets='113471336086')
# <Interface(id='3', name='Gi0/0.21',idx='13',lastupdate='1441626997',adminstat='1',operstat='1',ifinoctets='34665462859',ifoutoctets='36138714200')
# <Interface(id='4', name='Gi0/0.1',idx='12',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='191349938979',ifoutoctets='191349945512')
# <Interface(id='8', name='Gi0/1',idx='3',lastupdate='1441279803',adminstat='1',operstat='1',ifinoctets='1069418207231',ifoutoctets='379885321536')
#
# - show devices in database
# pi@mymachine #$ ./check_iftraffic5.py -q
# <Device(name='rt-01,IP='10.20.20.1')
#
# - show interfaces for specified devices
# pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1
# Hostname: rt-01
# IP: 10.20.20.1
# Sysdescr: Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.2(2)T, RELEASE SOFTWARE (fc1)
# Technical Support: http://www.cisco.com/techsupport
# Copyright (c) 1986-2011 by Cisco Systems, Inc.
# Compiled Tue 15-Nov-11 20:59 by prod_rel_team
# Interfaces:
# <Interface(id='1', name='Gi0/1.2',idx='11',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='954559747129',ifoutoctets='954559760053')
# <Interface(id='2', name='Gi0/1.1',idx='10',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='113471333482',ifoutoctets='113471336086')
# <Interface(id='3', name='Gi0/0.21',idx='13',lastupdate='1441626997',adminstat='1',operstat='1',ifinoctets='34665462859',ifoutoctets='36138714200')
# <Interface(id='4', name='Gi0/0.1',idx='12',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='191349938979',ifoutoctets='191349945512')
# <Interface(id='8', name='Gi0/1',idx='3',lastupdate='1441279803',adminstat='1',operstat='1',ifinoctets='1069418207231',ifoutoctets='379885321536')
#
# - return icinga/nagios-syntax for all interfaces (to import them easily)
# pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1 -a CiscoRTInterfaceStat
#
# define service {
#    service_description         CiscoRTInterfaceStat_Gi0_1.2
#    check_command               CiscoRTInterfaceStat!Gi0/1.2
#    host_name                   rt-01
#    check_period                0000-2400
#    notification_period         none
#    event_handler_enabled       0
#    use                         default-servicetemplate-2-5-3-0-0,default-monitortemplate-1-1-1-1-86400
#    contact_groups              admins
# }
#
# define service {
#    service_description         CiscoRTInterfaceStat_Gi0_1.1
#    check_command               CiscoRTInterfaceStat!Gi0/1.1
#    host_name                   rt-01
#    check_period                0000-2400
#    notification_period         none
#    event_handler_enabled       0
#    use                         default-servicetemplate-2-5-3-0-0,default-monitortemplate-1-1-1-1-86400
#    contact_groups              admins
# }
# ...
#
# - get interface statistics with performance data
# pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1 -i Gi0/1
# OK - Interface: Gi0/1 Admin: up Oper: up Description: Trunk to provider | inUse=10.15%, outUse=4.09%, inBW=0.12Mbps, outBW=0.05Mbps, inErrors=0, outErrors=0, warn=75, crit=90
# 
#
# -*- coding: utf-8 -*-
__author__ = "Peter Gastinger"
__copyright__ = "Copyright 2015"
__credits__ = [""]
__license__ = "GPL"
__version__ = "0.01"
__maintainer__ = "Peter Gastinger"
__email__ = "peter.gastinger@gmail.com"
__status__ = "Test"

### global stuff ###
import argparse
import time
import logging
from sys import exit
from pysnmp.entity.rfc3413.oneliner import cmdgen
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, backref

# file with all interfaces for a specified device
engine = create_engine("sqlite:////var/lib/check_iftraffic5/devices.db")
Base = declarative_base()

status_code = dict(OK = 0, WARNING = 1, CRITICAL = 2, UNKNOWN = 3)
if_status = ["up","down","testing","unknown","dormant","notPresent","lowerLayerDown"]
units = dict(bps=1.0, Kbps=1024.0, Mbps=1024.0*1024, Gbps=1024.0*1024*1024)

# snmp variables
snmpIfAdminStatus           = '.1.3.6.1.2.1.2.2.1.7'
snmpIfAlias                 = '.1.3.6.1.2.1.31.1.1.1.18'
snmpIfDescr                 = '.1.3.6.1.2.1.2.2.1.2'
snmpIfHCInBroadcastPkts     = '.1.3.6.1.2.1.31.1.1.1.9'
snmpIfHCInMulticastPkts     = '.1.3.6.1.2.1.31.1.1.1.8'
snmpIfHCInOctets            = '.1.3.6.1.2.1.31.1.1.1.6'
snmpIfHCInUcastPkts         = '.1.3.6.1.2.1.31.1.1.1.7'
snmpIfHCOutBroadcastPkts    = '.1.3.6.1.2.1.31.1.1.1.13'
snmpIfHCOutMulticastPkts    = '.1.3.6.1.2.1.31.1.1.1.12'
snmpIfHCOutOctets           = '.1.3.6.1.2.1.31.1.1.1.10'
snmpIfHCOutUcastPkts        = '.1.3.6.1.2.1.31.1.1.1.11'
snmpIfHCSpeed               = '.1.3.6.1.2.1.31.1.1.1.15'
snmpIfIndex                 = '.1.3.6.1.2.1.2.2.1.1'
snmpifInErrors              = '.1.3.6.1.2.1.2.2.1.14'
snmpIfInOctets              = '.1.3.6.1.2.1.2.2.1.10'
snmpIfName                  = '.1.3.6.1.2.1.31.1.1.1.1'
snmpIfOperStatus            = '.1.3.6.1.2.1.2.2.1.8'
snmpifOutErrors             = '.1.3.6.1.2.1.2.2.1.20'
snmpIfOutOctets             = '.1.3.6.1.2.1.2.2.1.16'
snmpSysDescr                = '.1.3.6.1.2.1.1.1.0'
snmpSysName                 = '.1.3.6.1.2.1.1.5.0'

### classes ###
class SNMPConfig(Base):
    __tablename__ = 'snmpconfig'

    id = Column(Integer,primary_key=True)
    port = Column(Integer)
    version = Column(Integer)
    community = Column(String)
    v3user = Column(String)
    v3authalg = Column(String)
    v3authpw = Column(String)
    v3privalg = Column(String)
    v3privpw = Column(String)
    v3level = Column(String)

    def __repr__(self):
        if self.version in [1,2]:
            return "<SNMPConfig(version='%s', community='%s', port='%s')>"%(self.version, self.community, self.port)
        else:
            return "<SNMPConfig(version='%s', v3user='%s', v3level='%s', v3authalg='%s', v3authpw='%s', " \
                   "v3privalg='%s', v3privpw='%s', port='%s')>"%(self.version, self.v3user, self.v3level,
                                                                 self.v3authalg, self.v3authpw, self.v3privalg,
                                                                 self.v3privpw, self.port)

class Device(Base):
    __tablename__ = 'device'

    id = Column(Integer,primary_key=True)
    hostname = Column(String,unique=True)
    ip = Column(String,unique=True)
    sysdescr = Column(String)
    snmp_id = Column(Integer, ForeignKey('snmpconfig.id'))
    snmp = relationship(SNMPConfig,backref=backref('device',uselist=True))

    def __repr__(self):
        return "<Device(name='%s',IP='%s')"%(self.hostname, self.ip)

class Interface(Base):
    __tablename__= 'interface'

    id = Column(Integer,primary_key=True)
    idx = Column(Integer)
    name = Column(String,default="")
    alias = Column(String,default="")
    desc = Column(String,default="")
    lastupdate = Column(Integer)
    adminstat = Column(Integer)
    operstat = Column(Integer)
    ifinoctets = Column(Integer)
    ifoutoctets = Column(Integer)
    ifouterrors = Column(Integer)
    ifinerrors = Column(Integer)

    device_id = Column(Integer, ForeignKey('device.id'))
    device = relationship(Device,backref=backref('interfaces',uselist=True))

    def __repr__(self):
        return "<Interface(id='%d', name='%s',idx='%s',lastupdate='%s',adminstat='%s',operstat='%s',ifinoctets='%s'," \
               "ifoutoctets='%s')"%(self.id, self.name, self.idx, self.lastupdate, self.adminstat, self.operstat,
                                     self.ifinoctets,self.ifoutoctets)

    def getIcingaServiceConfig(self,servicename):
        servicetemplate="""
define service {
    service_description         %s_%s
    check_command               %s!%s
    host_name                   %s
    check_period                0000-2400
    notification_period         none
    event_handler_enabled       0
    use                         default-servicetemplate-2-5-3-0-0,default-monitortemplate-1-1-1-1-86400
    contact_groups              admins
}"""

        return servicetemplate%(servicename,self.name.replace("/","_"),servicename,self.name,
                                self.device.hostname.split(".")[0])

### functions ###
def getDeviceInfos(snmpconfig):
    hostname = ""
    sysdescr = ""
    results_objs = snmpGet(snmpconfig, snmpSysName)
    if len(results_objs) > 0:
        hostname = results_objs[0][1].prettyPrint()
    results_objs = snmpGet(snmpconfig, snmpSysDescr)
    if len(results_objs) > 0:
        sysdescr = results_objs[0][1].asOctets()
    return hostname, sysdescr

def getDeviceInterfaces(snmpconfig):
    now = int(time.time())
    ifmap = dict()
    ifindex_results = snmpWalk(snmpconfig,snmpIfIndex)
    ifdesc_results = snmpWalk(snmpconfig,snmpIfDescr)
    ifname_results = snmpWalk(snmpconfig,snmpIfName)
    ifalias_results = snmpWalk(snmpconfig,snmpIfAlias)
    if_inoctets_results = snmpWalk(snmpconfig,snmpIfHCInOctets)
    if_outoctets_results = snmpWalk(snmpconfig,snmpIfHCOutOctets)
# use old values, if the new ones don't work
    if len(if_inoctets_results) == 0:
        if_inoctets_results = snmpWalk(snmpconfig,snmpIfInOctets)
    if len(if_outoctets_results) == 0:
        if_outoctets_results = snmpWalk(snmpconfig,snmpIfOutOctets)
    ifInErrors_results = snmpWalk(snmpconfig,snmpifInErrors)
    ifOutErrors_results = snmpWalk(snmpconfig,snmpifOutErrors)
    ifadminstatus = snmpWalk(snmpconfig,snmpIfAdminStatus)
    ifoperstatus = snmpWalk(snmpconfig,snmpIfOperStatus)
    for i in ifindex_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        ifmap[idx] = Interface(idx=idx,lastupdate=now)
    for i in ifname_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].name= value
    for i in ifdesc_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].desc = value
            if not ifmap[idx].name:
                ifmap[idx].name = value
    for i in ifalias_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].alias = value
    for i in if_inoctets_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].ifinoctets = int(value)
    for i in if_outoctets_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].ifoutoctets = int(value)
    for i in ifInErrors_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].ifinerrors = int(value)
    for i in ifOutErrors_results:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].ifouterrors = int(value)
    for i in ifadminstatus:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].adminstat=value
    for i in ifoperstatus:
        idx = i[0][0].prettyPrint().split(".")[-1]
        value = i[0][1].prettyPrint()
        if ifmap.has_key(idx):
            ifmap[idx].operstat=value
    return ifmap

def getInterfaceStatistics(snmpconfig, ifidx):
    # check if there are valid values
    if_inoctets = getSnmpGetValue(snmpconfig, snmpIfHCInOctets,ifidx)
    if not if_inoctets:
        if_inoctets = getSnmpGetValue(snmpconfig, snmpIfInOctets,ifidx)
    if_inoctets = int(if_inoctets)
    logger.debug("ifidx %s ifinoctests %s"%(ifidx, if_inoctets))
    if_outoctets = getSnmpGetValue(snmpconfig, snmpIfHCOutOctets,ifidx)
    if not if_outoctets:
        if_outoctets = getSnmpGetValue(snmpconfig, snmpIfOutOctets,ifidx)
    if_outoctets = int(if_outoctets)
    logger.debug("ifidx %s ifoutoctests %s"%(ifidx, if_outoctets))
    if_inerrors = int(getSnmpGetValue(snmpconfig, snmpifInErrors,ifidx))
    if_outerrors = int(getSnmpGetValue(snmpconfig, snmpifOutErrors,ifidx))
    if_oper_status = int(getSnmpGetValue(snmpconfig, snmpIfOperStatus,ifidx))
    if_admin_status = int(getSnmpGetValue(snmpconfig, snmpIfAdminStatus,ifidx))
    if_alias = getSnmpGetValue(snmpconfig, snmpIfAlias,ifidx)
    if_speed = getSnmpGetValue(snmpconfig, snmpIfHCSpeed,ifidx)
    if if_speed:
        if_speed = int(if_speed) * 1000000
    else:
        if_speed = 0
    return if_oper_status, if_admin_status, if_inoctets, if_outoctets, if_inerrors, if_outerrors, if_alias, if_speed

def getSnmpGetValue(snmpconfig, oid,ifidx):
    val = snmpGet(snmpconfig,oid+"."+str(ifidx))
    if len(val) > 0:
        if val[0][1] != "":
            return val[0][1]
        else:
            return None
    return None

def snmpGet(snmpconfig, oid):
    return snmpQuery(snmpconfig, oid)

def snmpWalk(snmpconfig, oid):
    return snmpQuery(snmpconfig, oid,False)

def snmpQuery(snmpconfig, oid,get=True):
    if snmpconfig.version in [1,2]:
        snmpcredentials = cmdgen.CommunityData(snmpconfig.community,mpModel=snmpconfig.version-1)
    else:
#TODO security level, ignore securitylevel at the moment
        a_alg=cmdgen.usmHMACSHAAuthProtocol
        p_alg=cmdgen.usmAesCfb128Protocol

        if snmpconfig.v3privalg.lower() == "des":
            p_alg=cmdgen.usmDESPrivProtocol
        if snmpconfig.v3authalg.lower() == "md5":
            a_alg=cmdgen.usmHMACMD5AuthProtocol
        snmpcredentials = cmdgen.UsmUserData(snmpconfig.v3user,snmpconfig.v3authpw,snmpconfig.v3privpw,
                                             authProtocol=a_alg,
                                             privProtocol=p_alg)

    logger.debug(snmpcredentials)
    if get:
        errorIndication, errorStatus, errorIndex, varBinds = cmdgen.CommandGenerator().getCmd(
            snmpcredentials,
            cmdgen.UdpTransportTarget((args.device,snmpconfig.port)),
            (oid))
    else:
        errorIndication, errorStatus, errorIndex, varBinds = cmdgen.CommandGenerator().nextCmd(
            snmpcredentials,
            cmdgen.UdpTransportTarget((args.device,snmpconfig.port)),
            (oid))
    if errorIndication:
        print(errorIndication)
        exit(status_code["UNKNOWN"])
    else:
        if errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[-1][int(errorIndex)-1] or '?'
                )
            )
            exit(status_code["UNKNOWN"])
        else:
            return varBinds

### MAIN ###
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='check cisco interface statistics',epilog="This check get all "
                                                                                           "interfaces from the "
                                                                                           "specified device and "
                                                                                           "stores them in a file. If "
                                                                                           "any specified interface "
                                                                                           "is face statistics")
    group_req = parser.add_mutually_exclusive_group(required=True)
    group_req.add_argument('-d','--device',help='Device')
    group_req.add_argument('-q','--query',help='Query database with devices',action='store_true')
    parser.add_argument('-i','--interface',help='Interface')
    parser.add_argument('-s','--snmpversion',help='SNMP version',default="2",type=int)
    parser.add_argument('-S','--snmpport',help='SNMP Port',default="161",type=int)
    parser.add_argument('-C','--community',help='SNMP v1+2 community',default="public")
    parser.add_argument('-u','--snmpv3user',help='SNMP v3 user',default="icinga")
    parser.add_argument('-x','--snmpv3authalg',help='SNMP v3 auth algorithm, default: SHA',default="SHA")
    parser.add_argument('-X','--snmpv3authkey',help='SNMP v3 auth key')
    parser.add_argument('-p','--snmpv3privalg',help='SNMP v3 priv algorithm, default: AES',default="AES")
    parser.add_argument('-P','--snmpv3privkey',help='SNMP v3 priv key')
    parser.add_argument('-l','--snmpv3level',help='SNMP v3 level, default: authPriv',default="authPriv")
    parser.add_argument('-w','--warning',help='warning level',default="75")
    parser.add_argument('-c','--critical',help='warning level',default="90")
    parser.add_argument('-v','--verbose',help='Verbose',action='store_true')
    parser.add_argument('-U','--update',help='Update Interfaces',action='store_true')
    parser.add_argument('-D','--delete',help='Delete Device',action='store_true')
    parser.add_argument('-B','--bytes', help='Output in kilo, mega or gigabyte',choices=['bps', 'Kbps', 'Mbps',
                                                                                         'Gbps'],default="Mbps")
    parser.add_argument('-a','--autodiscovery',help='autodiscovery for Icinga, list nagios service config with '
                                                    'specified servicename, e.g. CiscoSwitch_Interface_Stats')
    args = parser.parse_args()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    logger = logging.getLogger('sqlalchemy.engine')
    hdlr = logging.FileHandler('/tmp/check_iftraffic5.log')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.ERROR)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

# check snmp version
    if args.snmpversion not in [1,2,3]:
        print "Invalid snmp version"
        exit(status_code["UNKNOWN"])

# show all entries in database
    if args.query:
        devices = session.query(Device).all()
        for item in devices:
            print item
        exit(status_code["OK"])

# create file if it does not exist
    if len(session.query(Device).filter(Device.ip==args.device).all()) == 0:
        logger.info("device %s not found in database"%(args.device))

        if args.snmpversion in [1,2]:
            snmpconfig= session.query(SNMPConfig).filter(SNMPConfig.port==args.snmpport).\
                filter(SNMPConfig.community==args.community).filter(SNMPConfig.version==args.snmpversion).first()
            if not snmpconfig:
                snmpconfig = SNMPConfig(version=args.snmpversion,community=args.community,port=args.snmpport)
        else:
            snmpconfig= session.query(SNMPConfig).filter(SNMPConfig.port==args.snmpport).\
                filter(SNMPConfig.v3user==args.snmpv3user).filter(SNMPConfig.v3authalg==args.snmpv3authalg).\
                filter(SNMPConfig.v3authpw==args.snmpv3authkey).filter(SNMPConfig.v3privalg==args.snmpv3privalg).\
                filter(SNMPConfig.v3privpw==args.snmpv3privkey).filter(SNMPConfig.v3level==args.snmpv3level).first()
            if not snmpconfig:
                snmpconfig = SNMPConfig(version=args.snmpversion,v3user=args.snmpv3user,v3authalg=args.snmpv3authalg,
                                    v3authpw=args.snmpv3authkey,v3privalg=args.snmpv3privalg,
                                    v3privpw=args.snmpv3privkey, port=args.snmpport, v3level=args.snmpv3level)
        hostname, sysdescr = getDeviceInfos(snmpconfig)
        dev = Device(hostname=hostname,ip=args.device,sysdescr=sysdescr,snmp=snmpconfig)
        ifmap = getDeviceInterfaces(snmpconfig)
        try:
            session.add(snmpconfig)
            session.add(dev)
            for item in ifmap:
                i = ifmap[item]
                i.device = dev
                session.add(i)
            session.commit()
        except:
            session.rollback()

    dev = session.query(Device).filter(Device.ip==args.device).first()

    if args.delete:
        try:
            session.delete(dev)
            session.commit()
            print "Deleting device %s successful"%(dev)
        except:
            print "Deleting device %s failed"%(dev)
            session.rollback()

    if args.update:
        ifmap = getDeviceInterfaces(dev.snmp)
        try:
            ifaces = session.query(Interface).filter(Interface.device==dev).all()
            for item in ifaces:
                session.delete(item)
            for item in ifmap:
                i = ifmap[item]
                i.device = dev
                session.add(i)
            session.commit()
        except:
            session.rollback()

    ifidx = 0
    iflong = ""
    if args.interface:
        iface = session.query(Interface).filter(Interface.device_id==dev.id).\
            filter(Interface.name==args.interface).all()
        if len(iface) > 1:
            print "More than one interface %s found, aborting"%(iface)
            exit(status_code["UNKNOWN"])
        else:
            iface = iface[0]
        if not iface:
            print "Interface %s not found, aborting"%(args.interface)
            exit(status_code["UNKNOWN"])
# show interfaces for device
    else:
        if args.autodiscovery:
            for item in dev.interfaces:
                if item.adminstat == 1 and item.operstat == 1 and (item.name.lower().startswith("gi") or
                                                                       item.name.lower().startswith("fa") or
                                                                       item.name.lower().startswith("te") or
                                                                       item.name.lower().startswith("et")):
                    print item.getIcingaServiceConfig(args.autodiscovery)
        else:
            print "Hostname: "+dev.hostname
            print "IP: "+dev.ip
            print "Sysdescr: "+dev.sysdescr
            print "Interfaces: "
            for item in dev.interfaces:
                print item
        exit(status_code["OK"])

# current timestamp
    now = int(time.time())
    if_oper_status, if_admin_status, if_inoctets, if_outoctets, if_inerrors, if_outerrors, \
    if_alias, if_speed = getInterfaceStatistics(dev.snmp, iface.idx)
#    logger.debug(getInterfaceStatistics(dev.snmp, iface.idx))

# get old values
    lastupdate = iface.lastupdate
    lastifin = iface.ifinoctets if iface.ifinoctets else 0
    lastifout = iface.ifoutoctets if iface.ifoutoctets else 0
    lastifinerrors = iface.ifinerrors if iface.ifinerrors else 0
    lastifouterrors = iface.ifouterrors if iface.ifouterrors else 0

    hasIfSpeed = True

    inBW = float(if_inoctets - lastifin)/(now - lastupdate) * 8
    outBW = float(if_outoctets - lastifout)/(now - lastupdate) * 8
# if_speed is in bit/second!
    if if_speed != 0:
        inUse = 8 * 100.0 * inBW/if_speed
        outUse = 8 * 100.0 * outBW/if_speed
    else:
        inUse = inBW
        outUse = outBW
        hasIfSpeed = False

# convert units
    inBW = inBW / units[args.bytes]
    outBW = outBW / units[args.bytes]

    inErrors = if_inerrors - lastifinerrors
    outErrors = if_outerrors - lastifouterrors

    logger.debug("check interval: %d seconds"%(now - lastupdate))

# update values
    iface.lastupdate = now
    iface.lastupdate = now
    iface.ifinoctets = if_inoctets
    iface.ifoutoctets = if_outoctets
    iface.ifinerrors = if_inerrors
    iface.ifouterrors = if_outerrors
    iface.adminstat = if_admin_status
    iface.operstat = if_oper_status

    logger.debug("updating %s %s %s %s"%(args.device,iface.ifinoctets, iface.ifoutoctets, iface))
    logger.debug("last values: inBW %s outBW %s inUse %s outUse %s"%(inBW, outBW, inUse, outUse))

    try:
        session.commit()
    except:
        session.rollback()
        exit(status_code["UNKNOWN"])

    state = "OK"
    if inUse > args.warning or outUse > args.warning:
        state = "WARNING"
    if inUse > args.critical or outUse > args.critical:
        state = "CRITICAL"
    if iface.adminstat == 1 and iface.operstat != 1:
        state = "CRITICAL"

    if hasIfSpeed:
        print "%s - Interface: %s Admin: %s Oper: %s Description: %s | inUse=%.2f%%, outUse=%.2f%%, inBW=%.2f%s," \
              " outBW=%.2f%s, inErrors=%s, outErrors=%s, warn=%s, crit=%s"%(state, iface.name,
                                                                            if_status[if_admin_status-1],
                                                                            if_status[if_oper_status-1], iface.alias,
                                                                            inUse, outUse, inBW,args.bytes, outBW,
                                                                            args.bytes, inErrors, outErrors,
                                                                            args.warning, args.critical)
    else:
        print "%s - Interface: %s Admin: %s Oper: %s Description: %s | inBW=%.2f%s, outBW=%.2f%s, inErrors=%s, " \
              "outErrors=%s, warn=%s, crit=%s"%(state, iface.name, if_status[if_admin_status-1],
                                                if_status[if_oper_status-1],iface.alias, inBW, args.bytes, outBW,
                                                args.bytes, inErrors, outErrors, args.warning, args.critical)

    exit(status_code[state])

