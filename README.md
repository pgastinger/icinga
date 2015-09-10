icinga

- add new device to database (SNMP credentials will be stored)
pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1 -s 2 -C snmpcommunity
Hostname: rt-01
IP: 10.20.20.1
Sysdescr: Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.2(4)M2, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2012 by Cisco Systems, Inc.
Compiled Wed 07-Nov-12 12:45 by prod_rel_team
Interfaces:
<Interface(id='1', name='Gi0/1.2',idx='11',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='954559747129',ifoutoctets='954559760053')
<Interface(id='2', name='Gi0/1.1',idx='10',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='113471333482',ifoutoctets='113471336086')
<Interface(id='3', name='Gi0/0.21',idx='13',lastupdate='1441626997',adminstat='1',operstat='1',ifinoctets='34665462859',ifoutoctets='36138714200')
<Interface(id='4', name='Gi0/0.1',idx='12',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='191349938979',ifoutoctets='191349945512')
<Interface(id='8', name='Gi0/1',idx='3',lastupdate='1441279803',adminstat='1',operstat='1',ifinoctets='1069418207231',ifoutoctets='379885321536')

- show devices in database
pi@mymachine #$ ./check_iftraffic5.py -q
<Device(name='rt-01,IP='10.20.20.1')

- show interfaces for specified devices
pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1
Hostname: rt-01
IP: 10.20.20.1
Sysdescr: Cisco IOS Software, C1900 Software (C1900-UNIVERSALK9-M), Version 15.2(2)T, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2011 by Cisco Systems, Inc.
Compiled Tue 15-Nov-11 20:59 by prod_rel_team
Interfaces:
<Interface(id='1', name='Gi0/1.2',idx='11',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='954559747129',ifoutoctets='954559760053')
<Interface(id='2', name='Gi0/1.1',idx='10',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='113471333482',ifoutoctets='113471336086')
<Interface(id='3', name='Gi0/0.21',idx='13',lastupdate='1441626997',adminstat='1',operstat='1',ifinoctets='34665462859',ifoutoctets='36138714200')
<Interface(id='4', name='Gi0/0.1',idx='12',lastupdate='1441188909',adminstat='1',operstat='1',ifinoctets='191349938979',ifoutoctets='191349945512')
<Interface(id='8', name='Gi0/1',idx='3',lastupdate='1441279803',adminstat='1',operstat='1',ifinoctets='1069418207231',ifoutoctets='379885321536')

- return icinga/nagios-syntax for all interfaces (to import them easily)
pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1 -a CiscoRTInterfaceStat

define service {
   service_description         CiscoRTInterfaceStat_Gi0_1.2
   check_command               CiscoRTInterfaceStat!Gi0/1.2
   host_name                   rt-01
   check_period                0000-2400
   notification_period         none
   event_handler_enabled       0
   use                         default-servicetemplate-2-5-3-0-0,default-monitortemplate-1-1-1-1-86400
   contact_groups              admins
}

define service {
   service_description         CiscoRTInterfaceStat_Gi0_1.1
   check_command               CiscoRTInterfaceStat!Gi0/1.1
   host_name                   rt-01
   check_period                0000-2400
   notification_period         none
   event_handler_enabled       0
   use                         default-servicetemplate-2-5-3-0-0,default-monitortemplate-1-1-1-1-86400
   contact_groups              admins
}
...

- get interface statistics with performance data
pi@mymachine #$ ./check_iftraffic5.py -d 10.20.20.1 -i Gi0/1
OK - Interface: Gi0/1 Admin: up Oper: up Description: Trunk to provider | inUse=10.15%, outUse=4.09%, inBW=0.12Mbps, outBW=0.05Mbps, inErrors=0, outErrors=0, warn=75, crit=90
