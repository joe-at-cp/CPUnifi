# CPUnifi

Joe Dillig - Check Point Software 2019

Tool used to integrate Ubiquiti Unifi Client data into Check Point's Identity Awareness API

<b>Change Log:</b>
<br>
<b>Version 1.1</b>
+ Added logging output file
+ IDA IDs now use the friendly name of the Unifi site
+ IDA ID session timeout global variable added (default 300 seconds)


<b>Planned enhancments:</b>
- SmartEvent integration to allow Check Point to notify the Unifi controller if a connected client is sending malicious traffic on to the network. The Unifi    API can be used to disconnect and block the offending client for a period of time at that point.
- Integrated script scheduler to run queries without relying on crontab or other scheduler programs.
- More location details for connected clients in IDA ID (specific switches and ports etc)
- Better detection of connected clients when hostname or name is not provided from Unifi controller

<b>Tool Requirements:</b>
- Host machine supporting Python 2.7 and the following python libraries (requests, json, os, urllib3, pickle, argparse)
- Cronjob or similar setup to run this script every X min of interval

<b>Check Point Requirements:</b>
- Gateway(s) and Management server that support the Identity Awareness API
- Access Roles Created and placed in the rule base (Name Format: "Unifi_SITENAME" or "Unifi_SITENAME_SSIDNAME") 

<b>Ubiquiti Requirements:</b>
- Unifi Controller or Cloud Key always available for Unifi API use
- Read Only api user account (Read/Write Required for SmartEvent Integration)


<b>Tool Usage:</b>

- List all Unifi Sites and Details
  ./CPUnifi.py -list

- List all active wired clients on the "default" Unifi site
  ./CPUnifi.py -site default

- List all active wired clients on the "default" Unifi site and create Check Point Identities for each client
  ./CPUnifi.py -site default -ida

- List all active wireless clients connected to the "Wifi" SSID on the "default" Unifi site
  ./CPUnifi.py -site default -ssid Wifi

- List all active wireless clients connected to the "Wifi" SSID on the "default" Unifi site and create Check Point Identities for each client
  ./CPUnifi.py -site default -ssid Wifi -ida

- List all active wireless guest clients connected to the "Wifi" SSID on the "default" Unifi site
  ./CPUnifi.py -site default -ssid Wifi -guests




