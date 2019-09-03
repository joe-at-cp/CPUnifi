#!/usr/bin/python

#CPUnifi
#Check Point and Ubuiquiti Unifi SDN Integration
#Joe Dillig - Check Point Software 2019 - dillig@checkpoint.com

import requests, json, os, urllib3, pickle, argparse

#Disable the SSL Cert warning on each requests call
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def globalconst():
    
    global CP_MANAGEMENT_IP
    global CP_MANAGEMENT_USER
    global CP_MANAGEMENT_PASS
    global CP_IA_GW
    global CP_IA_GW_SECRET
    global UNIFI_CONTROLLER
    global UNIFI_USER
    global UNIFI_PASS
    global UNIFI_COOKIE

    #Check Point Settings
    CP_MANAGEMENT_IP = "192.168.1.2"
    CP_MANAGEMENT_USER = "api_user"
    CP_MANAGEMENT_PASS = "api_user_password"
    CP_IA_GW = ["192.168.1.3"] #Comma seperated list of gateways to create IDs on
    CP_IA_GW_SECRET = "IDAPI_secret"

    #Unifi Settings
    UNIFI_CONTROLLER="https://192.168.1.1:8443"
    UNIFI_USER="admin"
    UNIFI_PASS="password"
    UNIFI_COOKIE="unifi_session"


def save_cookies(requests_cookiejar, filename):
    with open(filename, 'wb') as f:
        pickle.dump(requests_cookiejar, f)

def load_cookies(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)


#Add Wireless IDA Client
def add_ida_client(CP_IA_GW,CP_IA_GW_SECRET,UNIFI_SITE,UNIFI_SSID,CLIENT_IP,CLIENT_NAME,CLIENT_MAC,CLIENT_DESCRIPTION):
    for CP_GW in CP_IA_GW:
        try:
            headers = {'Content-type': 'application/json'}
            data = {"shared-secret":CP_IA_GW_SECRET,"ip-address":CLIENT_IP,"machine":CLIENT_NAME,"identity-source":"CPUnifi Script","domain":"Unifi_Site_"+UNIFI_SITE+"_"+CLIENT_DESCRIPTION,"calculate-roles":0,"session-timeout":300,"fetch-machine-groups":0,"roles":["Unifi_"+UNIFI_SITE+"_"+UNIFI_SSID]}
            r = requests.get('https://'+CP_GW+'/_IA_API/add-identity', data=json.dumps(data), headers=headers, verify=False)
            pdpreturn = json.loads(r.text)
            #print json.dumps(pdpreturn, indent=4, sort_keys=True)
            print("       \__[IDA "+CP_GW+" >] "+pdpreturn['message'])
        except:
            print("       \__[IDA "+CP_GW+" >] API Connection Failed!")
            pass

#Add Wired IDA Client
def add_wired_ida_client(CP_IA_GW,CP_IA_GW_SECRET,UNIFI_SITE,CLIENT_IP,CLIENT_NAME,CLIENT_MAC,CLIENT_DESCRIPTION):
    for CP_GW in CP_IA_GW:
        try:
            headers = {'Content-type': 'application/json'}
            data = {"shared-secret":CP_IA_GW_SECRET,"ip-address":CLIENT_IP,"machine":CLIENT_NAME,"identity-source":"CPUnifi Script","domain":"Unifi_Site_"+UNIFI_SITE+"_"+CLIENT_DESCRIPTION,"calculate-roles":0,"session-timeout":300,"fetch-machine-groups":0,"roles":["Unifi_"+UNIFI_SITE]}
            r = requests.get('https://'+CP_GW+'/_IA_API/add-identity', data=json.dumps(data), headers=headers, verify=False)
            pdpreturn = json.loads(r.text)
            #print json.dumps(pdpreturn, indent=4, sort_keys=True)
            print("       \__[IDA "+CP_GW+" >] "+pdpreturn['message'])
        except:
            print("       \__[IDA "+CP_GW+" >] API Connection Failed!")
            pass


#List Wireless Clients From Specific Site and SSID
def list_wireless_clients_for_ssid(UNIFI_SITE,UNIFI_SSID):
    print('[+] Wireless Clients For SSID: '+UNIFI_SSID+" (Site: "+UNIFI_SITE+")")
    headers = {'Content-type': 'application/json'}
    data = {}
    r = requests.get(UNIFI_CONTROLLER+'/api/s/'+UNIFI_SITE+'/stat/sta', data=json.dumps(data), cookies=load_cookies(UNIFI_COOKIE), headers=headers, verify=False)
    SITE_ACTIVE_CLIENTS = json.loads(r.text)

    for CLIENT in SITE_ACTIVE_CLIENTS['data']:
        #if CLIENT['essid'] == UNIFI_SSID and CLIENT['is_guest'] == False: #Non Guest SSID Users
        if "essid" in CLIENT:
            if CLIENT['essid'] == UNIFI_SSID and CLIENT['is_guest'] == False:
                #print("---[Client Dump]---")
                #print json.dumps(CLIENT, indent=4, sort_keys=True)
                #print("------")

                if not "hostname" in CLIENT:
                    CLIENT['hostname'] = "UnknownClient"

                if "ip" in CLIENT:
                    print('    [>] '+UNIFI_SSID+','+CLIENT['hostname']+','+CLIENT['ip']+','+CLIENT['mac']) #CSV Output
                    #print("DEBUG: CREATE_IDA_ID="+str(CREATE_IDA_ID))
                    if CREATE_IDA_ID == True:
                        #print("DEBUG: IF STATMENT OK")
                        add_ida_client(CP_IA_GW,CP_IA_GW_SECRET,UNIFI_SITE,UNIFI_SSID,CLIENT['ip'],CLIENT['hostname'],CLIENT['mac'],"Wireless_Client_SSID_"+UNIFI_SSID)
                else:
                    print("    [!] Skipping: "+CLIENT['mac']+" - IP Not Found ")



#List Wireless Guests From Specific Site and SSID
def list_wireless_guests_for_ssid(UNIFI_SITE,UNIFI_SSID):
    print('[+] Wireless Guest Clients For SSID: '+UNIFI_SSID+" (Site: "+UNIFI_SITE+")")
    headers = {'Content-type': 'application/json'}
    data = {}
    r = requests.get(UNIFI_CONTROLLER+'/api/s/'+UNIFI_SITE+'/stat/sta', data=json.dumps(data), cookies=load_cookies(UNIFI_COOKIE), headers=headers, verify=False)
    SITE_ACTIVE_CLIENTS = json.loads(r.text)

    for CLIENT in SITE_ACTIVE_CLIENTS['data']:
        #if CLIENT['essid'] == UNIFI_SSID and CLIENT['is_guest'] == False: #Non Guest SSID Users
        if "essid" in CLIENT:
            if CLIENT['essid'] == UNIFI_SSID and CLIENT['is_guest'] == True:
                #print("---[Guest Client Dump]---")
                #print json.dumps(CLIENT, indent=4, sort_keys=True)
                #print("------")

                if not "hostname" in CLIENT:
                    CLIENT['hostname'] = "UnknownClient"

                if "ip" in CLIENT:
                    print('    [>] '+UNIFI_SSID+','+CLIENT['hostname']+','+CLIENT['ip']+','+CLIENT['mac']) #CSV Output
                    #print("DEBUG: CREATE_IDA_ID="+str(CREATE_IDA_ID))
                    if CREATE_IDA_ID == True:
                        #print("DEBUG: IF STATMENT OK")
                        add_ida_client(CP_IA_GW,CP_IA_GW_SECRET,UNIFI_SITE,UNIFI_SSID,CLIENT['ip'],CLIENT['hostname'],CLIENT['mac'],"Wireless_Guest_Client_SSID_"+UNIFI_SSID)
                else:
                    print("    [!] Skipping: "+CLIENT['mac']+" - IP Not Found ")



#List Wired Clients From Specific Site
def list_wired_clients_for_site(UNIFI_SITE):
    print('[+] Wired Clients For Site: '+UNIFI_SITE)
    headers = {'Content-type': 'application/json'}
    data = {}
    r = requests.get(UNIFI_CONTROLLER+'/api/s/'+UNIFI_SITE+'/stat/sta', data=json.dumps(data), cookies=load_cookies(UNIFI_COOKIE), headers=headers, verify=False)
    SITE_ACTIVE_CLIENTS = json.loads(r.text)

    for CLIENT in SITE_ACTIVE_CLIENTS['data']:
        if "is_wired" in CLIENT:
            if CLIENT['is_wired'] == True and CLIENT['is_guest'] == False:
                #print("---[Client Dump]---")
                #print json.dumps(CLIENT, indent=4, sort_keys=True)
                #print("------")

                if not "hostname" in CLIENT:
                    CLIENT['hostname'] = "UnknownClient"

                if "ip" in CLIENT:
                    print('    [>] '+UNIFI_SITE+','+CLIENT['hostname']+','+CLIENT['ip']+','+CLIENT['mac']) #CSV Output
                    if CREATE_IDA_ID == True:
                        add_wired_ida_client(CP_IA_GW,CP_IA_GW_SECRET,UNIFI_SITE,CLIENT['ip'],CLIENT['hostname'],CLIENT['mac'],"Wired_Client_SWPort_"+str(CLIENT['sw_port']))
                else:
                    print("    [!] Skipping: "+CLIENT['mac']+" - IP Not Found ")


#List Wired Guest Clients From Specific Site
def list_wired_guest_clients_for_site(UNIFI_SITE):
    print('[+] Wired Guest Clients For Site: '+UNIFI_SITE)
    headers = {'Content-type': 'application/json'}
    data = {}
    r = requests.get(UNIFI_CONTROLLER+'/api/s/'+UNIFI_SITE+'/stat/sta', data=json.dumps(data), cookies=load_cookies(UNIFI_COOKIE), headers=headers, verify=False)
    SITE_ACTIVE_CLIENTS = json.loads(r.text)

    for CLIENT in SITE_ACTIVE_CLIENTS['data']:
        if "is_wired" in CLIENT:
            if CLIENT['is_wired'] == True and CLIENT['is_guest'] == True:
                #print("---[Guest Client Dump]---")
                #print json.dumps(CLIENT, indent=4, sort_keys=True)
                #print("------")

                if not "hostname" in CLIENT:
                    CLIENT['hostname'] = "UnknownClient"

                if "ip" in CLIENT:
                    print('    [>] '+UNIFI_SITE+','+CLIENT['hostname']+','+CLIENT['ip']+','+CLIENT['mac']) #CSV Output
                    if CREATE_IDA_ID == True:
                        add_wired_ida_client(CP_IA_GW,CP_IA_GW_SECRET,UNIFI_SITE,CLIENT['ip'],CLIENT['hostname'],CLIENT['mac'],"Wired_Guest_Client_SWPort_"+str(CLIENT['sw_port']))
                else:
                    print("    [!] Skipping: "+CLIENT['mac']+" - IP Not Found ")

#List All Unifi Controller Sites and Desctiptions
def list_unifi_sites():
    print('[+] Listing All Unifi Sites For Controller: '+UNIFI_CONTROLLER)
    headers = {'Content-type': 'application/json'}
    data = {}
    r = requests.get(UNIFI_CONTROLLER+'/api/self/sites', data=json.dumps(data), cookies=load_cookies(UNIFI_COOKIE), headers=headers, verify=False)
    UNIFI_SITES = json.loads(r.text)

    for SITE in UNIFI_SITES['data']:
        print('    [>] Site Name: '+SITE['name'])
        print('        Site Description: '+SITE['desc']) 
        print('        Site ID: '+SITE['_id']) 
        print('        API User Role: '+SITE['role']) 



#Delete Client

#Process Event (From SmartEvent)

#Main
def main():

    global CREATE_IDA_ID
    global CREATE_HOST_OBJECT
    global UNIFI_SSID
    global UNIFI_SITE

    #Process Input Parameters
    parser = argparse.ArgumentParser(prog='Check Point Unifi Tool (Alpha 1.0)', usage='./CPUnifi.py [-list] [-site (name)] [-ssid (name)] [-guests] [-ida] [-hostobj]')

    #Arguments
    parser.add_argument('-list', '--list', help='Lists all Unifi Sites', action='store_true', required=False)
    parser.add_argument('-site', '--site', help='Unifi Site Name or "all"', required=False)
    parser.add_argument('-ssid', '--ssid', help='Unifi SSID or "all"', required=False)
    parser.add_argument('-guests', '--guests', help='Unifi Site Guests', action='store_true', required=False)
    parser.add_argument('-block', '--block', help='Block Unifi Client With MAC Address', required=False)
    parser.add_argument('-unblock', '--unblock', help='Unblocks Unifi Client with MAC Address', required=False) 
    parser.add_argument('-event', '--event', help='Check Point SmartEvent Event', required=False)
    parser.add_argument('-ida', '--ida', help='Create Check Point IDA Identities', action='store_true', required=False)
    parser.add_argument('-hostobj', '--hostobj', help='Create Check Point Host Objects', action='store_true', required=False)

    #Parse and Store Args
    args = parser.parse_args()
    global CONSOLE_ARGUMENTS
    CONSOLE_ARGUMENTS = args

    UNIFI_LIST = args.list
    UNIFI_GUESTS = args.guests
    UNIFI_SITE = args.site
    UNIFI_SSID = args.ssid
    UNIFI_BLOCK = args.block
    UNIFI_UNBLOCK = args.unblock
    SE_EVENT = args.event
    CP_IDA = args.ida
    CP_HOSTOBJ = args.hostobj

    #Authenticate to Unifi Controller and Store Session Cookie
    headers = {'Content-type': 'application/json'}
    data = {'username':UNIFI_USER, 'password':UNIFI_PASS}
    r = requests.post(UNIFI_CONTROLLER+'/api/login', data=json.dumps(data), headers=headers, verify=False)
    save_cookies(r.cookies, UNIFI_COOKIE)
    hostreturn = json.loads(r.text)

    if CP_IDA == True:
        CREATE_IDA_ID = True
    else:
        CREATE_IDA_ID = False

    if CP_HOSTOBJ == True:
        CREATE_HOST_OBJECT = True
    else:
        CREATE_HOST_OBJECT = False

    if UNIFI_LIST == True:
        list_unifi_sites()

    if UNIFI_SITE and not UNIFI_SSID and UNIFI_GUESTS == False:
        #Wired Clients
        list_wired_clients_for_site(UNIFI_SITE)

    if UNIFI_SITE and not UNIFI_SSID and UNIFI_GUESTS == True:
        #Wired Guest Clients
        list_wired_guest_clients_for_site(UNIFI_SITE)
    
    if UNIFI_SITE and UNIFI_SSID and UNIFI_GUESTS == False:
        #Wireless Clients
        list_wireless_clients_for_ssid(UNIFI_SITE,UNIFI_SSID)

    if UNIFI_SITE and UNIFI_SSID and UNIFI_GUESTS == True:
        #Wireless Guest Clients
        list_wireless_guests_for_ssid(UNIFI_SITE,UNIFI_SSID)

    #Log Out
    headers = {'Content-type': 'application/json'}
    data = {}
    r = requests.get(UNIFI_CONTROLLER+'/api/logout', data=json.dumps(data), cookies=load_cookies(UNIFI_COOKIE), headers=headers, verify=False)

    #Cleanup Session
    os.remove(UNIFI_COOKIE)



globalconst() #Load Global Const
main() #Run Main

