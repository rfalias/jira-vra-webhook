from os import path
import uuid
import argparse
import http.server
import simplejson
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from urllib.parse import parse_qsl
import subprocess
import threading
import requests
import configparser
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
from prettytable import PrettyTable
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
processing = False


# Method to get authentication token from VRA
def vra_auth(vrafqdn, user, password, tenant):
    url = "https://{}/csp/gateway/am/api/login".format(vrafqdn)
    payload = '{{"username":"{}","password":"{}","tenant":"{}"}}'\
              .format(user, password, tenant)
    headers = {
        'accept': "application/json",
        'content-type': "application/json",
        }
    response_raw = requests.request("POST", url, data=payload, headers=headers,
                                    verify=False)
    if(response_raw.status_code == 200):
        response = response_raw
        j = response.json()
        auth = "Bearer " + j['cspAuthToken']
        return auth
    else:
        print("Invalid server response %s" % response_raw.status_code)
        raise Exception("Invalid Server Response", "Authentication")


# Get catalog items available from vra
def get_catalog_items(vrafqdn, user, password, tenant):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth
            }
    vraApiUrl = "https://{}/catalog/api/items".format(vrafqdn)
    req_raw = requests.request("GET", vraApiUrl, headers=vraheaders,
                               verify=False)
    if (req_raw.status_code == 200):
        req = req_raw.json()['content']
        for i in req:
            name = i['name']
            cID = i['id']
        return req
    else:
        print("Invalid server response %s" % req_raw.status_code)
    return


# Get a catalog item by it's name
def get_catalog_item_by_name(vrafqdn, user, password, tenant, catname):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth
            }
    vraApiUrl = "https://{}/catalog/api/items".format(vrafqdn)
    req_raw = requests.request("GET", vraApiUrl, headers=vraheaders,
                               verify=False)
    if (req_raw.status_code == 200):
        req = req_raw.json()['content']
        for i in req:
            name = i['name']
            cID = i['id']
            if name == catname:
                project = i['projectIds'][0]
        return req
    else:
        print("Invalid server response %s" % req_raw.status_code)
    return


def get_deployment_by_vm_name(vrafqdn, user, password, tenant, vmname):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth
            }
    vraApiUrl = "https://{}/deployment/api/deployments".format(vrafqdn)
    req_raw = requests.request("GET", vraApiUrl, headers=vraheaders,
                               verify=False)
    if (req_raw.status_code == 200):
        req = req_raw.json()['content']
        for i in req:
            #name = i['name']
            cID = i['id']
            hostname = get_deployment_resources_hostname_by_id(vrafqdn,user,password,tenant,cID)
            if hostname == vmname:
                print("MATCHED %s" % hostname)
                return i
    else:
        print("Invalid server response %s" % req_raw.status_code)
    return



def get_deployment_resources_by_id(vrafqdn, user, password, tenant, did):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth
            }
    vraApiUrl = "https://{}/deployment/api/deployments/{}/resources".format(vrafqdn,did)
    req_raw = requests.request("GET", vraApiUrl, headers=vraheaders,
                               verify=False)
    if (req_raw.status_code == 200):
        req = req_raw.json()['content']
        print("RESORUCES FOR ID %s" % did)
        for i in req:
            ept = i['type']
            if ept == "Cloud.vSphere.Machine":
                print(ept)
                print(i['properties']['resourceName'])
        return req
    else:
        print("Invalid server response %s" % req_raw.status_code)
    return


def get_deployment_resources_hostname_by_id(vrafqdn, user, password, tenant, did):
    names = list()
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth
            }
    vraApiUrl = "https://{}/deployment/api/deployments/{}/resources".format(vrafqdn,did)
    req_raw = requests.request("GET", vraApiUrl, headers=vraheaders,
                               verify=False)
    if (req_raw.status_code == 200):
        req = req_raw.json()['content']
        print("RESORUCES FOR ID %s" % did)
        for i in req:
            ept = i['type']
            if ept == "Cloud.vSphere.Machine":
                print(ept)
                n = i['properties']['resourceName']
                print("RETURNING NAME %s " % n)
                return n
    else:
        print("Invalid server response %s" % req_raw.status_code)
    return


# Get approval ID by name
def get_approval_id_by_name(vrafqdn, user, password, tenant, name):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth
            }
    vraApiUrl = "https://{}/approval/api/approvals".format(vrafqdn)
    req_raw = requests.request("GET", vraApiUrl, headers=vraheaders,
                               verify=False)
    if (req_raw.status_code == 200):
        req = req_raw.json()['content']
        for i in req:
            if i['deploymentName'] == name:
                print("Approval ID: %s" % i['id'])
                print("Request ID: %s Name: %s" % (i['id'],
                                                   i['deploymentName']))
                return i['id']
    else:
        print("Invalid server response %s" % req_raw.status_code)
    return


# Get approval by ID
def approve_by_id(vrafqdn, user, password, tenant, approval_id):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
        'accept': "application/json",
        'authorization': auth,
        'Content-Type': 'application/json'
        }

    app_post = ("{"
                '"action": "APPROVE",'
                '"comment": "Approved by admin via webhook",'
                '"headers":{"additionalProp1": "string"},'
                f'"itemId": "{approval_id}"'
                "}")
    vraApiUrl = "https://{}/approval/api/approvals/action".format(vrafqdn)
    req = requests.request("POST", vraApiUrl, headers=vraheaders, verify=False,
                           data=app_post).json()
    return


# Get a catalog item using the build_info class object. Ensure the catalog name is set
# Also gets the catalog version from the config file
def get_catalog_item_by_build_info(vrafqdn, user, password, tenant, binfo):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth
            }
    vraApiUrl = "https://{}/catalog/api/items".format(vrafqdn)
    req_raw = requests.request("GET", vraApiUrl, headers=vraheaders,
                               verify=False)
    if (req_raw.status_code == 200):
        req = req_raw.json()['content']
        if binfo.catalogname is not None and binfo.catalogname is not "Unknown":
            catname = binfo.catalogname
        elif binfo.os == "Linux":
            catname = "Oracle Linux 7"
        for i in req:
            name = i['name']
            cID = i['id']
            if name == catname:
                project = i['projectIds'][0]
                binfo.catalogItemID = cID
                binfo.catalogname = catname
                binfo.projectID = project
                binfo.version = ci.get_version_by_name(binfo.catalogname)

    else:
        print("Invalid server response %s" % req_raw.status_code)


# Build a JSON catalog request, consumable by VRA
def build_catalog_request(deploymentcount, deploymentname, size, hostname,
                          vlan, domain, projectId, reason, version, guid):
    rdata = ("{"
             f'"bulkRequestCount": {deploymentcount},'
             f'"deploymentName": "{deploymentname}",'
             '"inputs": {'
             f'"requestCount":{deploymentcount},'
             f'"Size":"{size}",'
             f'"Hostname":"{hostname}",'
             f'"guid":"{guid}",'
             f'"VLAN":"{vlan}",'
             f'"Domain":"{domain}",'
             f'"deploymentName": "{deploymentname}"'
             '},'
             f'"projectId": "{projectId}",'
             f'"reason": "{reason}",'
             f'"version": "{version}"'
             '}'
             )
    return rdata


# Issue a manual catalog request from supplied JSON
# Usually used in testing
def manual_catalog_request(vrafqdn, user, password,
                           tenant, buildtxt, catalogID):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth,
            'Content-Type':'application/json'
            }
    rdata = buildtxt
    print("---- Build Data ----")
    print(rdata)
    vraApiUrl = "https://{}/catalog/api/items/{}/request"\
                .format(vrafqdn, catalogID)
    req = requests.request("POST", vraApiUrl, headers=vraheaders,
                           verify=False, data=rdata).json()
    print(req)
    return


# Delete a deployment by ID
def delete_dep_by_id(vrafqdn, user, password,
                           tenant, depID):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth,
            'Content-Type':'application/json'
            }
    rdata = ""
    print(rdata)
    vraApiUrl = "https://{}/deployment/api/deployments/{}"\
                .format(vrafqdn, depID)
    req = requests.request("DELETE", vraApiUrl, headers=vraheaders,
                           verify=False, data=rdata).json()
    return



# Request a catalog item, using the build info class.
def request_catalog_item(vrafqdn, user, password, tenant, binfo):
    auth = vra_auth(vrafqdn, user, password, tenant)
    vraheaders = {
            'accept': "application/json",
            'authorization': auth,
            'Content-Type': 'application/json'
            }
    get_catalog_item_by_build_info(vrafqdn, user, password, tenant, binfo)
    binfo.version = ci.get_version_by_name(binfo.catalogname)
    rdata = build_catalog_request(binfo.deploymentcount, binfo.deploymentname,
                                  binfo.size, binfo.hostname,
                                  binfo.vlan, binfo.domain,
                                  binfo.projectID, binfo.reason,
                                  binfo.version, binfo.guid)
    vraApiUrl = "https://{}/catalog/api/items/{}/request"\
                .format(vrafqdn, binfo.catalogItemID)
    print(f"Requesting Catalog Item {binfo.catalogname}, Deployment: {binfo.deploymentname} from {ci.host}")

    req = requests.request("POST", vraApiUrl, headers=vraheaders,
                           verify=False, data=rdata).json()
    print(f"VRA Response: {req}")
    
    return req


# Holds easily consumable configuration file info
class config_info():
    # [vra]
    def __init__(self, path):
        self.config = configparser.ConfigParser()
        self.config.read(path)
        self.vraconf = self.config['vra']
        self.host = self.vraconf['host']
        self.tenant = self.vraconf['tenant']
        self.username = self.vraconf['username']
        self.password = self.vraconf['password']
        self.token = self.vraconf['token']
        self.debug = self.vraconf['debug']

    def get_version_by_name(self, name):
        return self.config[name]['version']


# Build info used by various methods to convert jira data to valid
# VRA/JSON data
class build_info:
    def __init__(self):
        self.deploymentcount = 1
        self.hostname = None
        self.location = None
        self.size = None
        self.vlan = None
        self.os = None
        self.tags = None
        self.ispci = None
        self.ismountrequired = None
        self.mountdescription = None
        self.mountpoint = None
        self.projectID = None
        self.guid = str(uuid.uuid1())
        self.deploymentname = None
        self.catalogItemID = None
        self.status = None
        self.isjavainstallrequired = None
        self.version = None
        self.catalogname = None
        self.issuetype = None
        self.reason = None
        self.isDecom = False


# Class to store config file data mapping Jira fields to well know fields
class field_map:
    def __init__(self):
        self.hostname = None
        self.location = None
        self.size = None
        self.os = None
        self.tags = None
        self.vlan = None
        self.ispci = None
        self.ismountrequired = None
        self.mountdescription = None
        self.mountpoint = None
        self.projectID = None
        self.deploymentname = None
        self.catalogItemID = None
        self.status = None
        self.isjavainstallrequired = None
        self.version = None
        self.catalogname = None
        self.reason = None
        self.isDecom = False


# Get fields from the map sections
def get_map_sect(mapsect, field):
    try:
        return mapsect[field]
    except:
        return "Unknown"



def process_build_type(build_info):
     
    if build_info.issuetype is not None:
        config = configparser.ConfigParser()
        config.read('/etc/vra/' + build_info.issuetype + '.conf')
        #print(config[build_info.issuetype])
        for x in config[build_info.issuetype]:
            print("Trying to set build_info attr %s to %s" % (x, config[build_info.issuetype][x]))
            setattr(build_info, x, config[build_info.issuetype][x])
        

# Generate issue field maps
def get_issue_field_map(issue_data):
    '''
hostname = customfield_16633
Location = customfield_16430
Size = customfield_21032
OS = customfield_21033
Tags = customfield_16650
IsPCINetwork = customfield_18448
MountPointRequired = customfield_18250
MountDescription = customfield_18531
NFSMountPoint = customfield_18251
IsJavaInstall = customfield_21034
    '''
    key = issue_data['fields']['project']['key']
    try:
        issuetype = issue_data['fields']['issuetype']['name']
    except:
        issuetype = None
    if issuetype is not None:
        key = issuetype
    config = configparser.ConfigParser()
    config.read(args.config)
    fm = field_map()
    try:
        mapsect = config[key]
    except:
        print("Issue type not present in configuration")
        raise Exception("Issue not present in config file","Add issue type to resolve this error")
        
    fm.hostname = get_map_sect(mapsect,'hostname')
    fm.location = get_map_sect(mapsect, 'location')
    fm.size = get_map_sect(mapsect, 'size')
    fm.os = get_map_sect(mapsect,'os')
    fm.tags = get_map_sect(mapsect, 'tags')
    fm.ispci = get_map_sect(mapsect,'ispcinetwork')
    fm.domain = get_map_sect(mapsect,'domain')
    fm.vlan = get_map_sect(mapsect,'vlan')
    fm.catalogname = get_map_sect(mapsect, 'catalogname')
    fm.ismountrequired = get_map_sect(mapsect, 'mountpointrequired')
    fm.mountdescription = get_map_sect(mapsect, 'mountdescription')
    fm.mountpoint = get_map_sect(mapsect, 'nfsmountpoint')
    fm.isjavainstallrequired = get_map_sect(mapsect, 'isjavainstall')
    fm.deploymentcount = get_map_sect(mapsect, 'deploymentcount')
    fm.issuetype = issuetype
    fm.reason = get_map_sect(mapsect, 'reason')
    return fm

 
# Get field data from jira issues
# Set unknown value if proper information is not supplied
# Incorrectly populated data can cause a VRA request to fail
def get_field_data(data, formid):
    try:
        if isinstance(data[formid], dict):
            if 'value' in data[formid].keys():
                return data[formid]['value']
            else:
                return "Unknown Value"
        else:
            return data[formid]
    except Exception as e:
        print(e)
        return "Unknown"


# Extract build fields from a Jira Issue JSON
def extract_build_fields(data):
    fields = '''hostname = customfield_16633
Location = customfield_16430
Size = customfield_21032
OS = customfield_21033
Tags = customfield_16650
IsPCINetwork = customfield_18448
MountPointRequired = customfield_18250
MountDescription = customfield_18531
NFSMountPoint = customfield_18251
IsJavaInstall = customfield_21034'''
    binfo = build_info()
    
    key = data['key']
    fields = data['fields']
    if ("SD-" in key):
        fm = get_issue_field_map(data)
        binfo.hostname =  get_field_data(fields,fm.hostname)
        binfo.isDecom = True
        return binfo

    try:
        issuetype = fields['issuetype']['name']
    except:
        issuetype = "Unknown"
    
    fm = get_issue_field_map(data)
    binfo.hostname =  get_field_data(fields,fm.hostname)
    binfo.location = get_field_data(fields,fm.location)
    binfo.size =  get_field_data(fields,fm.size)
    binfo.os =  get_field_data(fields,fm.os)
    binfo.tags =  get_field_data(fields,fm.tags)
    binfo.ispci =  get_field_data(fields,fm.ispci)
    binfo.ismountrequired = get_field_data(fields,fm.ismountrequired)
    binfo.mountdescription = get_field_data(fields,fm.mountdescription)
    binfo.mountpoint = get_field_data(fields,fm.mountpoint)
    binfo.vlan = get_field_data(fields,fm.vlan)
    binfo.domain = get_field_data(fields,fm.domain)
    binfo.catalogname = get_field_data(fields, fm.catalogname)
    binfo.isjavainstallrequired = get_field_data(fields,fm.isjavainstallrequired)
    binfo.reason = get_field_data(fields, fm.reason)
    binfo.status = fields['status']['name']
    binfo.issuetype = issuetype
    print("Processing build type")
    binfo.deploymentname = f"Jira - {key} - {binfo.issuetype}"
    binfo.deploymentcount = get_field_data(fields, fm.deploymentcount)
    process_build_type(binfo)    
    return binfo


# Just get the token
def getToken():
    return ci.token


# Simple HTTP Listener, also initiates basic handling of GET to check server status
# And POST to process jira requests.
class SimpleHandler(BaseHTTPRequestHandler):
    processing = False

    def do_GET(self):
        global processing
        print(self.headers['token'])
        print(self.path)
        if(self.headers['token'] == getToken()):
            req = "Authentication success"
            self.wfile.write(bytes("Auth success", "utf8"))
            self.send_response(200)
            self.end_headers()
        else:
            self.wfile.write(bytes("Invalid token", "utf8"))
            self.send_response(200)
            self.end_headers()

    def do_POST(self):
        global processing
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        tokenHeader = self.headers['token']
        if tokenHeader == getToken():
            data = simplejson.loads(self.data_string)
            print("extract build fields")
            bi = extract_build_fields(data)
	 
            print(self.data_string)
            if debug:
                print("-----------------PLAIN_DATA-------------------")
            if bi.status == "Approved":
                r = request_catalog_item(ci.host, ci.username, ci.password,
                                         ci.tenant, bi)
                try:
                    statusCode = int(r['statusCode'])
                except:
                    statusCode = 200
                self.wfile.write(bytes(str(r), "utf8"))
                self.send_header("Content-type", "application/json")
                self.send_response(statusCode)
                self.end_headers()
            else:
                self.send_header("Content-type", "application/json")
                self.send_response(200)
                self.end_headers()
        else:
            self.send_header("Response","Invalid Token")
            self.send_header("Content-type", "application/json")
            self.end_headers()

            self.send_response(401)


# Unused currently, logs go to systemd or console
def log_request(self, code=None, size=None):
    return


# Configure a couple globals
ci = None
debug = False
args = None


def do_flask_setup():
    global ci
    ci = config_info('/etc/vra/vra-webhook.conf')
    print(vars(ci))

    if ci.debug == "True":
        debug = True
    print(f"Debug: {debug}")
    print("Config loaded: %s, %s" % ('/etc/vra/vra-webhook.conf', ci.host))


def do_flask_post(token, json_post):
    global ci
    do_flask_setup()

    global processing
    tokenHeader = token
    
    fr = flask_return()
    fr.code = 400
    fr.message = "Request not processed"
    if tokenHeader == getToken():
        data = json_post
        print(data)
        print("extract build fields")
        bi = extract_build_fields(data)
        print(vars(bi))
        if bi.status == "Approved":
            r = request_catalog_item(ci.host, ci.username, ci.password,
                                     ci.tenant, bi)
            statusCode = 400
            msg = "Unknown"
	    
            try:
                if isinstance(r, list):
                    statusCode = int(r[0]['statusCode'])
                    msg = r[0]['message']
                else:
                    statusCode = r['statusCode']
                    msg = r['message']
            except:
                statusCode = 200
            try:
                if isinstance(r,list):
                    statusCode = 200
                    tmp = []
                    for x in r:
                        tmp.append(x['deploymentName'])
                    msg = ",".join(tmp)
                else:
                    statusCode = 200
                    msg = r['deploymentName']
            except:
                statusCode = 400
                msg = "Unknown result"
            fr.code = statusCode
            fr.message = msg
        elif bi.isDecom:
            print("Is a decom ticket, process now. Deleting %s" % bi.hostname)
            del_dep_req = get_deployment_by_vm_name(ci.host, ci.username, ci.password, ci.tenant, bi.hostname)
            if del_dep_req is not None:
                print(del_dep_req['id'])
                delete_dep_by_id(ci.host, ci.username, ci.password, ci.tenant,del_dep_req['id'])
                print("Scheduled delete of %s" % bi.hostname)
            else:
                print("Hostname not found as vra deployment, doing nothing")
        else:
            fr.code = 400
            fr.message = "Ticket not in approved status, rejecting"
            print("Ticket not approved")
    else:
        fr.code = 401
        fr.message = "Not authorized"
        print("Not authorized")
    return fr

class args:
    config = '/etc/vra/vra-webhook.conf'

class flask_return:
    code = 200
    message = "OK"


# Main entry, setup the parser, check config files and start the listener
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', action='store', type=str, required=True)
    args = parser.parse_args()
    if not args.config:
        print("Specify config file path")
        exit(-5)
    if not path.exists(args.config):
        print("Config file not found or not readable")
        exit(-10)
    ci = config_info(args.config)
    if ci.debug == "True":
        debug = False
    print(f"Debug: {debug}")
    print("Config loaded: %s, %s" % (args.config, ci.host))
    print("-----------------GETTING ALL DEPS INF----------------")
    try:
        HTTPServer(("0.0.0.0", 9000), SimpleHandler).serve_forever()
    except KeyboardInterrupt:
        print('shutting down server')

