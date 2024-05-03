#!/var/ossec/framework/python/bin/python3
## MISP API Integration
#
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->misp:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()

# New Alert Output if MISP Alert or Error calling the API
alert_output = {}
misp_base_url = "https://ti-misp.local/attributes/restSearch/"
misp_api_auth_key = "*****api-key*****"

# MISP Server Base URL
# API - HTTP Headers
misp_apicall_headers = {"Content-Type":"application/json", "Authorization":f"{misp_api_auth_key}", "Accept":"application/json"}

## Extract Sysmon for Windows/Sysmon for Linux and Sysmon Event ID
event_source = alert["rule"]["groups"][0]
## Regex Pattern used based on SHA256 length (64 characters)
regex_file_hash = re.compile('\w{64}')

if event_source == 'audit':
    try:
        wazuh_event_param = alert["data"]["audit"]["execve"]["a1"]
    except IndexError:
        sys.exit()
    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()

        if misp_api_response["response"]["Attribute"]:
            alert_output["misp"] = {}
            alert_output["misp"]["source"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            alert_output["misp"]["source"]["description"] = alert["rule"]["description"]
            send_event(alert_output, alert["agent"])
else:
    sys.exit()
