#!/usr/bin/env python
import sys
import json
import requests
from requests.auth import HTTPBasicAuth
CHAT_ID="-chat_id"
alert_file = open(sys.argv[1], encoding='utf-8') 
hook_url = sys.argv[3]
alert_json = json.loads(alert_file.read())
alert_file.close()
alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else "N/A"
description = alert_json['rule']['description'] if 'description' in alert_json['rule'] else "N/A"
agent = alert_json['agent']['name'] if 'name' in alert_json['agent'] else "N/A"
rule_id = alert_json['rule']['id'] if 'id' in alert_json['rule'] else "N/A"
rule_groups = alert_json['rule']['groups'] if 'groups' in alert_json['rule'] else "N/A"
rule_mitre_tactic = alert_json['rule']['mitre']['id'] if 'mitre' in alert_json['rule'] else "N/A"
rule_mitre_technique = alert_json['rule']['mitre']['technique'] if 'mitre' in alert_json['rule'] and 'technique' in alert_json['rule']['mitre'] else "N/A"
msg_data = {
    "chat_id": CHAT_ID,
    "text": {
        "description": description,
        "alert_level": str(alert_level),
        "agent": agent,
        "rule_id": rule_id,
        "rule_groups": rule_groups,
        "rule_mitre_tactic": rule_mitre_tactic,
        "rule_mitre_technique": rule_mitre_technique
    }
}

json_string = json.dumps(msg_data, ensure_ascii=False, separators=(',\n', ': '))

response = requests.post(hook_url, headers={'content-type': 'application/json'}, data=json_string.encode('utf-8'))

if response.status_code == 200:
    print("Notification sent successfully.")
else:
    print(f"Failed to send notification. Status code: {response.status_code}")
sys.exit(0)
