#!/usr/bin/env python
import requests
from cortexutils.analyzer import Analyzer
from urllib.parse import urlencode

class KasperskyTIP(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.test_key = self.get_param('config.key', None, 'Missing Kaspersky Threat Intelligence Portal API key')

    def generate_portal_link(self, data):
        if self.data_type == 'ip' or self.data_type == 'domain' or self.data_type == 'hash':
            return 'https://opentip.kaspersky.com/{}/results?tab=lookup'.format(data)
        else:
            return None

    def run(self):
        Analyzer.run(self)
        if self.data_type in ['ip', 'domain', 'hash']:
            try:
                data = self.get_data()
                portal_link = self.generate_portal_link(data)
                headers = {
                    'x-api-key': self.test_key,
                }
                params = {
                    'request': data,
                }
                endpoint = 'https://opentip.kaspersky.com/api/v1/search/{}'.format(self.data_type)
                response_details = requests.get(endpoint, headers=headers, params=params)

                if response_details.status_code == 200:
                    result = response_details.json()
                    self.report(result if len(result) > 0 else {})
                else:
                    self.error('Failed to query Kaspersky Threat Intelligence Portal details. Status_code {}'.format(
                        response_details.status_code))
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()
        if portal_link:
            self.report({'portal_link': portal_link})

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'KTIP'
        predicate = 'Status'
        value = "None"
        if "Zone" in raw:
            value = "{}".format(raw["Zone"])
        if value == "Green":
            level = "safe"
        elif value == "Yellow":
            level = "suspicious"
        elif value == "Red":
            level = "malicious"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

if __name__ == '__main__':
    analyzer = KasperskyTIP()
    analyzer.run()
