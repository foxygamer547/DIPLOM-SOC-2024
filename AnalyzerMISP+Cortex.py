#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from mispclient import MISPClient, MISPClientError
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests
class CustomAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        name = self.get_param('config.name', None)
        if not name or len(name) == 0:
            name = 'Unnamed'
        if self.get_param('config.cert_check', True):
            ssl_path = self.get_param('config.cert_path', None)
            if not ssl_path or ssl_path == '':
                ssl = True
            else:
                ssl = ssl_path
        else:
            ssl = False
        try:
            self.misp = MISPClient(url=self.get_param('config.url', None, 'No MISP url given.'),
                                   key=self.get_param('config.key', None, 'No MISP api key given.'),
                                   ssl=ssl,
                                   name=name,
                                   proxies={'http': self.http_proxy, 'https': self.https_proxy})
        except MISPClientError as e:
            self.error(str(e))
        except TypeError as te:
            self.error(str(te))

    def summary(self, raw):
        level, namespace, predicate = "info", "MISP", "Поиск"
        data = [res['uuid'] for r in raw['results'] for res in r['result'] if 'uuid' in res]
        value = "{} событий(я)".format(len(set(data))) if data else "0 событий"
        return {"taxonomies": [self.build_taxonomy(level, namespace, predicate, value)]}

    def run(self):
        search_function = getattr(self.misp, f"search_{self.data_type}"
        if self.data_type not in ['registry', 'filename'] else f"search_{self.data_type}_all", self.misp.searchall)
        response = search_function(self.get_data())
        self.report({'results': response})
    def error(self, message):
        super().error(message)
if __name__ == '__main__':
    CustomAnalyzer().run()
