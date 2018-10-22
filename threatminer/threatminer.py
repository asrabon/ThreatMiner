# Standard Python Libraries
from datetime import datetime
import re
from requests import session
from urllib3.exceptions import DependencyWarning
import warnings

warnings.filterwarnings('ignore', category=DependencyWarning)

# regex to check if an input is a domain
DOMAIN_REGEX = re.compile(r'^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$')
# regex to check if an input is an ip address
IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
# regex to check if an input is a MD5 hash
MD5_REGEX = re.compile(r'([a-fA-F\d]{32})')
# regex to check if an input is a SHA-1 hash
SHA1_REGEX = re.compile(r'([a-fA-F\d]{40})')
# regex to check if an input is a SHA-256 hash
SHA256_REGEX = re.compile(r'([a-fA-F\d]{64})')
# regex to check if an input is a SSDEEP hash
SS_DEEP_REGEX = re.compile(r'.{64,}')

class ThreatMiner:

    def __init__(self):
        self.session = session()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, traceback):
        del self

    def who_is(self, site):
        if DOMAIN_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/domain.php?q={}&rt=1'.format(site)).json()
            return response
        elif IP_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/host.php?q={}&rt=1'.format(site)).json()
            return response
        else:
            raise InvalidTypeException('You must submit either a URL or a Domain.')
    
    def passive_dns(self, site):
        if DOMAIN_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/domain.php?q={}&rt=2'.format(site)).json()
            return response
        elif IP_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/host.php?q={}&rt=2'.format(site)).json()
            return response
        else:
            raise InvalidTypeException('You must submit either a URL or a Domain.')
    
    def get_uris(self, site):
        if DOMAIN_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/domain.php?q={}&rt=3'.format(site)).json()
            return response
        elif IP_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/host.php?q={}&rt=3'.format(site)).json()
            return response
        else:
            raise InvalidTypeException('You must submit either a URL or a Domain.')
    
    def get_related_samples(self, ioc):
        response = None
        if DOMAIN_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/domain.php?q={}&rt=4'.format(ioc)).json()
        elif IP_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/host.php?q={}&rt=4'.format(ioc)).json()
        elif MD5_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/imphash.php?q={}&rt=1'.format(ioc)).json()
        elif SS_DEEP_REGEX.search(ioc) and ':' in ioc:
            response = self.session.get('https://api.threatminer.org/v2/ssdeep.php?q={}&rt=1'.format(ioc)).json()
        if response and response['status_code'] == '404':
            response = self.session.get('https://api.threatminer.org/v2/av.php?q={}&rt=1'.format(ioc)).json()
        return response
    
    def get_domains(self, email):
        if SHA1_REGEX.search(email):
            response = self.session.get('https://api.threatminer.org/v2/email.php?q={}'.format(email)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a SHA-1 has of an email.')
    
    def get_subdomains(self, site):
        if DOMAIN_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/domain.php?q={}&rt=5'.format(site)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a Domain.')
    
    def get_report(self, ioc):
        if DOMAIN_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/domain.php?q={}&rt=6'.format(ioc)).json()
            return response
        elif IP_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/host.php?q={}&rt=6'.format(ioc)).json()
            return response
        elif MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or (SHA256_REGEX.search(ioc) and ':' not in ioc):
            response = self.session.get('https://api.threatminer.org/v2/sample.php?q={}&rt=7'.format(ioc)).json()
            return response
        elif SS_DEEP_REGEX.search(ioc) and ':' in ioc:
            response = self.session.get('https://api.threatminer.org/v2/ssdeep.php?q={}&rt=2'.format(ioc)).json()
        else:
            raise InvalidTypeException('You must submit a Domain, URL, MD5, SHA1, SHA256.')
    
    def get_ssl_certificates(self, site):
        if IP_REGEX.search(site):
            response = self.session.get('https://api.threatminer.org/v2/host.php?q={}&rt=5'.format(site)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a URL.')
    
    def get_metadata(self, ioc):
        if MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or SHA256_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/sample.php?q={}&rt=1'.format(ioc)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a MD5, SHA1, or SHA256 hash.')
    
    def get_http_traffic(self, ioc):
        if MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or SHA256_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/sample.php?q={}&rt=2'.format(ioc)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a MD5, SHA1, or SHA256 hash.')
    
    def get_hosts(self, ioc):
        if MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or SHA256_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/sample.php?q={}&rt=3'.format(ioc)).json()
            if response['status_code'] == '404':
                response = self.session.get('https://api.threatminer.org/v2/ssl.php?q={}&rt=1'.format(ioc)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a MD5, SHA1, or SHA256 hash.')    

    def get_mutants(self, ioc):
        if MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or SHA256_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/sample.php?q={}&rt=4'.format(ioc)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a MD5, SHA1, or SHA256 hash.')
            
    def get_registry_changes(self, ioc):
        if MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or SHA256_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/sample.php?q={}&rt=5'.format(ioc)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a MD5, SHA1, or SHA256 hash.')
    
    def get_av_detections(self, ioc):
        if MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or SHA256_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/sample.php?q={}&rt=6'.format(ioc)).json()
            return response
        else:
            raise InvalidTypeException('You must submit a MD5, SHA1, or SHA256 hash.')
    
    def get_sample_info(self, ioc):
        if MD5_REGEX.search(ioc) or SHA1_REGEX.search(ioc) or SHA256_REGEX.search(ioc):
            response = {'ioc': ioc}
            metadata, http_traffic, hosts, mutants, registry_changes, av_detections, reports = self.get_metadata(ioc), self.get_http_traffic(ioc), self.get_hosts(ioc), self.get_mutants(ioc), self.get_registry_changes(ioc), self.get_av_detections(ioc), self.get_report(ioc)
            response['metadata'] = metadata['results'][0] if metadata['results'] else None
            response['http_traffic'] = http_traffic['results'][0] if http_traffic['results'] else None
            response['hosts'] = hosts['results'][0] if hosts['results'] else None
            response['mutants'] = mutants['results'][0] if mutants['results'] else None
            response['registry_changes'] = registry_changes['results'][0] if registry_changes['results'] else None
            response['av_detections'] = av_detections['results'][0] if av_detections['results'] else None
            response['reports'] = reports['results'][0] if reports['results'] else None

            return response
        else:
            raise InvalidTypeException('You must submit a MD5, SHA1, or SHA256 hash.')
    
    def get_samples(self, ioc):
        if MD5_REGEX.search(ioc):
            response = self.session.get('https://api.threatminer.org/v2/imphash.php?q={}&rt=1'.format(ioc)).json()
        elif SS_DEEP_REGEX.search(ioc):
            print('ssdeep')
            response = self.session.get('https://api.threatminer.org/v2/ssdeep.php?q={}&rt=1'.format(ioc)).json()
        else:
            response = self.session.get('https://api.threatminer.org/v2/av.php?q={}&rt=1'.format(ioc)).json()
        return response
    
    def get_apt_domains(self, name, year):
        response = self.session.get('https://api.threatminer.org/v2/report.php?q={}&y={}&rt=1'.format(name, year)).json()
        return response
    
    def get_apt_hosts(self, name, year):
        response = self.session.get('https://api.threatminer.org/v2/report.php?q={}&y={}&rt=2'.format(name, year)).json()
        return response

    def get_apt_emails(self, name, year):
        response = self.session.get('https://api.threatminer.org/v2/report.php?q={}&y={}&rt=3'.format(name, year)).json()
        return response

    def get_apt_hashes(self, name, year):
        response = self.session.get('https://api.threatminer.org/v2/report.php?q={}&y={}&rt=4'.format(name, year)).json()
        return response
    
    def search_apt_notes(self, search_term):
        response = self.session.get('https://api.threatminer.org/v2/reports.php?q={}&rt=1'.format(search_term)).json()
        return response

    def get_all_apt_notes(self):
        apt_notes = []
        for i in range(2008, datetime.now().year+1):
            response = self.session.get('https://api.threatminer.org/v2/reports.php?q={}&rt=2'.format(i)).json()
            for apt_note in response['results']:
                apt_notes.append(apt_note)
        return apt_notes
    
    def get_all_apt_iocs(self):
        apt_notes = self.get_all_apt_notes()
        apt_iocs = {'domains': [],
                    'hosts': [],
                    'emails': [],
                    'hashes': []}
        for note in apt_notes:
            apt_iocs['domains'].extend(self.get_apt_domains(note['filename'], note['year'])['results'])
            apt_iocs['hosts'].extend(self.get_apt_hosts(note['filename'], note['year'])['results'])
            apt_iocs['emails'].extend(self.get_apt_emails(note['filename'], note['year'])['results'])
            apt_iocs['hashes'].extend(self.get_apt_hashes(note['filename'], note['year'])['results'])
        return apt_iocs


class InvalidTypeException(Exception):
    def __init__(self, message):
        super().__init__(message)
