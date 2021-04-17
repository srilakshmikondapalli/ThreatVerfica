import requests
from tabulate import tabulate
import json
from requests.exceptions import ConnectionError,ConnectTimeout
from netaddr import IPAddress
from netaddr.core import AddrFormatError


class sub:
    def valid_ip(self, ip_name):
        try:
            ip_name = IPAddress(ip_name)
        except AddrFormatError:
            print(f"invalid IPaddress.provide data as ips")
            return False
        else:
            if ip_name.version in [4, 6]:
                if ip_name.is_private():
                    print(f'provided {ip_name} is private. don\'t use private ips for reputation...')
                    return False
                else:
                    return True
            else:
                return True

    def read_config(self, key):
        with open('config.json', 'r') as json_file:
            data = json.load(json_file)
            return data.get(key, None)


class apivoid(sub):
    """
    Apivoid is a Threat Intel Platform to provide reputation information about IOC (Indicator of compromise)
    This Class offers three methods
    1. ip_reputaiton()
    2. domain_reputation()
    3. url_reputation()
    """
    def ip_reputation(self,ip_name):
        """
        This method validate the ip provided by the user from user console, if it is a public ip then only the request
        will be submitted to the apivoid server
        :param ip_name: provide IP, EG: 10.0.0.1
        :return: None
        """
        if self.valid_ip(ip_name):
            url = f"{self.read_config('basicurl')}{self.read_config('ip_api_endpoint')}"
            response = requests.get(url=url, params={"key": self.read_config('key'), "ip": ip_name})
            if response.status_code == 200:
                result = response.json()
                l1 = []
                l2 = []
                print(f'ip:{result["data"]["report"]["ip"]}')
                for k, v in result["data"].items():
                    print(f'ip:{v["ip"]}')
                    if isinstance(v, dict):
                        for i, j in v["blacklists"]["engines"].items():
                            l1.append([j["engine"], j["detected"]])
                        print(f'score: {v["blacklists"]["detections"]}/{v["blacklists"]["engines_count"]}')
                    try:
                        if len(v["information"]) != 0:
                            l2.append([v["information"]["country_name"], v["information"]["continent_name"],
                                       v["information"]["city_name"], v["information"]["latitude"],
                                       v["information"]["longitude"], v["information"]["isp"]])
                    except KeyError: print("no info")
                print('\n\n', tabulate(l1, headers=['engine', 'detected'], tablefmt='orgtbl'))
                print('\n\n', tabulate(l2,
                                       headers=['country_name', 'continent_name', 'city_name', 'latitude', 'longitude',
                                                'isp'], tablefmt='orgtbl'))

            else:print(f'status_code is {response.status_code} | reason is {response.reason}')

        else:print(f'provided ip{ip_name} is invalid for reputation check....')

    def domain(self):
        domain_name = input("enter domain:")
        url = f"{self.read_config('basicurl')}{self.read_config('domain_api_endpoint')}"
        response = requests.get(url=url, params={"key": self.read_config('key'), "host": domain_name})
        if response.status_code == 200:
            result = response.json()
            l1 = []
            l2 = []
            for k, v in result["data"].items():
                if isinstance(v, dict):
                    print(f'host:{v["host"]}')
                    for i, j in v["blacklists"]["engines"].items():
                        l1.append([j["engine"], j["detected"]])
                    print(f'score:{v["blacklists"]["detections"]}/{v["blacklists"]["engines_count"]}')
                try:
                    if len(v["server"])!= 0:
                        l2.append([v["server"]["ip"], v["server"]["continent_name"], v["server"]["country_name"],
                               v["server"]["city_name"], v["server"]["latitude"], v["server"]["longitude"],
                               v["server"]["isp"]])
                except KeyError:
                    print("no info")
            print('\n\n', tabulate(l1, headers=['engine', 'detected'], tablefmt='orgtbl'))
            print('\n\n', tabulate(l2, headers=['ip', 'country_name', 'continent_name', 'city_name', 'latitude',
                                                'longitude', 'isp'], tablefmt='orgtbl'))
        else:
            print(f'status_code is {response.status_code} | reason is {response.reason}')

    def url(self):
        url_name = input("enter url:")
        url = f"{self.read_config('basicurl')}{self.read_config('url_api_endpoint')}"
        response = requests.get(url=url, params={"key": self.read_config('key'), "url": url_name})
        if response.status_code == 200:
            result = response.json()
            l1 = []
            l2 = []
            for k, v in result["data"].items():
                if isinstance(v, dict):
                    for i, j in v["domain_blacklist"].items():
                        if isinstance(j, list):
                            for k in j:
                                l1.append([k["name"], k["detected"]])
                    try:
                        if len(v["server_details"]) != 0:
                            l2.append([[v["server_details"]["ip"]], v["server_details"]["continent_name"],
                                   v["server_details"]["country_name"], v["server_details"]["city_name"],
                                   v["server_details"]["latitude"], v["server_details"]["longitude"],
                                   v["server_details"]["isp"]])
                    except KeyError:
                        print("no info")
            print('\n\n', tabulate(l1, headers=['engine', 'detected'], tablefmt='orgtbl'))
            print('\n\n', tabulate(l2, headers=['ip', 'continent_name', 'country_name', 'city_name', 'latitude',
                                                'longitude', 'isp'], tablefmt='orgtbl'))
        else:
            print(f'status_code is {response.status_code} | reason is {response.reason}')

    def main(self):
        while True:
            try:
                print('1.ip_reputation', '2.domain', '3.url', sep='\n')
                choice = input('enter our choice:')

                if choice == '1':
                    ip_name = input("enter ip:")
                    self.ip_reputation(ip_name)
                elif choice == '2':
                    self.domain()
                elif choice == '3':
                    self.url()
                else:
                    print("invalid choice. enter your choice among above mentioned 3 choices")
            except (ConnectionError, ConnectTimeout):
                print("please check your internet connection")
            while True:
                f = False
                user_choice = input("do u want to continue apivoid[y/n]")
                if user_choice in ['y' or 'Y']:
                    f = True
                    break
                elif user_choice in ['n' or 'N']:
                    f = False
                    break
                else:
                    print("invalid entry please enter y(yes) or n(no)")
                    continue
            if f is True:
                continue
            elif f is False:
                break

class alienvault(sub):

    def ip_reputation(self,ip_name):
        url = f"{self.read_config('url')}{self.read_config('ip_reputation_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            l1.append([result.get("reputation", "no info")])
            print('\n\n', tabulate(l1, headers=["reputation details"], tablefmt="orgtbl"))

        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def ip_geo(self,ip_name):
        url = f"{self.read_config('url')}{self.read_config('ip_geo_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            l1.append([result["country_name"], result["latitude"], result["longitude"]])
            print('\n\n', tabulate(l1, headers=["country_name", "latitude", "longitude"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def ip_malware(self,ip_name):
        url = f"{self.read_config('url')}{self.read_config('ip_malware_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            for k, v in result.items():
                if isinstance(v, list):
                    for k in v:
                        l1.append([k["hash"], k["detections"]["avast"]])
            print('\n\n', tabulate(l1, headers=["hash", "avast"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def ip_urllist(self,ip_name):
        url = f"{self.read_config('url')}{self.read_config('ip_urllists_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            l1.append(result["detail"])
            print('\n\n', tabulate(l1, headers=["url_details"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def ip_passivedns(self,ip_name):
        url = f"{self.read_config('url')}{self.read_config('ip_passivedns_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            for k, v in result.items():
                if isinstance(v, list):
                    for k in v:
                        l1.append([k["address"], k["hostname"]])
            print('\n\n', tabulate(l1, headers=["ip_address", "hostname"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def ip_general(self,ip_name):
        if self.valid_ip(ip_name):
            self.ip_reputation(ip_name)
            self.ip_geo(ip_name)
            self.ip_malware(ip_name)
            self.ip_urllist(ip_name)
            self.ip_passivedns(ip_name)



    def domain_geo(self,domain_name):
        url = f"{self.read_config('url')}{self.read_config('domain_geo_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            l1.append([result["country_name"], result["latitude"], result["longitude"]])
            print('\n\n', tabulate(l1, headers=["country_name", "latitude", "longitude", ], tablefmt="orgtbl"))

        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def domain_malware(self,domain_name):
        url = f"{self.read_config('url')}{self.read_config('domain_malware_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            for k, v in result.items():
                if isinstance(v, list):
                    for k in v:
                        l1.append([k["hash"], k["detections"]["avast"]])
            print('\n\n', tabulate(l1, headers=["hash", "avast"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def domain_urllist(self,domain_name):
        url = f"{self.read_config('url')}{self.read_config('domain_urllist_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            l1.append([result["detail"]])
            print('\n\n', tabulate(l1, headers=["url_details"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def domain_passivedns(self,domain_name):
        url = f"{self.read_config('url')}{self.read_config('domain_passivedns_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            l1 = []
            for k, v in result.items():
                if isinstance(v, list):
                    for k in v:
                        l1.append([k["address"], k["hostname"]])
            print('\n\n', tabulate(l1, headers=["ip_address", "hostname"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def domain(self):
        domain_name = input("enter domain:")
        self.domain_geo(domain_name)
        self.domain_malware(domain_name)
        self.domain_urllist(domain_name)
        self.domain_passivedns(domain_name)

    def url(self):
        url_name = input("enter url:")
        url = f"{self.read_config('url')}{self.read_config('url_endpoint').replace('{url}', url_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result1 = response.json()
            l1 = []
            l2 = []
            for k, v in result1.items():
                if isinstance(v, list):
                    for i in v:
                        if isinstance(i, dict):
                            l1.append([i["result"]["urlworker"]["url"], i["result"]["urlworker"]["ip"],
                                       i["result"]["urlworker"]["sha256"]])
            l2.append([result1["country_name"], result1["latitude"], result1["longitude"]])
            print('\n\n', tabulate(l1, headers=["url", "ip", "sha256"], tablefmt="orgtbl"))
            print('\n\n', tabulate(l1, headers=["country_name", "latitude", "longitude"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')

    def main(self):
        while True:
            try:
                print('1.ip', '2.domain', '3.url', sep='\n')
                choice = input('enter our choice:')
                if choice == '1':
                    ip_name = input("enter ip:")
                    self.ip_general(ip_name)
                elif choice == '2':
                    self.domain()
                elif choice == '3':
                    self.url()
                else:
                    print("invalid choice. enter your choice among above mentioned 3 choices")
            except (ConnectionError, ConnectTimeout):
                print("please check your internet connection")
            while True:
                f = False
                user_choice = input("do u want to continue alienvault[y/n]")
                if user_choice in ['y' or 'Y']:
                    f = True
                    break
                elif user_choice in ['n' or 'N']:
                    f = False
                    break
                else:
                    print("invalid entry please enter y(yes) or n(no)")
                    continue
            if f is True:
                continue
            elif f is False:
                break

class virustotal(sub):


    def ip_address(self,ip_name):
        if self.valid_ip(ip_name):
            response = requests.get(url=self.read_config('ip_vt_endpoint'),
                                    params={'apikey': self.read_config('api_key'), 'ip': ip_name})

            if response.status_code == 200:
                result = response.json()
                if result['response_code'] == 1:
                    l1 = []
                    l2 = []
                    l1.append([result.get("country", "no info")])
                    print('\n\n', tabulate(l1, headers=['country'], tablefmt='orgtbl'))
                    if len(result['resolutions']) != 0:
                        resollist = []
                        for ele in result['resolutions']:
                            resollist.append([ele["last_resolved"], ele["hostname"]])
                        print('\n\n', tabulate(resollist, headers=['last_resolved', 'hostname'], tablefmt='orgtbl'))
                    if len(result['detected_urls']) != 0:
                        for ele in result['detected_urls']:
                            if result['detected_urls'][0]['positives'] != 0:
                                l2.append([ele["url"]])
                        print('\n\n', tabulate(l2, headers=["url"], tablefmt="orgtbl"))
                else:
                    print("missing ip address")
            else:
                print(f'status_code is {response.status_code} and reason is {response.reason}')


    def domain(self):
        domain_name = input("enter domain:")
        response = requests.get(url=self.read_config('domain_vt_endpoint'),
                                params={'apikey': self.read_config('api_key'), 'domain': domain_name})
        if response.status_code == 200:
            result = (response.json())
            if result['response_code'] == 1:
                l1 = []
                l2 = []
                l1.append([result.get("subdomains", "no info"), result.get("categories", "no info")])
                print('\n\n', tabulate(l1, headers=['subdomain', 'categories'], tablefmt="orgtbl"))
                if len(result['resolutions']) != 0:
                    resollist = []
                    for ele in result['resolutions']:
                        resollist.append([ele["last_resolved"], ele["ip_address"]])
                    print('\n\n', tabulate(resollist, headers=['last_resolved', 'ip_address'], tablefmt='orgtbl'))
                if len(result['detected_downloaded_samples']) != 0:
                    for ele in result['detected_downloaded_samples']:
                        if result['detected_downloaded_samples'][0]['positives'] != 0:
                            l2.append([ele["date"]])
                    print('\n\n', tabulate(l2, headers=['date'], tablefmt="orgtbl"))
            else:
                print("missing domain")


        else:
            print(f'status_code is {response.status_code} and reason is {response.reason}')

    def url_report(self):
        resource_name = input('enter the resource:')
        response = requests.get(url=self.read_config('url_vt_endpoint'),
                                params={'apikey': self.read_config('api_key'), 'resource': resource_name})
        if response.status_code == 200:
            result = response.json()
            if result['response_code'] == 1:
                l1 = []
                l1.append([result.get("scan_id", "no info"), result.get("url", "no info"),
                           result.get("scan_date", "no info"), ])
                print('\n\n', tabulate(l1, headers=['scan', 'url', 'scan_date'], tablefmt="orgtbl"))
                if result['positives'] != 0:
                    scanslist = []
                    for k, v in result.items():
                        if isinstance(v, dict):
                            for i, j in v.items():
                                if j["detected"] == True:
                                    scanslist.append([i, j["result"]])
                    print('\n\n', tabulate(scanslist, headers=['vendor', 'result'], tablefmt='orgtbl'))

        else:
            print(f'statuscode is {response.status_code} and reason is {response.reason}')

    def main(self):
        while True:
            try:
                print('1.ip_address', '2.domain', '3.url', sep='\n')
                choice = input('enter our choice:')
                if choice == '1':
                    ip_name = input("enter ip:")
                    self.ip_address(ip_name)
                elif choice == '2':
                    self.domain()
                elif choice == '3':
                    self.url_report()
                else:
                    print("invalid choice. choose from above 3")

            except (ConnectionError, ConnectTimeout):
                print("please check your internet connection")
            while True:
                f = False
                user_choice = input("do u want to continue virustotal[y/n]")
                if user_choice in ['y' or 'Y']:
                    f = True
                    break
                elif user_choice in ['n' or 'N']:
                    f = False
                    break
                else:
                    print("invalid entry please enter y(yes) or n(no)")
                    continue
            if f is True:
                continue
            elif f is False:
                break


class ibmxforce(sub):

    def ip_address(self,ip_name):
        if self.valid_ip(ip_name):
            response=requests.get(url=self.read_config('ip_ibm_endpoint').replace('{ip}',ip_name),
                                  headers={'Authorization':self.read_config('authorisation'),"ip":ip_name})
            if response.status_code==200:
                result=response.json()
                l1=[]
                if len(result['history'])!=0:
                    for ele in result['history']:
                        if len(ele["cats"])==0:
                            category="no info"
                            l1.append([result["ip"], ele.get("created", "no info"), ele.get("reason", "no info"),ele.get("score","no info"),category,ele["geo"]["country"]])
                        else:
                            l1.append([result["ip"],ele.get("created","no info"),ele.get("reason","no info"),ele.get("score","no info"),ele.get("category","no info"),ele["geo"]["country"]])

                    print('\n',tabulate(l1,headers=['ip','created','reason','score','category','geo'],tablefmt='orgtbl'))


            else:
                print(f'statuscode is {response.status_code} and reason is {response.reason}')



    def url_report(self):
        url_name=input("enter url:")
        response=requests.get(url=self.read_config('urlreport_ibm_endpoint').replace('{url}',url_name),
                              headers={'Authorization':self.read_config('authorisation'),'url':url_name})

        if response.status_code==200:
            result=response.json()
            rlist=[]
            if len(result)!=0:
                for k,v in result["result"].items():

                    if isinstance(v,dict):
                        try:
                            if len(result["tags"])==0:
                                tags="no info"

                        except KeyError:
                            tags=result["tags"]


                        try:
                            cats=list(result["result"]['cats'].keys())

                        except KeyError:
                            cats="no info"

            rlist.append([result["result"].get("url","no info"),result["result"].get("score","no info"),cats,tags])
            print('\n',tabulate(rlist,headers=['url','score','category','tags'],tablefmt='orgtbl'))
        else:
            print(f'statuscode is {response.status_code} and reason is {response.reason}')
    def url_history(self):
        url_name=input("enter url:")
        response = requests.get(url=self.read_config('urlhistory_ibm_endpoint').replace('{url}',url_name),headers={'Authorization': self.read_config('authorisation'),'url':url_name})

        if response.status_code == 200:
            result = response.json()
            rlist = []
            if len(result)!=0:
                try:
                    cats = list(result['cats'].keys())
                except KeyError:
                    cats = "no info"
                rlist.append([result["url"],result.get("created","no info"),result.get("score","no info"),cats])
            print('\n',tabulate(rlist,headers=["url","created","score","category"],tablefmt='orgtbl'))



        else:
            print(f'statuscode is {response.status_code} and reason is {response.reason}')

    def main(self):
        while True:
            try:
                print('1.ip_address','2.url_report','3.url_history',sep='\n')
                choice=input("enter your choice:")
                if choice=='1':

                    ip_name=input("enter ip:")
                    self.ip_address(ip_name)

                elif choice=='2':
                    self.url_report()
                elif choice=='3':
                    self.url_history()
            except (ConnectionError,ConnectTimeout):
                print("please check your internet connection")


            while True:
                f = False
                user_choice = input("do u want to continue ibmxforce[y/n]")
                if user_choice in ['y' or 'Y']:
                    f = True
                    break
                elif user_choice in ['n' or 'N']:
                    f = False
                    break
                else:
                    print("invalid entry please enter y(yes) or n(no)")
                    continue
            if f is True:
                continue

            elif f is False:
                break

class tool:

    def main(self):
        while True:
            try:
                print("WELCOME TO THREAT INTEL TOOL ...!")
                print('1.apivoid', '2.alievault', '3.virustotal','4.ibmxforce', sep='\n')
                choice = input('enter our choice:')
                if choice == '1':
                    t=apivoid()
                    t.main()

                elif choice == '2':
                    t = alienvault()
                    t.main()
                elif choice == '3':
                    t = virustotal()
                    t.main()
                elif choice=='4':
                    t = ibmxforce()
                    t.main()
                else:
                    print("invalid choice. enter your choice among above mentioned 3 choices")
            except (ConnectionError, ConnectTimeout):
                print("please check your internet connection")
            while True:
                f = False
                user_choice = input("do u want to continue threat intel tool[y/n]")
                if user_choice in ['y' or 'Y']:
                    f = True
                    break
                elif user_choice in ['n' or 'N']:
                    f = False
                    break
                else:
                    print("invalid entry please enter y(yes) or n(no)")
                    continue
            if f is True:
                continue
            elif f is False:
                break
# th=tool()
# th.main()
obj = apivoid
print(obj.__doc__)
print(obj.ip_reputation.__doc__)