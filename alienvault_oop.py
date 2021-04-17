import requests
from tabulate import tabulate
from requests.exceptions import ConnectionError,ConnectTimeout
from sub_oop import sub

class ALIENVAULT(sub):
    """
    Alienvault is a Threat Intel Platform to provide reputation information about IOC (Indicator of compromise)
    This Class offers three methods
    1. ip_reputaiton()
    2. domain_reputation()
    3. url_reputation()
    """

    def ip_reputation(self, ip_name):
        """
        This method validate the ip provided by the user from user console, if it is a public ip then only the request
        will be submitted to the alienvault server
        :param ip_name: provided ip ex:8.8.8.8
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('ip_reputation_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            lt1.append([result.get("reputation", "no info")])
            print('\n\n', tabulate(lt1, headers=["reputation details"], tablefmt="orgtbl"))

        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def ip_geo(self, ip_name):
        """
        This method validate the ip provided by the user from user console, if it is a public ip then only the request
        regarding geographic location will be submitted to the alienvault server
        :param ip_name: provided ip ex:8.8.8.8
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('ip_geo_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            lt1.append([result["country_name"], result["latitude"], result["longitude"]])
            print('\n\n', tabulate(lt1, headers=["country_name", "latitude", "longitude"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def ip_malware(self, ip_name):
        """
        This method validate the ip provided by the user from user console, if it is a public ip then only the request
        regarding ip malware will be submitted to the alienvault server
        :param ip_name:provided ip ex:8.8.8.8
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('ip_malware_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            for _, val in result.items():
                if isinstance(val, list):
                    for k in val:
                        lt1.append([k["hash"], k["detections"]["avast"]])
            print('\n\n', tabulate(lt1, headers=["hash", "avast"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def ip_urllist(self, ip_name):
        """
        This method validate the ip provided by the user from user console, if it is a public ip then only the request
        regarding ip urllists will be submitted to the alienvault server
        :param ip_name: provided ip ex:8.8.8.8
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('ip_urllists_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            lt1.append(result["detail"])
            print('\n\n', tabulate(lt1, headers=["url_details"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def ip_passivedns(self, ip_name):
        """
        This method validate the ip provided by the user from user console, if it is a public ip then only the request
        regarding passive dns of ip will be submitted to the alienvault server
        :param ip_name: provided ip ex:8.8.8.8
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('ip_passivedns_endpoint').replace('{ip}', ip_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            for _, val in result.items():
                if isinstance(val, list):
                    for k in val:
                        lt1.append([k["address"], k["hostname"]])
            print('\n\n', tabulate(lt1, headers=["ip_address", "hostname"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def ip_general(self, ip_name):
        """
        This method validate the ip provided by the user from user console, if it is a public ip then only the request
        regarding complete information will be submitted to the alienvault server
        :param ip_name: provided ip ex:8.8.8.8
        :return: none
        """
        if self.valid_ip(ip_name):
            self.ip_reputation(ip_name)
            self.ip_geo(ip_name)
            self.ip_malware(ip_name)
            self.ip_urllist(ip_name)
            self.ip_passivedns(ip_name)


    def domain_geo(self, domain_name):
        """
        this method provides geographical location of specified domain fetched by user from user console,which is submitted by alienvault server
        :param domain_name: provided domain ex:google.com
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('domain_geo_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            lt1.append([result["country_name"], result["latitude"], result["longitude"]])
            print('\n\n', tabulate(lt1, headers=["country_name", "latitude", "longitude", ], tablefmt="orgtbl"))

        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def domain_malware(self, domain_name):
        """
        this method provides malware analysis of specified domain fetched by the user from user console which is
        submitted by alienvault server
        :param domain_name: provided domain ex:google.com
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('domain_malware_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            for _, val in result.items():
                if isinstance(val, list):
                    for k in val:
                        lt1.append([k["hash"], k["detections"]["avast"]])
            print('\n\n', tabulate(lt1, headers=["hash", "avast"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def domain_urllist(self, domain_name):
        """
        this method provides the url lists of specified domain fetched by the user from user console whic is
        submitted by alienvault server
        :param domain_name: provided domain ex:google.com
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('domain_urllist_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            lt1.append([result["detail"]])
            print('\n\n', tabulate(lt1, headers=["url_details"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def domain_passivedns(self, domain_name):
        """
        this method provides the passive dns of specified domain fetched by the user from user console which is
        submitted by the alienvault server
        :param domain_name: provided domain ex:google.com
        :return: none
        """
        url = f"{self.read_config('url')}{self.read_config('domain_passivedns_endpoint').replace('{domain}', domain_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            for _, val in result.items():
                if isinstance(val, list):
                    for k in val:
                        lt1.append([k["address"], k["hostname"]])
            print('\n\n', tabulate(lt1, headers=["ip_address", "hostname"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def domain(self):
        """
        this method provides complete information of specified domain fetched by the user from user console which is
        submitted by the alien vault server
        :return: none
        """
        domain_name = input("enter domain:")
        self.domain_geo(domain_name)
        self.domain_malware(domain_name)
        self.domain_urllist(domain_name)
        self.domain_passivedns(domain_name)


    def url(self):
        """
        this method provides the required data of specified url fetched by the user from user console which is submitted
        by the alienvault server
        :return: none
        """
        url_name = input("enter url:")
        url = f"{self.read_config('url')}{self.read_config('url_endpoint').replace('{url}', url_name)}"
        response = requests.get(url=url)
        if response.status_code == 200:
            result1 = response.json()
            lt1 = []
            lt2 = []
            for _, val in result1.items():
                if isinstance(val, list):
                    for res in val:
                        if isinstance(res, dict):
                            lt1.append([res["result"]["urlworker"]["url"], res["result"]["urlworker"]["ip"],
                                       res["result"]["urlworker"]["sha256"]])
            lt2.append([result1["country_name"], result1["latitude"], result1["longitude"]])
            print('\n\n', tabulate(lt1, headers=["url", "ip", "sha256"], tablefmt="orgtbl"))
            print('\n\n', tabulate(lt1, headers=["country_name", "latitude", "longitude"], tablefmt="orgtbl"))
        else:
            print(f'statuscode:{response.status_code}| reason:{response.reason}')


    def main(self):
        """
        this method allows the user to choose among the three choices i.e:
        1.ip
        2.domain
        3.url
        :return:none
        """
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
                flag = False
                user_choice = input("do u want to continue alienvault[y/n]")
                if user_choice in ['y' or 'Y']:
                    flag = True
                    break
                elif user_choice in ['n' or 'N']:
                    flag = False
                    break
                else:
                    print("invalid entry please enter y(yes) or n(no)")
                    continue
            if flag is True:
                continue
            elif flag is False:
                break
