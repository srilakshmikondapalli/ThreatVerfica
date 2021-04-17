import requests
from tabulate import tabulate
from requests.exceptions import ConnectionError,ConnectTimeout
from  sub_oop import sub
class APIVOID(sub):
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
                lt1 = []
                lt2 = []
                print(f'ip:{result["data"]["report"]["ip"]}')
                for _, val in result["data"].items():
                    print(f'ip:{val["ip"]}')
                    if isinstance(val, dict):
                        for _, j in val["blacklists"]["engines"].items():
                            lt1.append([j["engine"], j["detected"]])
                        print(f'score: {val["blacklists"]["detections"]}/{val["blacklists"]["engines_count"]}')
                    try:
                        if len(val["information"]) != 0:
                            lt2.append([val["information"]["country_name"], val["information"]["continent_name"],
                                       val["information"]["city_name"], val["information"]["latitude"],
                                       val["information"]["longitude"], val["information"]["isp"]])
                    except KeyError:
                        print("no info")
                print('\n\n', tabulate(lt1, headers=['engine', 'detected'], tablefmt='orgtbl'))
                print('\n\n', tabulate(lt2,
                                       headers=['country_name', 'continent_name', 'city_name', 'latitude', 'longitude',
                                                'isp'], tablefmt='orgtbl'))

            else:print(f'status_code is {response.status_code} | reason is {response.reason}')

        else:print(f'provided ip {ip_name} is invalid for reputation check....')

    def domain(self):
        """
        this method provides required data regarding specified domain fetched by user from user console,which is submitted by apivoid server
        :return: none
        """
        domain_name = input("enter domain:")
        url = f"{self.read_config('basicurl')}{self.read_config('domain_api_endpoint')}"
        response = requests.get(url=url, params={"key": self.read_config('key'), "host": domain_name})
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            lt2 = []
            for _, val in result["data"].items():
                if isinstance(val, dict):
                    print(f'host:{val["host"]}')
                    for _, j in val["blacklists"]["engines"].items():
                        lt1.append([j["engine"], j["detected"]])
                    print(f'score:{val["blacklists"]["detections"]}/{val["blacklists"]["engines_count"]}')
                try:
                    if len(val["server"])!= 0:
                        lt2.append([val["server"]["ip"], val["server"]["continent_name"], val["server"]["country_name"],
                               val["server"]["city_name"], val["server"]["latitude"], val["server"]["longitude"],
                               val["server"]["isp"]])
                except KeyError:
                    print("no info")
            print('\n\n', tabulate(lt1, headers=['engine', 'detected'], tablefmt='orgtbl'))
            print('\n\n', tabulate(lt2, headers=['ip', 'country_name', 'continent_name', 'city_name', 'latitude',
                                                'longitude', 'isp'], tablefmt='orgtbl'))
        else:
            print(f'status_code is {response.status_code} | reason is {response.reason}')

    def url(self):
        """
        this method provides required data regarding specified url fetched by user from user console which is submitted by the apivoid server
        :return:none
        """
        url_name = input("enter url:")
        url = f"{self.read_config('basicurl')}{self.read_config('url_api_endpoint')}"
        response = requests.get(url=url, params={"key": self.read_config('key'), "url": url_name})
        if response.status_code == 200:
            result = response.json()
            lt1 = []
            lt2 = []
            for _, val in result["data"].items():
                if isinstance(val, dict):
                    for _, j in val["domain_blacklist"].items():
                        if isinstance(j, list):
                            for k in j:
                                lt1.append([k["name"], k["detected"]])
                    try:
                        if len(val["server_details"]) != 0:
                            lt2.append([[val["server_details"]["ip"]], val["server_details"]["continent_name"],
                                   val["server_details"]["country_name"], val["server_details"]["city_name"],
                                   val["server_details"]["latitude"], val["server_details"]["longitude"],
                                   val["server_details"]["isp"]])
                    except KeyError:
                        print("no info")
            print('\n\n', tabulate(lt1, headers=['engine', 'detected'], tablefmt='orgtbl'))
            print('\n\n', tabulate(lt2, headers=['ip', 'continent_name', 'country_name', 'city_name', 'latitude',
                                                'longitude', 'isp'], tablefmt='orgtbl'))
        else:
            print(f'status_code is {response.status_code} | reason is {response.reason}')

    def main(self):
        """
        this method allows the user to choose among three choices i.e:
        1. ip_reputation
        2. domain
        3. url
        :return:none
        """
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
                flag = False
                user_choice = input("do u want to continue apivoid[y/n]")
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


