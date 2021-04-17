import requests
from tabulate import tabulate
from requests.exceptions import ConnectionError,ConnectTimeout
from sub_oop import sub

class VIRUSTOTAL(sub):

    """
    virustotal is a Threat Intel Platform to provide reputation information about IOC (Indicator of compromise)
    This Class offers three methods
    1. ip_reputaiton()
    2. domain_reputation()
    3. url_reputation()
    """

    def ip_address(self, ip_name):
        """
         This method validates the ip provided by the user from user console, if it is a public ip then only the request
        will be submitted to the virustotal server
        :param ip_name: provided ip ex:8.8.8.8
        :return: none
        """
        if self.valid_ip(ip_name):
            response = requests.get(url=self.read_config('ip_vt_endpoint'),
                                        params={'apikey': self.read_config('api_key'), 'ip': ip_name})

            if response.status_code == 200:
                result = response.json()
                if result['response_code'] == 1:
                    lt1 = []
                    lt2 = []
                    lt1.append([result.get("country", "no info")])
                    print('\n\n', tabulate(lt1, headers=['country'], tablefmt='orgtbl'))
                    if len(result['resolutions']) != 0:
                        resollist = []
                        for ele in result['resolutions']:
                            resollist.append([ele["last_resolved"], ele["hostname"]])
                        print('\n\n', tabulate(resollist, headers=['last_resolved', 'hostname'], tablefmt='orgtbl'))
                    if len(result['detected_urls']) != 0:
                        for ele in result['detected_urls']:
                            if result['detected_urls'][0]['positives'] != 0:
                                lt2.append([ele["url"]])
                        print('\n\n', tabulate(lt2, headers=["url"], tablefmt="orgtbl"))
                else:
                    print("missing ip address")
            else:
                print(f'status_code is {response.status_code} and reason is {response.reason}')
        else:print(f'provided ip {ip_name} is invalid for reputation check....')
    def domain(self):
        """
        This method provides the required data of specified domain fetched by the user from user console which
        is submitted by virustotal server
        :return: none
        """
        domain_name = input("enter domain:")
        response = requests.get(url=self.read_config('domain_vt_endpoint'),
                                    params={'apikey': self.read_config('api_key'), 'domain': domain_name})
        if response.status_code == 200:
            result = (response.json())
            if result['response_code'] == 1:
                lt1 = []
                lt2 = []
                lt1.append([result.get("subdomains", "no info"), result.get("categories", "no info")])
                print('\n\n', tabulate(lt1, headers=['subdomain', 'categories'], tablefmt="orgtbl"))
                if len(result['resolutions']) != 0:
                    resollist = []
                    for ele in result['resolutions']:
                        resollist.append([ele["last_resolved"], ele["ip_address"]])
                    print('\n\n', tabulate(resollist, headers=['last_resolved', 'ip_address'], tablefmt='orgtbl'))
                if len(result['detected_downloaded_samples']) != 0:
                    for ele in result['detected_downloaded_samples']:
                        if result['detected_downloaded_samples'][0]['positives'] != 0:
                            lt2.append([ele["date"]])
                    print('\n\n', tabulate(lt2, headers=['date'], tablefmt="orgtbl"))
            else:
                print("missing domain")


        else:
            print(f'status_code is {response.status_code} and reason is {response.reason}')

    def url_report(self):
        """
        This method provides the required data of specified url fetched by the user from user console which
        is submitted by virustotal server
        :return: none
        """
        resource_name = input('enter the resource:')
        response = requests.get(url=self.read_config('url_vt_endpoint'),
                                    params={'apikey': self.read_config('api_key'), 'resource': resource_name})
        if response.status_code == 200:
            result = response.json()
            if result['response_code'] == 1:
                lt1 = []
                lt1.append([result.get("scan_id", "no info"), result.get("url", "no info"),
                               result.get("scan_date", "no info"), ])
                print('\n\n', tabulate(lt1, headers=['scan', 'url', 'scan_date'], tablefmt="orgtbl"))
                if result['positives'] != 0:
                    scanslist = []
                    for _, val in result.items():
                        if isinstance(val, dict):
                            for res, ele in val.items():
                                if ele["detected"] is True:
                                    scanslist.append([res, ele["result"]])
                    print('\n\n', tabulate(scanslist, headers=['vendor', 'result'], tablefmt='orgtbl'))

        else:
            print(f'statuscode is {response.status_code} and reason is {response.reason}')

    def main(self):
        """
        this method allows the user to choose among three choices i.e:
        1.ip_address
        2.domain
        3.url
        :return:none
        """
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
                flag = False
                user_choice = input("do u want to continue virustotal[y/n]")
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
