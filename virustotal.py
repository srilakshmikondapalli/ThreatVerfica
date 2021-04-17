import  requests
from tabulate import tabulate
import json
from requests.exceptions import ConnectionError,ConnectTimeout

def read_config(key):
    with open('config.json', 'r') as json_file:
        data = json.load(json_file)
        return data.get(key, None)
def ip_address(ip_name):
    if valid_ip(ip_name):
        response = requests.get(url=read_config('ip_vt_endpoint'),
                                params={'apikey': read_config('api_key'), 'ip': ip_name})

        if response.status_code==200:
            result=response.json()
            if result['response_code']==1:
                l1=[]
                l2=[]
                #print(f'country = {result.get("country","no info")}')
                l1.append([result.get("country","no info")])
                print('\n\n', tabulate(l1, headers=['country'], tablefmt='orgtbl'))
                if len(result['resolutions'])!=0:
                    resollist=[]
                    for ele in result['resolutions']:
                        resollist.append([ele["last_resolved"],ele["hostname"]])
                    print('\n\n',tabulate(resollist,headers=['last_resolved','hostname'],tablefmt='orgtbl'))
                if len(result['detected_urls'])!=0:
                    for ele in result['detected_urls']:
                        if result['detected_urls'][0]['positives']!=0:
                            l2.append([ele["url"]])
                    print('\n\n',tabulate(l2,headers=["url"],tablefmt="orgtbl"))
            else:
                print("missing ip address")
        else:
            print(f'status_code is {response.status_code} and reason is {response.reason}')

def valid_ip(ip_name):
    iplist = ip_name.split('.')
    if len(iplist) == 4:
        count = 0
        for ip in iplist:
            if int(ip) in range(0, 256): count = count + 1
        if count == len(iplist):
            if iplist[0] == '10':
                print(f'Provide IP {ip_name} is Private. Don\'t use private ips for reputation')
                return False
            elif iplist[0] == '192' and iplist[1] == '168':
                print(f'Provide IP {ip_name} is Private. Don\'t use private ips for reputation')
                return False
            elif iplist[0] == '172' and int(iplist[1]) in range(16, 32):
                print(f'Provide IP {ip_name} is Private. Don\'t use private ips for reputation')
                return False
            else: return True
        else:
            print(f'Provided IP {ip_name} is Invalid..!')
            return False
    else:
        print(f'Provided IP {ip_name} is Invalid..!')
        return False


def domain():
    domain_name = input("enter domain:")
    response = requests.get(url=read_config('domain_vt_endpoint'),params={'apikey': read_config('api_key'),'domain': domain_name})
    if response.status_code == 200:
        result = (response.json())
        if result['response_code'] == 1:
            l1=[]
            l2=[]
            #print(f'subdomains:{result.get("subdomains", "no info")}',
             #         f'categories:{result.get("categories", "no info")}', sep='\n')
            l1.append([result.get("subdomains", "no info"),result.get("categories", "no info")])
            print('\n\n',tabulate(l1,headers=['subdomain','categories'],tablefmt="orgtbl"))
            if len(result['resolutions']) != 0:
                resollist = []
                for ele in result['resolutions']:
                    resollist.append([ele["last_resolved"], ele["ip_address"]])
                print('\n\n', tabulate(resollist, headers=['last_resolved', 'ip_address'], tablefmt='orgtbl'))
            if len(result['detected_downloaded_samples']) != 0:
                for ele in result['detected_downloaded_samples']:
                    if result['detected_downloaded_samples'][0]['positives'] != 0:
                        #print(f'\t{ele["date"]}', en
                        #print(f'\t{ele["positives"]}/{ele["total"]}')
                        l2.append([ele["date"]])
                print('\n\n',tabulate(l2,headers=['date'],tablefmt="orgtbl"))
        else:
            print("missing domain")


    else:
        print(f'status_code is {response.status_code} and reason is {response.reason}')

def url_report():
    resource_name = input('enter the resource:')
    response = requests.get(url=read_config('url_vt_endpoint'),params={'apikey': read_config('api_key'),'resource': resource_name})
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:
            l1=[]
            l1.append([result.get("scan_id", "no info"),result.get("url", "no info"),result.get("scan_date", "no info"),])
            print('\n\n',tabulate(l1,headers=['scan','url','scan_date'],tablefmt="orgtbl"))
            #print(f'scan_id : {result.get("scan_id", "no info")}', f'url : {result.get("url", "no info")}',
                     ## f'score : {result["positives"]}/{result["total"]}', sep='\n')
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


def main():
    while True:
        try:
            print('1.ip_address', '2.domain', '3.url', sep='\n')
            choice = input('enter our choice:')
            if choice == '1':
                ip_name = input("enter ip:")
                ip_address(ip_name)
            elif choice == '2':
                domain()
            elif choice == '3':
                url_report()
            else:print("invalid choice. choose from above 3")

        except (ConnectionError, ConnectTimeout):
            print("please check your internet connection")
        while True:
            f = False
            user_choice = input("do u want to continue[y/n]")
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

main()