import requests
from tabulate import tabulate
import json
from requests.exceptions import ConnectionError,ConnectTimeout
def read_config(key):
    with open('config.json', 'r') as json_file:
        data = json.load(json_file)
        return data.get(key, None)

def ip_address(ip_name):
    if valid_ip(ip_name):
        response=requests.get(url=read_config('ip_ibm_endpoint').replace('{ip}',ip_name),
                              headers={'Authorization':read_config('authorisation'),"ip":ip_name})
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

def url_report():
    url_name=input("enter url:")
    response=requests.get(url=read_config('urlreport_ibm_endpoint').replace('{url}',url_name),
                          headers={'Authorization':read_config('authorisation'),'url':url_name})

    if response.status_code==200:
        result=response.json()
        rlist=[]
        if len(result)!=0:
            for k,v in result["result"].items():

                if isinstance(v,dict):
                    try:
                        if len(result["tags"])==0:
                            tags="no info"
                            rlist.append([tags])
                    except KeyError:
                        tags=result["tags"]
                        rlist.append([tags])

                    try:
                        cats=list(result["result"]['cats'].keys())
                        rlist.append([cats])
                    except KeyError:
                        cats="no info"
                        rlist.append([cats])
            rlist.append([result["result"].get("url","no info"),result["result"].get("score","no info")])
        print('\n',tabulate(rlist,headers=['url','score','category','tags'],tablefmt='orgtbl'))
    else:
        print(f'statuscode is {response.status_code} and reason is {response.reason}')
def url_history():
    url_name=input("enter url:")
    response = requests.get(url=read_config('urlhistory_ibm_endpoint').replace('{url}',url_name),headers={'Authorization': read_config('authorisation'),'url':url_name})

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

def main():
    while True:
        try:
            print('1.ip_address','2.url_report','3.url_history',sep='\n')
            choice=input("enter your choice:")
            if choice=='1':

                ip_name=input("enter ip:")
                ip_address(ip_name)

            elif choice=='2':
                url_report()
            elif choice=='3':
                url_history()
        except (ConnectionError,ConnectTimeout):
            print("please check your internet connection")


        while True:
            f = False
            user_choice = input("do u want to continue [y/n]")
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