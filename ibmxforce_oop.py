import requests
from tabulate import tabulate
from requests.exceptions import ConnectionError,ConnectTimeout
from sub_oop import sub
class IBMXFORCE(sub):
    """
    Ibmxforce is a Threat Intel Platform to provide reputation information about IOC (Indicator of compromise)
    This Class offers three methods
    1. ip_reputaiton()
    2. domain_reputation()
    3. url_reputation()
    """

    def ip_address(self,ip_name):
        """
         This method validate the ip provided by the user from user console, if it is a public ip then only the request
        will be submitted to the ibmxforce server
        :param ip_name: provided ip ex:8.8.8.8
        :return: none
        """
        if self.valid_ip(ip_name):
            response=requests.get(url=self.read_config('ip_ibm_endpoint').replace('{ip}',ip_name),
                                  headers={'Authorization':self.read_config('authorisation'),"ip":ip_name})
            if response.status_code==200:
                result=response.json()
                lt1=[]
                if len(result['history'])!=0:
                    for ele in result['history']:
                        if len(ele["cats"])==0:
                            category="no info"
                            lt1.append([result["ip"], ele.get("created", "no info"), ele.get("reason", "no info"),ele.get("score","no info"),category,ele["geo"]["country"]])
                        else:
                            lt1.append([result["ip"],ele.get("created","no info"),ele.get("reason","no info"),ele.get("score","no info"),ele.get("category","no info"),ele["geo"]["country"]])

                    print('\n',tabulate(lt1,headers=['ip','created','reason','score','category','geo'],tablefmt='orgtbl'))


            else:
                print(f'statuscode is {response.status_code} and reason is {response.reason}')
        else: print(f'provided ip {ip_name} is invalid for reputation check....')



    def url_report(self):
        """
        This method provides the required data of specified url fetched by the user from user console
        which is submitted by ibmxforce server
        :return: none
        """
        url_name=input("enter url:")
        response=requests.get(url=self.read_config('urlreport_ibm_endpoint').replace('{url}',url_name),
                              headers={'Authorization':self.read_config('authorisation'),'url':url_name})

        if response.status_code==200:
            result=response.json()
            rlist=[]
            if len(result)!=0:
                for _,val in result["result"].items():

                    if isinstance(val,dict):
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
        """
        This method provides the required data of specified url fetched by the user from user console which
        is submitted by the ibmxforce server
        :return: none
        """
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
        """
        This method allows the user to choose among three choices i.e:
        1. ip_address
        2.url_report
        3.url_history
        :return: none
        """
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
                flag = False
                user_choice = input("do u want to continue ibmxforce[y/n]")
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

