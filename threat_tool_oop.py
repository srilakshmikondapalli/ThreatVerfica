from requests.exceptions import ConnectionError,ConnectTimeout

from apivoid_oop import APIVOID
from alienvault_oop import ALIENVAULT
from virustotal_oop import VIRUSTOTAL
from ibmxforce_oop import IBMXFORCE


def result():
    """
    This method allows user to choose among four choices i.e:
    1.apivoid
    2.alienvault
    3.virustotal
    4.ibmxforce
    :return: none
    """
    while True:
        try:
            print("WELCOME TO THREAT INTEL TOOL ...!")
            print('1.apivoid', '2.alievault', '3.virustotal','4.ibmxforce', sep='\n')
            choice = input('enter our choice:')
            if choice == '1':
                obj=APIVOID()
                obj.main()

            elif choice == '2':
                obj = ALIENVAULT()
                obj.main()
            elif choice == '3':
                obj = VIRUSTOTAL()
                obj.main()
            elif choice=='4':
                obj= IBMXFORCE()
                obj.main()
            else:
                print("invalid choice. enter your choice among above mentioned 3 choices")
        except (ConnectionError, ConnectTimeout):
            print("please check your internet connection")
        while True:
            flag = False
            user_choice = input("do u want to continue threat intel tool[y/n]")
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
result()

