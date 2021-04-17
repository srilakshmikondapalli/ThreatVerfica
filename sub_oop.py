from netaddr import IPAddress
from netaddr.core import AddrFormatError
import json
class sub:
    """
    this class named sub checks the validation of provided ip i.e whether,

    this class also contains the reading of  json configuraton file
    """
    def valid_ip(self, ip_name):
        """
        this method checks the validation of provided ip i.e whether,
        1.  ip contains 4 octets or not
        2.  each octet of ip in range of 256 or not
        3.  provided ip is public or not
        :param ip_name:provided ip. ex: 8.8.8.8
        :return: either true or false
        """
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
        """
        this method contains reading of json configuration file
        :param key: key
        :return: data
        """
        with open('config.json', 'r') as json_file:
            data = json.load(json_file)
            return data.get(key, None)
