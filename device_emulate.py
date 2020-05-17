#!/usr/bin/python3
# Emulate device for pam-smartphone

import argparse
import asyncio
import configparser as cfp
import hmac
import random
import time
from hashlib import sha256
from os.path import abspath, curdir, join

KEY_FILE = join(abspath(curdir), "keys")
PORT = 48888


def get_config(user):
    config = cfp.ConfigParser()
    try:
        rv = config.read(KEY_FILE)
        if not rv:
            raise FileExistsError
        key = config.get('keys', user)
    except cfp.Error:
        print("config file damaged")
        return
    except FileExistsError:
        print(f'config file not found at {KEY_FILE}')
        return
    else:
        return key


def set_config(user, key):
    config = cfp.ConfigParser()
    try:
        config.read(KEY_FILE)
    except cfp.Error:
        print("config file damaged")  # not matter, rewrite
    config.update({"keys": {user: key}})
    with open(KEY_FILE, 'w') as cf:
        config.write(cf)


async def get_hotp(key):
    now = time.time() // 20
    return hmac.new(key=key.encode(), msg=str(now).encode(), digestmod=sha256).hexdigest()


async def handler(reader, writer):
    while True:
        user = await reader.read(100)
        if not user:
            writer.close()
            return
        user = user.decode()
        print(f'get request {user=}', flush=True)
        if True:  # input(f'Allow access for {user} y/N: ').lower().startswith('y'):
            key = get_config(user)
            token = await get_hotp(key)
            token = token.encode()
            writer.write(token)
            await writer.drain()
        writer.close()


def init():
    print("Hello, let init device.")

    while not (user := input("Enter login for generate token: ")):
        continue

    while True:
        numbers = "".join((str(random.randint(0, 9)) for _ in range(8)))
        count = random.randint(5, 20)
        prompt = \
            f"""
            I generated random values for generate your secret key:
            field1 = {numbers}
            field2 = {count}
            Does it suit you? (this is NOT a secret key) Y/n: """
        if input(prompt).lower().startswith('n'):
            continue
        break
    secret_key = numbers
    for _ in range(count):
        secret_key = sha256(secret_key.encode()).hexdigest()
    set_config(user, secret_key)
    print('done')


async def serv():
    server = await asyncio.start_server(
        handler, '0.0.0.0', PORT)
    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}', flush=True)

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Emulate the device for pam-smartphone")
    parser.add_argument('act', choices=['init', 'run'], help="init start sync keys with device, run - run server")
    args = parser.parse_args()
    if args.act == 'init':
        init()
    elif args.act == 'run':
        asyncio.run(serv())
