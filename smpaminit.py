#!/usr/bin/python2

# Init file for pam_smartphone
# Download smartphone app and tap "INIT"

import ConfigParser as cfp
import getpass
import hmac
import socket
import subprocess
import sys
import time
from contextlib import closing
from exceptions import EnvironmentError
from hashlib import sha256
from os import fchmod
from os.path import join, expanduser, exists
from stat import S_IREAD, S_IWRITE

KEY_FILE = ".pam_smartphone/key"
PORT = 48888


def init(path):
    print """
        Hello, I will initialize your pam-smartphone's secret key.
        You must install the app to your smartphone and tap INIT button.
        """
    if exists(path):
        prompt = "I found config file at {}. Do you want rewrite it? y/N: ".format(path)
        rv = raw_input(prompt)
        return rv.lower().startswith("y")
    return True


def sync_secret():
    prompt = "Enter the number from first field at smartphone (make sure no one sees): "
    init_value = raw_input(prompt)
    prompt = "Enter the number of two field at smartphone: "
    while True:
        try:
            count = int(raw_input(prompt))
            break
        except ValueError:
            prompt = "Wrong input. Enter the NUMBER of two field at smartphone: "

    secret_key = init_value
    for _ in xrange(count):
        secret_key = sha256(secret_key).hexdigest()

    return secret_key


def create_config(path, key):
    config = cfp.ConfigParser()
    config.add_section("main")
    config.set("main", "key", key)
    with open(path, 'w') as cf:
        config.write(cf)
        fchmod(cf.fileno(), S_IREAD | S_IWRITE)


def get_config(path):
    config = cfp.ConfigParser()
    try:
        rv = config.read(path)
        if not rv:
            raise EnvironmentError
        key = config.get('main', 'key')
    except EnvironmentError:
        print "Config file not found at {}, run psm_sync".format(path)
        exit()
    except cfp.Error, err:
        print "Config file is damaged", err
        exit()
    else:
        return key


def is_open(ip, port):
    sock = socket.socket()
    sock.settimeout(0.05)
    try:
        sock.connect((ip, port))
        sock.shutdown(socket.SHUT_RDWR)
        return True
    except socket.error:
        return False
    finally:
        sock.close()


def find_device():
    cmd = ["ip", "route", "show", "0.0.0.0/0"]
    gateway_addr = subprocess.check_output(cmd).split()[2]  # 192.168.0.105
    print "gateway address {}".format(gateway_addr)
    head = gateway_addr.rsplit('.', 1)[0]  # 192.168.0
    print "device search",
    for addr in (".".join((head, str(tail))) for tail in xrange(1, 256)):
        print '\b.', ;
        sys.stdout.flush()
        rv = is_open(addr, PORT)
        if rv:
            print "device found at {}".format(addr)
            return addr

    else:
        print "\ndevice not found"
        exit()


def ask_device(device_addr):
    user = getpass.getuser()
    address = (device_addr, PORT)
    with closing(socket.socket()) as s:
        s.settimeout(20)
        try:
            s.connect(address)
            s.send(user)
            token = s.recv(64)
        except socket.error, err:
            print "error asking device", err
            exit()
        else:
            return token


def get_hotp(secret_key):
    now = time.time() // 20
    return hmac.new(key=secret_key, msg=str(now), digestmod=sha256).hexdigest()


def check(path, secret_key):
    prompt = "Do you want check syncing? Y/n: "
    rv = raw_input(prompt)
    if rv.lower().startswith("n"):
        exit()

    secret_key = secret_key or get_config(path)
    device_addr = find_device()
    for _ in range(3):
        hotp = ask_device(device_addr)
        match = get_hotp(secret_key)
        if hotp == match:
            print "SYNC SUCCESS"
            break


def main():
    path = join(expanduser("~"), KEY_FILE)
    secret_key = None
    if init(path):
        secret_key = sync_secret()
        create_config(path, secret_key)
    check(path, secret_key)


if __name__ == '__main__':
    main()
