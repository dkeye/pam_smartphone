# IMPORTANT: use python2

import ConfigParser as cfp
import hmac
import socket
import subprocess
import time
from contextlib import closing
from exceptions import EnvironmentError
from hashlib import sha256
from os.path import join, expanduser

KEY_FILE = ".pam_smartphone/key"
PORT = 48888


def get_key(user):
    """Read config file and return key value"""
    ret_val, ret_msg = False, ""
    home = expanduser("~" + user)
    path = join(home, KEY_FILE)
    config = cfp.ConfigParser()
    try:
        rv = config.read(path)
        if not rv:
            raise EnvironmentError
        key = config.get('main', 'key')
        ret_val, ret_msg = True, key
    except EnvironmentError:
        ret_msg = "Config file not found at {}, run psm_sync".format(path)
    except cfp.Error:
        ret_msg = "Config file is damaged"
    return ret_val, ret_msg


def send_error(pamh, msg_text):
    prompt = pamh.Message(pamh.PAM_ERROR_MSG, msg_text)
    pamh.conversation(prompt)


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
    rv, msg = False, ""
    cmd = ["ip", "route", "show", "0.0.0.0/0"]
    gateway_addr = subprocess.check_output(cmd).split()[2]  # 192.168.0.105
    head = gateway_addr.rsplit('.', 1)[0]  # 192.168.0
    for addr in (".".join((head, str(tail))) for tail in xrange(1, 256)):
        rv = is_open(addr, PORT)
        if rv:
            rv, msg = True, addr
            break

    else:
        msg = "device not found"
    return rv, msg


def ask_device(device_addr, user):
    rv, msg = False, ""
    address = (device_addr, PORT)
    with closing(socket.socket()) as s:
        s.settimeout(20)
        try:
            s.connect(address)
            s.send(user)
            token = s.recv(64)
        except socket.error:
            msg = "error asking device"
        else:
            rv, msg = True, token
    return rv, msg


def get_hotp(secret_key):
    now = time.time() // 20
    return hmac.new(key=secret_key, msg=str(now), digestmod=sha256).hexdigest()


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if not user:
        return pamh.PAM_USER_UNKNOWN

    rv, secret_key = get_key(user)
    if not rv:
        send_error(pamh, secret_key)
        return pamh.PAM_AUTH_ERR

    rv, addr = find_device()
    if not rv:
        send_error(pamh, addr)
        return pamh.PAM_AUTH_ERR

    for _ in xrange(3):
        rv, token = ask_device(addr, user)
        if rv:
            match = get_hotp(secret_key)
            if token == match:
                break
    else:
        send_error(pamh, token)
        return pamh.PAM_AUTH_ERR

    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
