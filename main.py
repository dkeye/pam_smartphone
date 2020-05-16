# IMPORTANT: use python2

import ConfigParser as cfp
from exceptions import EnvironmentError
from os.path import join, expanduser

KEY_FILE = ".pam_smartphone/key"


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


def send_error(msg_text):
    prompt = PamHandle.Message(PAM_ERROR_MSG, msg_text)
    PamHandle.conversation(prompt)


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
    except pamh.exception as e:
        return e.pam_result
    if user == None:
        return PAM_USER_UNKNOWN

    rv, msg = get_key(user)
    if not rv:
        pamh.conv(msg)
        return PAM_AUTH_ERR

    return pamh.PAM_SUCCESS
