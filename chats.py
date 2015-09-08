# -*- coding: utf-8 -*-

SCRIPT_NAME = "chats"
SCRIPT_DESC = "chats"

import re
import weechat
from cryptchats import Chats
import curve25519

keys = {
    'user1': {
        'lt': 'b8950391623c96c9aac0198e83e437ee0fc82cf895edce6fd552fc7bb09e7761',
        'ephem0': '6858bea4b5f4a9985fd9df833f622df82e3f837467b92c769809c530104ef879',
        'ephem1': '10bddc067088687bbf2afdfe823d6dd2ce2b4c3724b73fb36579a22177bf157d'
    },
    'int': {
        'lt': '707a33db6b6b59905c8aa89b6ef3b527f2f8e9c85be9bb6824c0fd71c7e49f67',
        'ephem0': 'b880637c8c3996be49287e31ab2d43934cad3cfac819ae7dcd7c7c0d5a261a79',
        'ephem1': '580006b1e24f9084b777927048297031cbc571956274c1cfc3e6d5539a72a378'
    }
}

chats = {}

def get_key(key):
    return curve25519.Private(key.decode('hex'))

def b64encode(_str)
    return _str.encode('base64').replace('\n', '')

def chats_unload_cb():
    return

def chats_modifier_in_privmsg_cb(data, modifier, server_name, string):
    print string
    msg = re.search('^PRIVMSG ([^# ]+) :(.*)$', string)
    if not msg:
        return string

    nick = msg.group(1)
    return string

def chats_modifier_out_privmsg_cb(data, modifier, server_name, string):
    msg = re.search('^PRIVMSG ([^# ]+) :(.*)$', string)
    if not msg:
        return string

    nick = msg.group(1)
    msg = msg.group(2)

    my_nick = weechat.info_get('irc_nick', server_name)

    if nick in keys and nick not in chats:
        chats[nick] = Chats(get_key(keys[my_nick]['lt']),
            get_key(keys[nick]['lt']).get_public())
        chats[nick].init_keys(get_key(keys[my_nick]['ephem0']),
            get_key(keys[my_nick]['ephem1']))
        chats[nick].send_key(get_key(keys[nick]['ephem0']).get_public().serialize())
        chats[nick].receive_key(get_key(keys[nick]['ephem1']).get_public().serialize())
    elif nick not in keys:
        return string

    return 'PRIVMSG %s :%s' % (nick, b64encode(chats[nick].encrypt_msg(msg)))

if __name__ == "__main__" and weechat.register(SCRIPT_NAME, '', '', '', SCRIPT_DESC,
  "chats_unload_cb", ''):

    weechat.hook_modifier("irc_in_privmsg", "chats_modifier_in_privmsg_cb", "")
    weechat.hook_modifier("irc_out_privmsg", "chats_modifier_out_privmsg_cb", "")
