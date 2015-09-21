# -*- coding: utf-8 -*-
SCRIPT_NAME = "chats"
SCRIPT_DESC = "chats"

import re
import irssi
from cryptchats import Chats, ChatsError
import curve25519
import base64
import json
import os

chats = {}
keys = {}
key_path = __file__.replace('scripts/autorun/%s.py' % __name__, 'keys.json')
key_path = key_path.replace('scripts/%s.py' % __name__, 'keys.json')

def save_keys():
    tmp_keys = {}

    for key in keys:
        tmp_keys[key] = b64encode(keys[key].serialize())

    json.dump(tmp_keys, open(key_path, 'w'))

def load_keys():
    try:
        tmp_keys = json.load(open(key_path))
    except:
        keys['my_key'] = curve25519.Private()
        save_keys()
        return

    for key in tmp_keys:
        if key == 'my_key':
            keys[key] = curve25519.Private(b64decode(tmp_keys[key]))
        else:
            keys[key] = curve25519.Public(b64decode(tmp_keys[key]))

def printformat(win, level, format, args):
    win.printformat(level, format, args[0], args[1])

def b64decode(_str):
    return base64.b64decode(_str)

def b64encode(_str):
    return base64.b64encode(_str).replace('\n', '')

def silent_send(server, nick, msg):
    server.command('^msg -%s %s %s' % (server.tag, nick, b64encode(msg)))

def setkey(data, server, witem):
    data = data.split(' ')

    try:
        keys[data[0]] = curve25519.Public(b64decode(data[1]))
        save_keys()
    except:
        print 'Usage: /setkey <nick> <key>.'

    print 'Set key for %s to: %s' % (data[0], data[1])
    return 

def listkeys(data, server, witem):
    print 'Your key: ' + b64encode(keys['my_key'].get_public().serialize())

    for key in keys:
        if key == 'my_key':
            continue

        print '%s: %s' % (key, b64encode(keys[key].serialize()))

    return

def keyx(data, server, witem):
    nick = data

    if nick not in chats:
        return 

    if not nick:
        print 'Usage: /keyx <nick>'
        return

    chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
        chaff_block_size=8, debug=False)

    silent_send(server, nick, chats[nick].encrypt_initial_keyx())
    return 

def privmsg_in(server, msg, nick, user):
    omsg = msg

    if nick in keys and nick not in chats:
        chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
            chaff_block_size=8, debug=False)
    elif nick not in keys:
        return 0

    try:
        msg = chats[nick].decrypt_msg(b64decode(msg))
    except ChatsError:
        window = server.window_item_find(nick)
        printformat(window, irssi.MSGLEVEL_MSGS, 'pubmsg', [ nick, '\x0305' + omsg ])
        msg = None

    if msg and 'keyx' in msg:
        if msg['keyx'] == True:
            print 'Key exchange with %s completed.' % nick
        else:
            silent_send(server, nick, msg['keyx'])

    if msg and 'msg' in msg:
        window = server.window_item_find(nick)
        printformat(window, irssi.MSGLEVEL_MSGS, 'pubmsg',
            [ nick, '\x0303' + msg['msg'] ])

    irssi.signal_stop()
    return 1

def privmsg_out(msg, server, query):
    nick = query.name
    my_nick = server.nick

    if nick in keys and len(msg) == 384:
        return 0

    if nick[0] == '#':
        return 0

    if nick in keys and nick not in chats:
        chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
            chaff_block_size=8, debug=False)

        silent_send(server, nick, chats[nick].encrypt_initial_keyx())

    elif nick not in keys:
        return 0

    silent_send(server, nick, chats[nick].encrypt_msg(msg))
    printformat(irssi.active_win(), irssi.MSGLEVEL_PUBLIC, 'own_msg',
        [ my_nick, '\x0302' + msg ])

    irssi.signal_stop()
    return 1

load_keys()

irssi.get_script().theme_register([
    ('own_msg',  irssi.current_theme().get_format('fe-common/core', 'own_msg')),
    ('pubmsg',  irssi.current_theme().get_format('fe-common/core', 'pubmsg'))
])

irssi.command_bind('setkey', setkey)
irssi.command_bind('listkeys', listkeys)
irssi.command_bind('keyx', keyx)

irssi.signal_add('message private', privmsg_in)
irssi.signal_add('send text', privmsg_out)
