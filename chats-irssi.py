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
debug = False

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
        chaff_block_size=8, debug=debug)

    silent_send(server, nick, chats[nick].encrypt_initial_keyx())
    return 

def privmsg_in(server, msg, nick, user):
    omsg = msg

    if nick in keys and nick not in chats:
        chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
            chaff_block_size=8, debug=debug)
    elif nick not in keys:
        return 0

    try:
        msg = chats[nick].decrypt_msg(b64decode(msg))
    except ChatsError:
        if len(msg) != 384:
            window = server.window_item_find(nick)
            printformat(window, irssi.MSGLEVEL_MSGS, 'pubmsg', [ nick, '\x0305' + omsg ])
        msg = None
    except TypeError:
        return 0

    if msg and 'keyx' in msg:
        if msg['keyx'] == True:
            print 'Key exchange with %s completed.' % nick
        else:
            silent_send(server, nick, msg['keyx'])

    if msg and 'msg' in msg:
        window = server.window_item_find(nick)

        msg['msg'] = msg['msg'].replace('\0', '')

        action = re.search('^\x01ACTION (.*)\x01$', msg['msg'])
        if action:
            form, msg = 'action_public', action.group(1)
        else:
            form, msg = 'pubmsg', msg['msg']

        printformat(window, irssi.MSGLEVEL_MSGS, form, [ nick, '\x0303' + msg ])

    irssi.signal_stop()
    return 1

def privmsg_out(msg, server, query, command=False):
    if not query:
        return 0

    nick = query.name
    my_nick = server.nick

    if command:
        msg = msg.split()
        if len(msg) < 2:
            return 0

        command, msg = msg[0], ' '.join(msg[1:])

        if command != '/me':
            return 0

    if nick in keys and len(msg) == 384:
        return 0

    if nick[0] == '#':
        return 0

    if nick in keys and nick not in chats:
        chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
            chaff_block_size=8, debug=debug)

        silent_send(server, nick, chats[nick].encrypt_initial_keyx())
        irssi.signal_stop()
        return 1
    elif nick not in keys:
        return 0

    if command:
        pt = '\x01ACTION ' + msg + '\x01'
    else:
        pt = msg

    silent_send(server, nick, chats[nick].encrypt_msg(pt))

    if command:
        form = 'own_action'
    else:
        form = 'own_msg'

    printformat(irssi.active_win(), irssi.MSGLEVEL_PUBLIC, form, [ 
        my_nick, '\x0302' + msg
    ])

    irssi.signal_stop()
    return 1

def command_out(command, server, query):
    return privmsg_out(command, server, query, True)

load_keys()

irssi.get_script().theme_register([
    ('own_msg',  irssi.current_theme().get_format('fe-common/core', 'own_msg')),
    ('own_action',  irssi.current_theme().get_format('fe-common/irc', 'own_action')),
    ('pubmsg',  irssi.current_theme().get_format('fe-common/core', 'pubmsg')),
    ('action_public',  irssi.current_theme().get_format('fe-common/irc', 'action_public'))
])

irssi.command_bind('setkey', setkey)
irssi.command_bind('listkeys', listkeys)
irssi.command_bind('keyx', keyx)

irssi.signal_add('message private', privmsg_in)
irssi.signal_add('send text', privmsg_out)
irssi.signal_add('send command', command_out)
