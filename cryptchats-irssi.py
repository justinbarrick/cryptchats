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

def fix_key_perms():
    os.chmod(key_path, 0600)

def save_keys():
    tmp_keys = {}

    for key in keys:
        tmp_keys[key] = b64encode(keys[key].serialize())

    json.dump(tmp_keys, os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT,
        0600), 'w'))

def load_keys():
    try:
        tmp_keys = json.load(open(key_path))
        fix_key_perms()
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

def send_msg(server, nick, msg, command=False, resent=False):
    index = 96 if not command else 87

    while msg:
        tmp_msg, msg = msg[:index], msg[index:]

        if command:
            pt = '\x01ACTION ' + tmp_msg + '\x01'
        else:
            pt = tmp_msg

        ct = chats[nick].encrypt_msg(pt)
        if not ct:
            return

        silent_send(server, nick, ct)

        if command or pt[:7] == '\x01ACTION':
            form = 'own_action'
        else:
            form = 'own_msg'

        color = '\x0302'
        if resent:
            color = '\x0306[RESENT] ' + color

        printformat(irssi.active_win(), irssi.MSGLEVEL_PUBLIC, form, [
            server.nick, color + tmp_msg
        ])

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

def create_chats(nick):
    if nick not in keys:
        return None

    if nick not in chats:
        chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
            chaff_block_size=8, debug=debug)

    return chats[nick]

def keyx(data, server, witem):
    nick = data.rstrip()

    if nick not in keys:
        return 

    if not nick:
        print 'Usage: /keyx <nick>'
        return

    create_chats(nick).init_keys()
    silent_send(server, nick, chats[nick].encrypt_initial_keyx())
    return 

def privmsg_in(server, msg, nick, user):
    omsg = msg

    window = server.window_item_find(nick)
    if not create_chats(nick):
        return 0

    if re.match(r'^\[\d\d:\d\d:\d\d\] ', msg):
        msg = msg[11:]

    try:
        msg = chats[nick].decrypt_msg(b64decode(msg))
    except ChatsError:
        if len(msg) != 384:
            window = server.window_item_find(nick)
            printformat(window, irssi.MSGLEVEL_MSGS, 'pubmsg', [ nick, '\x0305' + omsg ])
        else:
            keyx(nick, server, None)
        msg = None
    except TypeError:
        return 0

    if msg and 'keyx' in msg:
        if msg['keyx'] == True:
            window.prnt('Key exchange with %s completed.' % nick)
        else:
            if 'msg' not in msg:
                window.prnt('Received key exchange from %s.' % nick)
            silent_send(server, nick, msg['keyx'])

    if msg and 'msg' in msg:
        msg['msg'] = msg['msg'].replace('\0', '')

        action = re.search('^\x01ACTION (.*)\x01$', msg['msg'])
        if action:
            form, msg = 'action_public', action.group(1)
        else:
            form, msg = 'pubmsg', msg['msg']

        printformat(window, irssi.MSGLEVEL_MSGS, form, [ nick, '\x0303' + msg ])

    if msg and 'msgs' in msg and msg['msgs']:
        window.prnt('Re-sending un-acked messages to %s.' % nick)
        for msg in msg['msgs']:
            send_msg(server, nick, msg, resent=True)

    irssi.signal_stop()
    return 1

def privmsg_out(msg, server, query, command=False):
    if not query:
        return 0

    nick = query.name

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
    elif nick not in keys:
        return 0

    send_msg(server, nick, msg, command=command)
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
