# -*- coding: utf-8 -*-

SCRIPT_NAME = "chats"
SCRIPT_DESC = "chats"

import re
import weechat
from cryptchats import Chats, ChatsError
import curve25519
import base64
import json

chats = {}
keys = {}
key_path = ''

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

def b64decode(_str):
    return base64.b64decode(_str)

def b64encode(_str):
    return base64.b64encode(_str).replace('\n', '')

def chats_unload_cb():
    return weechat.WEECHAT_RC_OK

def create_window(server_name, nick):
    buff = weechat.info_get('irc_buffer', '%s,%s' % (server_name, nick))
    if weechat.buffer_get_string(buff, "localvar_type") != "private":
        weechat.command(buff, '/mute -all query ' + nick)

def silent_send(server_name, nick, msg):
    print server_name, nick
    buff = weechat.info_get('irc_buffer', '%s,%s' % (server_name, nick))
    weechat.command(buff, '/mute -all say ' + b64encode(msg))

def chats_setkey_cb(data, buffer, args):
    args = args.split(' ')

    try:
        keys[args[0]] = curve25519.Public(b64decode(args[1]))
        save_keys()
    except:
        print 'Invalid key: /setkey <nick> <key>.'

    return weechat.WEECHAT_RC_OK

def chats_listkeys_cb(data, buffer, args):
    print 'Your key: ' + b64encode(keys['my_key'].get_public().serialize())

    for key in keys:
        if key == 'my_key':
            continue

        print '%s: %s' % (key, b64encode(keys[key].serialize()))

    return weechat.WEECHAT_RC_OK

def chats_keyx_cb(data, buff, args):
    nick = args
    create_window('', nick)

    if nick not in chats:
        return weechat.WEECHAT_RC_OK

    chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
        chaff_block_size=8, debug=True)

    silent_send('', nick, chats[nick].encrypt_initial_keyx())
    return weechat.WEECHAT_RC_OK

def chats_modifier_in_privmsg_cb(data, modifier, server_name, string):
    my_nick = weechat.info_get('irc_nick', server_name)

    omsg = re.search('^:([^ ]+)!([^ ]+)@([^ ]+) PRIVMSG ' + my_nick + ' :(.*)$', string)
    if not omsg:
        return string

    nick = omsg.group(1)
    msg = omsg.group(4)

    create_window(server_name, nick)

    if nick in keys and nick not in chats:
        chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
            chaff_block_size=8, debug=True)
    elif nick not in keys:
        return string

    try:
        msg = chats[nick].decrypt_msg(b64decode(msg))
    except ChatsError:
        return ':%s!%s@%s PRIVMSG %s :%s' % (nick, omsg.group(2), omsg.group(3),
            my_nick, '\x0305' + omsg.group(4))

    if not msg:
        return ''

    if 'keyx' in msg:
        if msg['keyx'] == True:
            print 'Key exchange with %s completed.' % nick
        else:
            silent_send(server_name, nick, msg['keyx'])

    if 'msg' in msg:
        return ':%s!%s@%s PRIVMSG %s :%s' % (nick, omsg.group(2), omsg.group(3),
            my_nick, '\x0303' + msg['msg'])
    else:
        return ''

def chats_modifier_out_privmsg_cb(data, modifier, server_name, string):
    msg = re.search('^PRIVMSG ([^# ]+) :(.*)$', string)
    if not msg:
        return string

    print '...'

    nick = msg.group(1)
    msg = msg.group(2)

    if nick in keys and len(msg) == 384:
        return string

    my_nick = weechat.info_get('irc_nick', server_name)
    if nick in keys and nick not in chats:
        chats[nick] = Chats(keys['my_key'], keys[nick], max_length=400,
            chaff_block_size=8, debug=True)

        return 'PRIVMSG %s :%s' % (nick, b64encode(chats[nick].encrypt_initial_keyx()))

    elif nick not in keys:
        return string

    return 'PRIVMSG %s :%s' % (nick, b64encode(chats[nick].encrypt_msg(msg)))

if __name__ == "__main__" and weechat.register(SCRIPT_NAME, '', '', '', SCRIPT_DESC,
  "chats_unload_cb", ''):
    key_path = weechat.info_get('weechat_dir', '') + '/keys.json'
    load_keys()

    weechat.hook_command('setkey', 'set a key',
        '<nick> <key>',
        'jaja',
        ' || %(nick) %(key)', 
        'chats_setkey_cb', '')

    weechat.hook_command('listkeys', 'list keys',
        '',
        'jaja',
        ' || ', 
        'chats_listkeys_cb', '')

    weechat.hook_command('keyx', 'do a key exchange',
        '<nick>',
        'jaja',
        ' || %(nick)',
        'chats_keyx_cb', '')

    weechat.hook_modifier("irc_in_privmsg", "chats_modifier_in_privmsg_cb", "")
    weechat.hook_modifier("irc_out_privmsg", "chats_modifier_out_privmsg_cb", "")
