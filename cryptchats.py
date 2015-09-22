#!/usr/bin/python2
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from os import urandom
from random import SystemRandom
import curve25519
import struct

bend = default_backend()
rand = SystemRandom()

class ChatsError(Exception):
    pass

class Chats(object):
    def __init__(self, long_term, bob_long_term, max_length=480, chaff_block_size=16,
      debug=False):
        self.debug = debug

        self.long_term = long_term
        self.long_term_public = self.long_term.get_public()
        self.bob_long_term = bob_long_term

        self.send_pending = None
        self.receive_pending = None

        self.i_am_alice = False

        # this gets the pre-base64 length, 480 bytes after base64 seems good for IRC.
        self.max_length = max_length * 3 / 4
        self.chaff_block_size = chaff_block_size
        self.cipher_block_size = AES.block_size / 8

        self.initial_key = { 'initial_key': True }
        self.init_keys()

    def init_keys(self):
        self.initial_key = { 'initial_key': True }
        self.send = { 'alice': curve25519.Private() }
        self.receive = { 'alice': curve25519.Private(), 'receiver': True }

    def hmac_counter(self, key):
        # increment counter
        if 'counter' in key:
            key['counter'] += 1
        else:
            key['counter'] = 0

        return key, self.derive_key(struct.pack('>I', key['counter']))

    def derive_key(self, key, length=96):
        hkdf = HKDFExpand(algorithm=SHA256(), length=length,
            info='cryptchats-protocol-v1', backend=bend)
        return hkdf.derive(key)

    def hmac(self, key, msg, truncate=None, algorithm=SHA256):
        hmac = HMAC(key, algorithm=algorithm(), backend=bend)
        hmac.update(msg)

        if truncate:
            return hmac.finalize()[:truncate]
        else:
            return hmac.finalize()

    def chaff(self, blocks):
        length = self.max_length / self.chaff_block_size
        needed_blocks = (length - len(blocks) * 2) / 2

        for _ in xrange(needed_blocks):
            c = [ urandom(self.chaff_block_size), urandom(self.chaff_block_size) ]
            blocks.insert(rand.randint(0, len(blocks)), c)

        c = ''
        for index, block in enumerate(blocks):
            c += block[0] + block[1]

        return c

    def get_blocks(self, _str):
        while _str:
            yield _str[:self.chaff_block_size]
            _str = _str[self.chaff_block_size:]

    def get_block_pairs(self, _str):
        blocks = [ [] ]

        for block in self.get_blocks(_str):
            if len(blocks[-1]) == 2:
                yield blocks[-1]
                blocks.append([ block ])
            else:
                blocks[-1].append(block)

        if len(blocks[-1]) == 2:
            yield blocks[-1]

    def mac_blocks(self, ct, key):
        blocks = []

        for block in self.get_blocks(ct):
            mac = self.hmac(key, block)[:self.chaff_block_size]
            blocks.append([ block, mac ])

        return blocks

    def encrypt_aes(self, key, counter, pt):
        if len(pt) % self.cipher_block_size:
            pt += '\x00' * (self.cipher_block_size - len(pt) % self.cipher_block_size)

        cipher = Cipher(AES(key), GCM(counter), backend=bend).encryptor()
        data = cipher.update(pt)
        cipher.finalize()
        return data, cipher.tag

    def decrypt_aes_initial_keyx(self, ct):
        counter = ct[:self.cipher_block_size]
        tag = ct[self.cipher_block_size:self.cipher_block_size*2]
        ct = ct[self.cipher_block_size*2:]
        key = self.derive_keys()

        self.print_key('Decrypting initial key exchange.', key)

        cipher = Cipher(AES(key['message_key']), GCM(counter, tag),
            backend=bend).decryptor()

        try:
            pt = cipher.update(ct)
            cipher.finalize()
        except InvalidTag:
            return None, None

        return pt[:32], pt[32:64]

    def decrypt_aes_keyx(self, ct, tag, decryptor):
        decryptor = self.derive_keys(decryptor)

        key = decryptor['exchange_key']
        counter = decryptor['exchange_counter']

        cipher = Cipher(AES(key), GCM(counter, tag), backend=bend).decryptor()

        try:
            pt = cipher.update(ct)
            cipher.finalize()
        except InvalidTag:
            return None

        return pt[:32]

    def decrypt_aes_msg(self, ct, tag, decryptor):
        decryptor = self.derive_keys(decryptor)

        key = decryptor['message_key']
        counter = decryptor['message_counter']

        cipher = Cipher(AES(key), GCM(counter, tag), backend=bend).decryptor()

        try:
            pt = cipher.update(ct)
            cipher.finalize()
        except InvalidTag:
            return None

        bob_ephemeral, msg = pt[:32], pt[32:]

        self.receive = decryptor

        # it's encrypted with the same key it advertised.. shouldn't happen.
        if bob_ephemeral == self.receive['bob'].serialize():
            raise
        # it's advertising the receive_pending key, we need to respond again because
        # they may not have gotten it.
        elif self.receive_pending \
          and bob_ephemeral == self.receive_pending['bob'].serialize():
            pass
        # yay a new key! we need to respond.
        elif not self.receive_pending \
          or bob_ephemeral != self.receive_pending['bob'].serialize():

            self.receive_pending = {
                'alice': curve25519.Private(),
                'bob': curve25519.Public(bob_ephemeral),
                'receiver': True
            }
        # uncharted territory...
        else:
            raise

        return msg

    def get_public(self, key):
        return key.get_public().serialize()

    def derive_keys(self, key=None):
        # initial key exchanges.
        if not key or 'bob' not in key:
            master = self.long_term.get_shared_key(self.bob_long_term, self.derive_key)
            key = key or {}
        # we're sending
        elif 'receiver' not in key:
            master  = self.long_term.get_shared_key(key['bob'], self.derive_key)
            master += key['alice'].get_shared_key(self.bob_long_term, self.derive_key)
            master += key['alice'].get_shared_key(key['bob'], self.derive_key)
        # we are receiving
        else:
            if 'alice' not in key:
                key['alice'] = curve25519.Private()

            master  = key['alice'].get_shared_key(self.bob_long_term, self.derive_key)
            master += self.long_term.get_shared_key(key['bob'], self.derive_key)
            master += key['alice'].get_shared_key(key['bob'], self.derive_key)

        # derive keys
        key, hmac_key = self.hmac_counter(key)
        master = self.derive_key(self.hmac(hmac_key, master, algorithm=SHA512), 192)
        
        keys = list(struct.unpack('>32s32s32s32s32s32s', master))
        key['exchange_counter'] = keys.pop()
        key['message_counter'] = keys.pop()
        key['exchange_chaff_key'] = keys.pop()
        key['chaff_key'] = keys.pop()
        key['exchange_key'] = keys.pop()
        key['message_key'] = keys.pop()
        return key

    def receive_key(self, bob_ephemeral):
        self.receive['bob'] = curve25519.Public(bob_ephemeral)
        if 'counter' in self.receive:
            del self.receive['counter']

    def send_key(self, bob_ephemeral):
        self.send['bob'] = curve25519.Public(bob_ephemeral)
        if 'counter' in self.send:
            del self.send['counter']

    def got_key(self, bob_ephemeral):
        if not bob_ephemeral:
            return

        if self.send_pending and bob_ephemeral != self.send['bob'].serialize():
            self.send = self.send_pending
            self.send_key(bob_ephemeral)
            self.send_pending = None

    def encrypt_msg(self, msg):
        self.send = self.derive_keys(self.send)
        self.print_key('Encrypting message.', self.send)

        if not self.send_pending:
            self.send_pending = { 'alice': curve25519.Private() }

        pt  = self.get_public(self.send_pending['alice'])
        pt += msg

        ct, tag = self.encrypt_aes(self.send['message_key'],
            self.send['message_counter'], pt)

        blocks = self.mac_blocks(tag + ct, self.send['chaff_key'])
        return self.chaff(blocks)

    def encrypt_keyx(self):
        self.send = self.derive_keys(self.send)
        self.print_key('Encrypting keyx.', self.send)

        data = self.get_public(self.receive_pending['alice'])
        ct, tag = self.encrypt_aes(self.send['exchange_key'],
            self.send['exchange_counter'], data)

        blocks = self.mac_blocks(tag + ct, self.send['exchange_chaff_key'])
        return self.chaff(blocks)

    def encrypt_initial_keyx(self):
        self.i_am_alice = 'bob' not in self.receive

        counter = urandom(self.cipher_block_size)
        key = self.derive_keys()
        self.print_key('Encrypting initial key exchange.', key)

        if self.i_am_alice:
            ephem_keys  = self.get_public(self.receive['alice'])
            ephem_keys += self.get_public(self.send['alice'])
        else:
            ephem_keys  = self.get_public(self.send['alice'])
            ephem_keys += self.get_public(self.receive['alice'])

        ct, tag = self.encrypt_aes(key['message_key'], counter, ephem_keys)

        blocks = self.mac_blocks(counter + tag + ct, key['chaff_key'])
        return self.chaff(blocks)

    def try_dechaffing(self, ct):
        blocks = []
        exchange_blocks = []

        for key in [ self.receive_pending, self.receive, self.initial_key ]:
            if not key:
                continue
       
            if 'counter' not in key:
                key['counter'] = -1
            
            original_counter = key['counter']

            while not exchange_blocks and not blocks and key['counter'] < 5:
                key = self.derive_keys(key)
                self.print_key('Testing.', key)

                for block_pair in self.get_block_pairs(ct):
                    if self.hmac(key['chaff_key'], block_pair[0], self.chaff_block_size) \
                      == block_pair[1]:
                        blocks.append(block_pair[0])
                    elif self.hmac(key['exchange_chaff_key'], block_pair[0],
                      self.chaff_block_size) == block_pair[1]:
                        exchange_blocks.append(block_pair[0])
                    
            if blocks or exchange_blocks:
                break
            else:
                key['counter'] = original_counter

        if blocks or exchange_blocks:
            if key == self.initial_key:
                del key['counter']
            else:
                key['counter'] -= 1
            return ''.join(blocks), ''.join(exchange_blocks), key
        else:
            return None, None, None

    def decrypt_msg(self, ct):
        # self.print_key('Received message.', self.receive)
        ct, exchange_ct, key = self.try_dechaffing(ct)

        if not ct and not exchange_ct:
            raise ChatsError('not encrypted.')

        if 'bob' not in key:
            bob_ephem1, bob_ephem2 = self.decrypt_aes_initial_keyx(ct)
            if not bob_ephem1:
                return None

            if self.i_am_alice:
                self.receive_key(bob_ephem1)
                self.send_key(bob_ephem2)
                return { 'keyx': True }
            else:
                self.init_keys()
                self.send_key(bob_ephem1)
                self.receive_key(bob_ephem2)
                return { 'keyx': self.encrypt_initial_keyx() }
        elif ct:
            self.receive = key
            self.print_key('Decrypting message.', self.receive)
            msg = self.decrypt_aes_msg(ct[16:], ct[:16], self.receive)

            if self.receive_pending:
                return { 'msg': msg, 'keyx': self.encrypt_keyx() }
            else:
                return { 'msg': msg }
        else:
            self.print_key('Decrypting keyx.', key)
            bob_ephemeral = self.decrypt_aes_keyx(exchange_ct[16:48], exchange_ct[:16], key)
            self.got_key(bob_ephemeral)
            return None

    def print_key(self, title, key):
        if not self.debug:
            return

        print ''
        print title
        print ''

        print 'Alice long term public: ' + self.get_public(self.long_term).encode('hex')
        print 'Bob long term public:   ' + self.bob_long_term.serialize().encode('hex')

        if 'alice' in key:
            print 'Alice ephemeral public: ' + self.get_public(key['alice']).encode('hex')
        if 'bob' in key:
            print 'Bob ephemeral public:   ' + key['bob'].serialize().encode('hex')
        if 'message_key' in key:
            print 'Shared key:             ' + key['message_key'].encode('hex')
        if 'chaff_key' in key:
            print 'Chaff key:              ' + key['chaff_key'].encode('hex')
        if 'exchange_key' in key:
            print 'Exchange shared key:    ' + key['exchange_key'].encode('hex')
        if 'exchange_chaff_key' in key:
            print 'Exchange chaff key:     ' + key['exchange_chaff_key'].encode('hex')
        if 'counter' in key:
            print 'Counter:                %d' % key['counter']

        print ''

if __name__ == "__main__":
    alice_key = curve25519.Private()
    bob_key = curve25519.Private()

    alice = Chats(alice_key, bob_key.get_public(), 400, 8, debug=False)
    bob = Chats(bob_key, alice_key.get_public(), 400, 8, debug=False)

    ct = alice.encrypt_initial_keyx()
    msg = bob.decrypt_msg(ct)
    alice.decrypt_msg(msg['keyx'])

    print '\nAlice -> Bob initial: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    msg = bob.decrypt_msg(ct)
    if msg['keyx']: alice.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']

    print '\nAlice -> Bob, Bob decrypts but forgets to respond to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    msg = bob.decrypt_msg(ct)
    print 'Plaintext: %s' % msg['msg']

    print '\nAlice -> Bob, Bob decrypts and responds to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    msg = bob.decrypt_msg(ct)
    if msg['keyx']: alice.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']

    print '\nAlice -> Bob, Bob decrypts and responds to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    msg = bob.decrypt_msg(ct)
    if msg['keyx']: alice.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']

    print '\nAlice -> Bob, Alice loses her message: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')

    print '\nAlice -> Bob, Alice sends Bob another message and Bob responds: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    msg = bob.decrypt_msg(ct)
    if msg['keyx']: alice.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']

    print '\nBob -> Alice, Bob responds to Alice. She responds to the key exchange: '
    ct = bob.encrypt_msg('ayy :)')
    msg = alice.decrypt_msg(ct)
    if msg['keyx']: bob.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']

    print '\nAlice -> Bob, Bob decrypts and responds to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    msg = bob.decrypt_msg(ct)
    if msg['keyx']: alice.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']

    print '\nBob -> Alice, Alice forgets to respond to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    msg = alice.decrypt_msg(ct)
    print 'Plaintext: %s' % msg['msg']

    print '\nBob -> Alice, Alice never receives the message: '
    ct = bob.encrypt_msg('pls response')

    print '\nBob -> Alice, Alice forgets to respond to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    msg = alice.decrypt_msg(ct)
    print 'Plaintext: %s' % msg['msg']

    print '\nBob -> Alice, Alice finally responds to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    msg = alice.decrypt_msg(ct)
    if msg['keyx']: bob.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']

    print '\nBob -> Alice, Alice responds to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    msg = alice.decrypt_msg(ct)
    if msg['keyx']: bob.decrypt_msg(msg['keyx'])
    print 'Plaintext: %s' % msg['msg']
