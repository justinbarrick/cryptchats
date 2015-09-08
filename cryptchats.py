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

class Chats(object):
    def __init__(self, long_term, bob_long_term, max_length=480, debug=False):
        self.debug = debug

        self.long_term = long_term
        self.long_term_public = self.long_term.get_public()
        self.bob_long_term = bob_long_term

        self.send_pending = None
        self.receive_pending = None

        # this gets the pre-base64 length, 480 bytes after base64 seems good for IRC.
        self.max_length = max_length * 3 / 4
        self.block_size = AES.block_size / 8

    def hmac_counter(self, key):
        if 'counter' in key:
            key['counter'] += 1
        else:
            key['counter'] = 0

        return key, self.derive_key(struct.pack('>I', key['counter']))

    def derive_key(self, key, length=96):
        hkdf = HKDFExpand(algorithm=SHA256(), length=length, info='chats', backend=bend)
        return hkdf.derive(key)

    def hmac(self, key, msg, algorithm=SHA256):
        hmac = HMAC(key, algorithm=algorithm(), backend=bend)
        hmac.update(msg)
        return hmac.finalize()

    def chaff(self, blocks):
        length = self.max_length / self.block_size
        needed_blocks = (length - len(blocks) * 2) / 2

        for _ in xrange(needed_blocks):
            c = [ urandom(self.block_size), urandom(self.block_size) ]
            blocks.insert(rand.randint(0, len(blocks)), c)

        c = ''
        for index, block in enumerate(blocks):
            c += block[0] + block[1]

        return c

    def get_blocks(self, _str):
        while _str:
            yield _str[:self.block_size]
            _str = _str[self.block_size:]

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
            mac = self.hmac(key, block)[:16]
            blocks.append([ block, mac ])

        return blocks

    def encrypt_aes(self, key, counter, pt):
        if len(pt) % self.block_size:
            pt += '\x00' * (self.block_size - len(pt) % self.block_size)

        cipher = Cipher(AES(key), GCM(counter), backend=bend).encryptor()
        data = cipher.update(pt)
        cipher.finalize()
        return data, cipher.tag

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

    def init_keys(self, send=None, receive=None):
        self.send = { 'alice': send or curve25519.Private() }
        self.receive = { 'alice': receive or curve25519.Private(), 'receiver': True }

        return self.get_public(self.receive['alice']), self.get_public(self.send['alice'])

    def derive_keys(self, key):
        if 'receiver' not in key:
            master  = self.long_term.get_shared_key(key['bob'], self.derive_key)
            master += key['alice'].get_shared_key(self.bob_long_term, self.derive_key)
            master += key['alice'].get_shared_key(key['bob'], self.derive_key)
        else:
            if 'alice' not in key:
                key['alice'] = curve25519.Private()

            master  = key['alice'].get_shared_key(self.bob_long_term, self.derive_key)
            master += self.long_term.get_shared_key(key['bob'], self.derive_key)
            master += key['alice'].get_shared_key(key['bob'], self.derive_key)

        key, hmac_key = self.hmac_counter(key)
        master = self.derive_key(self.hmac(hmac_key, master, SHA512), 192)
        
        key['message_key'] = master[:32]
        key['exchange_key'] = master[32:64]
        key['chaff_key'] = master[64:96]
        key['exchange_chaff_key'] = master[96:128]
        key['message_counter'] = master[128:160]
        key['exchange_counter'] = master[160:192]

        return key

    def receive_key(self, bob_ephemeral):
        self.receive['bob'] = curve25519.Public(bob_ephemeral)

    def send_key(self, bob_ephemeral):
        self.send['bob'] = curve25519.Public(bob_ephemeral)

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

    def try_dechaffing(self, ct):
        blocks = []
        exchange_blocks = []

        for key in [ self.receive_pending, self.receive ]:
            if not key:
                continue
        
            if 'counter' not in key:
                key['counter'] = -1
            
            original_counter = key['counter']

            while not exchange_blocks and not blocks and key['counter'] < 5:
                key = self.derive_keys(key)

                for block_pair in self.get_block_pairs(ct):
                    if self.hmac(key['chaff_key'], block_pair[0])[:16] == block_pair[1]:
                        blocks.append(block_pair[0])
                    elif self.hmac(key['exchange_chaff_key'], block_pair[0])[:16] == \
                      block_pair[1]:
                        exchange_blocks.append(block_pair[0])
                    
            if blocks or exchange_blocks:
                break
            else:
                key['counter'] = original_counter

        if blocks or exchange_blocks:
            key['counter'] -= 1
            return ''.join(blocks), ''.join(exchange_blocks), key
        else:
            return None, None, None

    def decrypt_msg(self, ct):
        ct, exchange_ct, key = self.try_dechaffing(ct)
        if not ct and not exchange_ct:
            return None, None

        if ct:
            self.receive = key
            self.print_key('Decrypting message.', self.receive)
            msg = self.decrypt_aes_msg(ct[16:], ct[:16], self.receive)

            if self.receive_pending:
                return msg, self.encrypt_keyx()
            else:
                return msg, None
        else:
            self.print_key('Decrypting keyx.', key)
            bob_ephemeral = self.decrypt_aes_keyx(exchange_ct[16:48], exchange_ct[:16], key)
            self.got_key(bob_ephemeral)
            return None, None

    def print_key(self, title, key):
        if not self.debug:
            return

        print ''
        print title
        print ''

        print 'Alice long term public: ' + self.get_public(self.long_term).encode('hex')
        print 'Bob long term public:   ' + self.bob_long_term.serialize().encode('hex')
        print 'Alice ephemeral public: ' + self.get_public(key['alice']).encode('hex')
        print 'Bob ephemeral public:   ' + key['bob'].serialize().encode('hex')
        print 'Shared key:             ' + key['message_key'].encode('hex')
        print 'Chaff key:              ' + key['chaff_key'].encode('hex')
        print 'Exchange shared key:    ' + key['exchange_key'].encode('hex')
        print 'Exchange chaff key:     ' + key['exchange_chaff_key'].encode('hex')
        print 'Counter:                %d' % key['counter']

        print ''

if __name__ == "__main__":
    alice_key = curve25519.Private()
    bob_key = curve25519.Private()

    alice = Chats(alice_key, bob_key.get_public(), debug=True)
    bob = Chats(bob_key, alice_key.get_public(), debug=True)

    alice_receive, alice_send = alice.init_keys()
    bob_receive, bob_send = bob.init_keys()

    alice.receive_key(bob_send)
    bob.send_key(alice_receive)

    alice.send_key(bob_receive)
    bob.receive_key(alice_send)

    print '\nAlice -> Bob initial: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    pt, pk = bob.decrypt_msg(ct)
    if pk: alice.decrypt_msg(pk)
    print 'Plaintext: %s' % pt

    print '\nAlice -> Bob, Bob decrypts but forgets to respond to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    pt, pk = bob.decrypt_msg(ct)
    print 'Plaintext: %s' % pt

    print '\nAlice -> Bob, Bob decrypts and responds to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    pt, pk = bob.decrypt_msg(ct)
    if pk: alice.decrypt_msg(pk)
    print 'Plaintext: %s' % pt

    print '\nAlice -> Bob, Bob decrypts and responds to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    pt, pk = bob.decrypt_msg(ct)
    if pk: alice.decrypt_msg(pk)
    print 'Plaintext: %s' % pt

    print '\nAlice -> Bob, Alice loses her message: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')

    print '\nAlice -> Bob, Alice sends Bob another message and Bob responds: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    pt, pk = bob.decrypt_msg(ct)
    if pk: alice.decrypt_msg(pk)
    print 'Plaintext: %s' % pt

    print '\nBob -> Alice, Bob finally responds to Alice and she responds to the key exchange: '
    ct = bob.encrypt_msg('ayy :)')
    pt, pk = alice.decrypt_msg(ct)
    if pk: bob.decrypt_msg(pk)
    print 'Plaintext: %s' % pt

    print '\nAlice -> Bob, Bob decrypts and responds to the key exchange: '
    ct = alice.encrypt_msg('ayy lmaoayy lmao')
    pt, pk = bob.decrypt_msg(ct)
    if pk: alice.decrypt_msg(pk)
    print 'Plaintext: %s' % pt

    print '\nBob -> Alice, Alice forgets to respond to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    pt, pk = alice.decrypt_msg(ct)
    print 'Plaintext: %s' % pt

    print '\nBob -> Alice, Alice never receives the message: '
    ct = bob.encrypt_msg('pls response')

    print '\nBob -> Alice, Alice forgets to respond to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    pt, pk = alice.decrypt_msg(ct)
    print 'Plaintext: %s' % pt

    print '\nBob -> Alice, Alice finally responds to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    pt, pk = alice.decrypt_msg(ct)
    if pk: bob.decrypt_msg(pk)
    print 'Plaintext: %s' % pt

    print '\nBob -> Alice, Alice responds to the key exchange: '
    ct = bob.encrypt_msg('pls response')
    pt, pk = alice.decrypt_msg(ct)
    if pk: bob.decrypt_msg(pk)
    print 'Plaintext: %s' % pt
