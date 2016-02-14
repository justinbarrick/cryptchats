# Cryptchats

Cryptchats is a plugin for irssi implementing strong cryptography for private
messages. It is still a work in progress and likely has some security issues. As usual,
it should not be considered secure.

This protocol is based off of the
[ntor handshake](https://gitweb.torproject.org/torspec.git/tree/proposals/216-ntor-handshake.txt),
[axolotl protocol](https://github.com/trevp/axolotl/wiki), and
[OTR](https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html).
It was designed for high security and obfuscation of ciphertexts and metadata.

# Dependencies

    * python 2.7
    * irssi-python
    * curve25519-donna
    * libnacl
    * hkdf

hkdf, libnacl, and curve25519-donna can be installed from pip or your
distribution's repositories. If your distribution does not have an
irssi-python package, I have included an install script that works
with irssi v0.8.17.

# Setup

Install the dependencies and setup cryptchats:

    $ sudo apt-get install python-dev build-essential
    $ sudo apt-get build-dep irssi
    $ ./install-irssi-python.sh
    $ virtualenv ~/.cryptchats
    $ source ~/.cryptchats/bin/activate
    $ pip install -r requirements.txt
    $ ln -s ~/src/cryptchats/cryptchats-irssi.py ~/.irssi/scripts/
    $ ln -s ~/src/cryptchats/cryptchats.py ~/.irssi/scripts/
    $ ln -s ~/src/cryptchats/cryptchats-irssi.py ~/.irssi/scripts/autorun/
    $ echo load python >> .irssi/startup
    $ echo "alias irssi='source ~/.cryptchats/bin/activate && irssi'" >> ~/.bashrc

# Commands

    * /listkeys            - lists all known keys
    * /setkey <nick> <key> - saves a key for a nickname.
    * /keyx <nick>         - manual key exchange with a user.

Currently in beta, please report any bugs.

# Protocol description

* salsa20 with Pol1305
* curve25519
* Poly1305
* hkdf with proto_id 'cryptchats-protocol-v1'

Each user has a long term curve25519 key that is generated when the script
is first loaded. The public key should be shared over a secure channel
prior to communicating with cryptchats, we use key pinning to simplify
the key exchange and to prevent man-in-the-middle attacks.

To preserve forward secrecy, each message is prepended with the next ephemeral
public key. Bob (the receiver) responds with his own ephemeral key acknowledging
the new key. Once he does that, Alice can begin using the new key where she'll
immediately generate a new key. If a key exchange is not acknowledged, Alice can
use the same key to encrypt the next several message to allow for network latency
or other delivery problems.

Alice and Bob use seperate keys for encryption and decryption.

## Key derivation

After Alice and Bob have exchanged keys, they derive several 256-bit encryption keys for
MAC keys, message keys, key exchanges keys, and the nonce.

### Generating the key seed in the initial key exchange

In the initial key exchange we don't yet have ephemeral keys to use, so we
just use the identity keys.

    key_seed = ECDH(alice_long_term, bob_long_term)

### Generating session key seeds

After the initial key exchange, all messages should use a key seed created by concatenating
the shared keys of Alice and Bob's longterms with the other's ephemeral and their two
ephemeral key's shared key:

    key_seed = ECDH(alice_ephemeral, bob_long_term) | ECDH(alice_long_term, bob_ephemeral) |
        ECDH(alice_ephemeral, bob_ephemeral)

### Deriving keys

Once the key seed is generated, the key seed is concatenated with the message counter (a
tally of all messages encrypted with this key, starting with zero) as literal string digits
(e.g. '0') and then MACed with the key of 'cryptchats-protocol-v1::poly1305'. This
value is then passed through the HKDF with SHA512 to generate the 176-byte master key.

    hmac_key = proto_id | ':mac'
    master = HKDF(Poly1305(key_seed | str(counter), hmac_key), 176)

From this master key we derive a series of 256-bit keys:

    message_key | exchange_key | chaff_key | exchange_chaff_key | message_counter |
        exchange_counter

## Message encryption

### Initial key exchange

To begin a session with Bob, Alice first generates a random counter and
two ephemeral keys - one for receiving and one for sending. Alice computes
a shared key with Bob using the method above (we discard the generated message
counter and use a random one because this key will never change). She then
encrypts her ephemeral keys with the `message_key` and sends these to Bob:

    random_counter = random(24)
    message = alice_ephemeral_receiving | alice_ephemeral_sending
    ct, tag = Salsa20(message, message_key, random_counter)
    ct = random_counter | tag | ct

For chaffing, Alice will use the generated `chaff_key`. Bob does the same thing
when responding, except the message is reversed and instead of using the `message_key`
and `chaff_key`, he uses the `exchange_key` and `exchange_chaff_key`. This allows
the client to distinguish between fresh key exchanges and acknowledgements.

    random_counter = random(24)
    message = bob_ephemeral_sending | bob_ephemeral_receiving
    ct, tag = Salsa20(message, exchange_key, random_counter)
    ct = random_counter | tag | ct

### Encrypting messages

To send an encrypted message, Alice first derives the master keys. If Alice has not sent
any messages using the current ephemeral key, she generates a new ephemeral key. If she
has, then Alice will resend the previously generated ephemeral key.

    message = alice_ephemeral | message
    ct, tag = Salsa20(message, message_key, message_counter)
    ct = tag | ct

For chaffing, Alice will use the generated `chaff_key`. After sending the message,
Alice increments the send counter.

### Encrypting key exchanges

When encrypting key exchange responses, Alice still uses her normal send key but does not
send a new ephemeral key for sending, only one for receiving (that is, key exchange
acknowledgements do not result in further key exchanges). She generates a new ephemeral
key and encrypts it with the exchange keys.

    message = alice_receive_ephemeral
    ct, tag = Salsa20(message, exchange_key, exchange_counter)
    ct = tag | ct

For chaffing, Alice will use the generated `exchange_chaff_key` and she increments the
send counter after sending the key exchange message.

## Chaffing

In order to futher obfuscate encrypted messages we use 
[chaffing](https://en.wikipedia.org/wiki/Chaffing_and_winnowing) to introduce random
blocks into the message. This hinders the attacker by ensuring the attacker can
never know which blocks even are ciphertext.

The ciphertext is broken into 8-byte blocks and each of these blocks is MACed using the
derived chaff key. These pairs of blocks (block and MAC) are then arranged in order with
the MACs truncated to 8-bytes. Next, random block pairs are introduced randomly between
the block pairs until a fixed message length is reached.

    block_pairs = []

    for all eight byte blocks in ct
        block_pairs.append(block, Poly1305(block, chaff_key))

    while len(block_pairs) < fixed_block_num
        block_pairs.random_insert(random_block_pair)

## Winnowing

To winnow the message ("de-chaff"), we iterate over block pairs and check the chaff keys.
If the exchange chaff key matches, then we know this is a key exchange message. If the
message chaff key matches, then we know it is a message for Alice. The final key to check
is the key exchange key, which allows Bob to initiate a key exchange at any time in case
of session loss. Once we have settled on a key, we discard block pairs with incorrect
MACs and rebuild the ciphertext. Clients should try several send counters if the keys
do not work to ensure that dropped messages do not disrupt chats.
