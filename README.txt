Dependencies:

    * python 2.7
    * irssi-python
    * python-cryptography
    * curve25519-donna

cryptography and curve25519-donna can be install from pip or your
distribution's repositories. If your distribution does not have an
irssi-python package, I have included an install script that works
with irssi v0.8.17.

Commands:

    * /listkeys            - lists all known keys
    * /setkey <nick> <key> - saves a key for a nickname.
    * /keyx <nick>         - manual key exchange with a user.

Currently in beta, please report any bugs.
