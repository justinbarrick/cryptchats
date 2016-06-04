#!/bin/bash

# download irssi python
git clone https://github.com/irssi-import/irssi-python
cd irssi-python

# download latest irssi source to compile against
curl -L https://github.com/irssi/irssi/releases/download/0.8.19/irssi-0.8.19.tar.gz |tar xz

# build irssi-python against latest irssi source
export PYTHON_VERSION=2
autoreconf -ivf -I.
./configure --with-irssi=irssi-0.8.19 --prefix=/usr
make -C src constants
make
libtool --finish /usr/lib/irssi/modules

# install irssi-python globally
sudo make install
