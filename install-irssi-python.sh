#!/bin/bash
mkdir irssi-python
cd irssi-python
curl -L http://irssi.org/files/irssi-0.8.17.tar.gz |tar xz
curl -L https://github.com/downloads/danielrichman/irssi_rstatus/irssi-python-ac.tar.gz |tar xz
curl -O http://anti.teamidiot.de/static/nei/*/Code/Irssi/python-256color.diff

export PYTHON_VERSION=2

cd irssi-python
mv ../python-256color.diff ./src/
patch -p1 < src/python-256color.diff

./configure --with-irssi=../irssi-0.8.17 --prefix=/usr
make -C src constants
make

sudo make install
