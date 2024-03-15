#!/bin/bash


set -e

VERSION_PEX=$(cat helpers/VERSION.pyinstxtractor-ng)
BASE_URL=https://raw.githubusercontent.com/pyinstxtractor/pyinstxtractor-ng/$VERSION_PEX

echo "Downloading dependencies for pyinstxtractor-ng $VERSION_PEX from $BASE_URL"
echo $BASE_URL/requirements.txt
curl $BASE_URL/requirements.txt -o /tmp/requirements.txt
pip install -r /tmp/requirements.txt
rm /tmp/requirements.txt

curl -L $BASE_URL/pyinstxtractor-ng.py -o pyinstxtractor.py

VERSION_PYI=$(cat helpers/VERSION.pyinstaller)
echo "Downloading hooks for pyinstaller $VERSION_PYI"
curl -L https://raw.githubusercontent.com/pyinstaller/pyinstaller/$VERSION_PYI/PyInstaller/hooks/rthooks.dat -o rthooks.dat