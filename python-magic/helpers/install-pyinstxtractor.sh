#!/bin/bash


set -e

VERSION=$(cat helpers/VERSION.pyinstxtractor-ng)
BASE_URL=https://raw.githubusercontent.com/pyinstxtractor/pyinstxtractor-ng/$VERSION

echo "Downloading dependencies for pyinstxtractor-ng $VERSION from $BASE_URL"
echo $BASE_URL/requirements.txt
curl $BASE_URL/requirements.txt -o /tmp/requirements.txt
pip install -r /tmp/requirements.txt
rm /tmp/requirements.txt

curl -L $BASE_URL/pyinstxtractor-ng.py -o pyinstxtractor.py