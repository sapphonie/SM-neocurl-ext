#!/bin/bash

cd /mnt/curl/
git config --global --add safe.directory "*"
rm -rf ./sm-1.11
git clone https://github.com/alliedmodders/sourcemod --branch 1.11-dev sm-1.11 --recursive 
rm -rf ./mm-1.11
git clone https://github.com/alliedmodders/metamod-source --branch 1.11-dev mm-1.11 --recursive 
make clean
make
