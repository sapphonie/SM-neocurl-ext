#!/bin/bash

cd /mnt/curl/
git config --global --add safe.directory "*"
rm -rf build
mkdir build
mkdir build/extensions 	-p
mkdir build/scripting 	-p
mkdir build/plugins 	-p

pushd build
	rm -rf ./sm-1.11
	git clone https://github.com/alliedmodders/sourcemod --branch 1.11-dev sm-1.11 --recursive 
	rm -rf ./mm-1.11
	git clone https://github.com/alliedmodders/metamod-source --branch 1.11-dev mm-1.11 --recursive
popd

pushd extension
	make clean
	make
	mv Release/curl.ext.so ../build/extensions/ -v
	rm -rf Release
popd

cp pawn/* build/ -Rfv

# cleanup

pushd build
	rm -rf ./sm-1.11
	rm -rf ./mm-1.11
popd
