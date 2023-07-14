#!/bin/bash
dpkg --add-architecture i386
apt update
apt install p7zip-full git ca-certificates build-essential g++-multilib -y --no-install-recommends
# lib32stdc++-10-dev lib32z1-dev libc6-dev-i386 linux-libc-dev:i386
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
	7za a -r sm-neocurl.zip scripting/ plugins/ extensions/

	rm -rf ./sm-1.11
	rm -rf ./mm-1.11
popd

chmod 777 * -Rfv
