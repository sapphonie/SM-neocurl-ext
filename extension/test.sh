#!/bin/bash
FIX ME
if ( ! git clone https://github.com/alliedmodders/sourcemod --branch 1.11-dev sm-1.11 --recursive ); then
	pushd sm-1.11 || echo "COULDNT CD TO SM???"; exit 255
	echo "test"; pwd;
	git reset --hard;
	git fetch
	git reset --hard FETCH_HEAD
	git submodule foreach --recursive git reset --hard origin/HEAD
	pwd
	popd || echo "COULDNT POPD FROM $(pwd)???"; exit 255;
	fi;
fi
