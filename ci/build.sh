#!/bin/bash

# we do this so that we can be agnostic about where we're invoked from
# meaning you can exec this script anywhere and it should work the same
thisiswhereiam=${BASH_SOURCE[0]}
# this should be /whatever/directory/structure/Open-Fortress-Source
script_folder=$( cd -- "$( dirname -- "${thisiswhereiam}" )" &> /dev/null && pwd )

# this should be /whatever/directory/structure/[sdkmod-source]/build
build_dir="build"

img="registry.gitlab.steamos.cloud/steamrt/sniper/sdk"
img="debian:11-slim"
echo ${thisiswhereiam}
echo ${script_folder}
docker run -it \
--mount type=bind,source=${script_folder}/../,target=/mnt/curl \
--user "$(id -u):$(id -g)" \
${img} \
bash #/mnt/curl/ci/_docker_script.sh



#
# debian:11-slim \
