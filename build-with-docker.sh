#!/bin/sh
#
docker run -it --rm  -v ${PWD}:/mnt -u 1000:1000 openjdk /bin/bash -c "cd /mnt && ./build.sh"
