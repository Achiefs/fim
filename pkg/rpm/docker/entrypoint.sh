#!/bin/bash

set -xe

ref=$1

mkdir -p /tmp/repo
cd /tmp/repo
git clone https://github.com/Achiefs/fim.git -b ${ref} --depth=1
cd fim/pkg/rpm
./builder.sh
cp fim-*.rpm /tmp/output/
chown 1000:1000 /tmp/output/fim-*.rpm
