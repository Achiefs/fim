#!/bin/bash

ref=$1

mkdir -p /tmp/output
mkdir -p /tmp/repo
cd /tmp/repo
git clone https://github.com/Achiefs/fim.git -b ${ref} --depth=1
cd fim/pkg/deb
./builder.sh
cp filemonitor_*.deb /tmp/output/
chown 1000:1000 /tmp/output/*
