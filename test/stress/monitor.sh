#!/bin/bash

echo DATE,TIMESTAMP,PID,%CPU,%MEM,RSS,VSZ,CMD
while true;
do
        PID="$(ps -C fim -o pid= | tr -d ' ')"
        sleep 1
        echo -n $(date)
        echo -n ",$(date +%s)"
        echo -n ",$PID"
        ps -p $PID -o %cpu,%mem,rss,vsz,cmd | tail -1 | tr -s ' ' | tr ' ' ','
done