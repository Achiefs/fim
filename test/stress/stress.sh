#!/bin/bash

if ! [ -z "$1" ]; then
    TEST_DIR=$1
else
    TEST_DIR="/tmp/fim_test"
fi

###############################################################################

echo -n "Starting 1000 files stress test ... "
sleep 1
for i in {0..1000}; do echo "This is a test" > ${TEST_DIR}/file$i.txt; done
echo "Done."

echo -n "Cleaning test ... "
sleep 1
rm ${TEST_DIR}/*
echo "Done."

###############################################################################

echo -n "Starting 10000 files stress test ... "
sleep 1
for i in {0..10000}; do echo "This is a test" > ${TEST_DIR}/file$i.txt; done
echo "Done."

echo -n "Cleaning test ... "
sleep 1
rm ${TEST_DIR}/*
echo "Done."

###############################################################################

echo -n "Starting 100000 files stress test ... "
sleep 1
for i in {0..100000}; do echo "This is a test" > ${TEST_DIR}/file$i.txt; done
echo "Done."

echo -n "Cleaning test ... "
sleep 1
rm -r ${TEST_DIR}/
mkdir -p ${TEST_DIR}/
echo "Done."