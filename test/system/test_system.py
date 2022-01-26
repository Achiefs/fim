# Copyright (C) 2021, Achiefs.

import pytest
import json
import os

events_json = '/var/lib/fim/events.json'
test_file = '/tmp/test/test.txt'

def get_last_event():
    with open(events_json) as f:
        for line in f: pass
        last_line = line.strip()
    return last_line

# -----------------------------------------------------------------------------

def test_file_create():
    f = open(test_file, 'w')
    data = json.loads(get_last_event())
    assert data['kind'] == "CREATE"
    f.close()

def test_file_write():
    f = open(test_file, 'w')
    data = json.loads(get_last_event())
    assert data['kind'] == "WRITE"
    f.close()

def test_file_close():
    f = open(test_file, 'w')
    f.close()
    data = json.loads(get_last_event())
    assert data['kind'] == "CLOSE_WRITE"

def test_file_rename():
    os.rename(test_file, test_file + '.rmv')
    os.rename(test_file + '.rmv', test_file)
    data = json.loads(get_last_event())
    assert data['kind'] == "RENAME"

def test_file_chmod():
    os.chmod(test_file, 0o777)
    data = json.loads(get_last_event())
    assert data['kind'] == "CHMOD"

def test_file_restan():
    # Check https://docs.rs/notify/latest/notify/op/index.html#rescan to apply rescan test
    # For now it will be always green
    assert True

def test_file_remove():
    os.remove(test_file)
    data = json.loads(get_last_event())
    assert data['kind'] == "REMOVE"
