# Copyright (C) 2022, Achiefs.

import pytest
import json
import os
import time
import platform

events_json = '/var/lib/fim/events.json'
test_file = '/tmp/test/test_file'
system = platform.system()

def get_last_event():
    time.sleep(0.1)
    with open(events_json) as f:
        for line in f: pass
        last_line = line.strip()
    return last_line

# -----------------------------------------------------------------------------

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
def test_file_create():
    c = open(test_file, 'w')
    data = json.loads(get_last_event())
    assert data['operation'] == "CREATE"
    c.close()

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
def test_file_write():
    w = open(test_file, 'w')
    w.write("This is a test")
    data = json.loads(get_last_event())
    assert data['operation'] == "NORMAL"
    w.close()

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
def test_file_remove():
    os.remove(test_file)
    data = json.loads(get_last_event())
    assert data['operation'] == "DELETE"

"""
@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
def test_file_close():
    cl = open(test_file, 'w')
    cl.close()
    data = json.loads(get_last_event())
    assert data['operation'] == "CLOSE_WRITE"

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
def test_file_rename():
    os.rename(test_file, test_file + '.rmv')
    os.rename(test_file + '.rmv', test_file)
    data = json.loads(get_last_event())
    assert data['operation'] == "RENAME"

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
def test_file_chmod():
    os.chmod(test_file, 0o777)
    data = json.loads(get_last_event())
    assert data['operation'] == "CHMOD"

"""