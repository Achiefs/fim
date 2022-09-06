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
class TestAuditd:
    def test_file_create():
        c = open(test_file, 'w')
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"
        c.close()

    def test_file_write():
        w = open(test_file, 'w')
        w.write("This is a test")
        w.close()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "257"

    def test_file_chmod():
        os.chmod(test_file, 0o777)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['comm'] == "chmod"
        assert data['syscall'] == "268"

    def test_file_chown():
        os.chmod(test_file, 0, 0)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['comm'] == "chown"
        assert data['syscall'] == "260"

    def test_file_remove():
        os.remove(test_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"

    def test_file_rename():
        os.rename(test_file, test_file + '.rmv')
        os.rename(test_file + '.rmv', test_file)
        data = json.loads(get_last_event())
        assert data['comm'] == "mv"
        assert data['syscall'] == "316"