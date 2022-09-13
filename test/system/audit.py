# Copyright (C) 2022, Achiefs.

import pytest
import json
import os
import time
import platform
import subprocess

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

    def test_file_create(self):
        c = open(test_file, 'w')
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"
        c.close()

    # -------------------------------------------------------------------------

    def test_file_write(self):
        w = open(test_file, 'w')
        w.write("This is a test")
        w.close()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "257"

    # -------------------------------------------------------------------------

    def test_file_chmod(self):
        os.chmod(test_file, 0o777)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "90"

    # -------------------------------------------------------------------------

    def test_file_chmod_bash(self):
        process = subprocess.Popen(["chmod", "+x", test_file], stdout=subprocess.PIPE)
        process.communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "268"

    # -------------------------------------------------------------------------

    def test_file_chown(self):
        os.chown(test_file, 0, 0)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "92"

    # -------------------------------------------------------------------------

    def test_file_chown_bash(self):
        subprocess.Popen(["chown", "root", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "260"

    # -------------------------------------------------------------------------

    def test_file_symlink(self):
        linked_file = test_file + '.link'
        os.symlink(test_file, linked_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "88"
        os.remove(linked_file)

    # -------------------------------------------------------------------------

    def test_file_symlink_bash(self):
        linked_file = test_file + '.link'
        subprocess.Popen(["ln", "-s", test_file, linked_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "266"
        os.remove(linked_file)

    # -------------------------------------------------------------------------

    def test_file_hardlink(self):
        linked_file = test_file + '.link'
        os.link(test_file, linked_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "86"
        os.remove(linked_file)

    # -------------------------------------------------------------------------

    def test_file_hardlink_bash(self):
        linked_file = test_file + '.link'
        subprocess.Popen(["ln", test_file, linked_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "265"
        os.remove(linked_file)

    # -------------------------------------------------------------------------

    def test_file_rename(self):
        os.rename(test_file, test_file + '.rmv')
        os.rename(test_file + '.rmv', test_file)
        data = json.loads(get_last_event())
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_file_remove(self):
        os.remove(test_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "87"

    # -------------------------------------------------------------------------

    def test_ignore(self):
        filename = test_file + '.swp'
        c = open(filename, 'w')
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "87"
        c.close()
        os.remove(filename)

    # -------------------------------------------------------------------------

    def test_false_move(self):
        subprocess.Popen(["mv", test_file, test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['syscall'] == "316"

    # -------------------------------------------------------------------------

    def test_move_external(self):
        filename = test_file + '2'
        open(filename, 'w').close()
        os.rename(filename, "/tmp/test_file2")
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "82"
        os.remove("/tmp/test_file2")

    # -------------------------------------------------------------------------

    def test_move_external_bash(self):
        filename = test_file + '2'
        open(filename, 'w').close()
        subprocess.Popen(["mv", filename, "/tmp/test_file2"],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "316"
        os.remove("/tmp/test_file2")

### Remaining tests
# - Move from external folder
# - Link from external folder
# - Link from internal to external folder
# - Echoing to a file (echo test > test_file)
# - Seding a file (sed -i test_file)
# - Nano/vi on File?
# - Touch to a file
# - Create dir
# - Remove dir
# - Move dir
# - Change owner of dir
# - Change permissions of dir
# - Hard/SymLink to dir
# - Rmdir command
# - > and >> to a file
# - Cp to a file or dir
# - Something with eval
# - Something with exec