# Copyright (C) 2022, Achiefs.

import pytest
import json
import os
import time
import platform
import subprocess

events_json = '/var/lib/fim/events.json'
test_file = '/tmp/test/test_file'
test_folder = '/tmp/test/test_folder'
test_link = test_file + '.link'
system = platform.system()

def get_last_event():
    time.sleep(0.4)
    with open(events_json) as f:
        for line in f: pass
        last_line = line.strip()
    return last_line

# -----------------------------------------------------------------------------

def remove(item):
    try:
        subprocess.Popen(["rm", "-rf", item],
            stdout=subprocess.PIPE).communicate()
    except:
        print("Cannot remove item -> {}".format(item))


# -----------------------------------------------------------------------------

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
class TestAuditd:

    def setup_method(self, method):
        time.sleep(0.1)

    def teardown_method(self, method):
        time.sleep(0.1)
        remove(test_file)
        remove(test_folder)
        remove(test_link)


    def test_file_create(self):
        c = open(test_file, 'w')
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"
        c.close()

    # -------------------------------------------------------------------------

    def test_file_write(self):
        open(test_file, 'w').close()
        w = open(test_file, 'w')
        w.write("This is a test")
        w.close()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "257"

    # -------------------------------------------------------------------------

    def test_file_chmod(self):
        open(test_file, 'w').close()
        os.chmod(test_file, 0o777)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "90"

    # -------------------------------------------------------------------------

    def test_file_chmod_bash(self):
        open(test_file, 'w').close()
        subprocess.Popen(["chmod", "+x", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "268"

    # -------------------------------------------------------------------------

    def test_file_chown(self):
        open(test_file, 'w').close()
        os.chown(test_file, 0, 0)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "92"

    # -------------------------------------------------------------------------

    def test_file_chown_bash(self):
        open(test_file, 'w').close()
        subprocess.Popen(["chown", "root", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "260"

    # -------------------------------------------------------------------------

    def test_file_symlink(self):
        os.symlink(test_file, test_link)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "88"

    # -------------------------------------------------------------------------

    def test_file_symlink_bash(self):
        subprocess.Popen(["ln", "-s", test_file, test_link],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "266"

    # -------------------------------------------------------------------------

    def test_file_hardlink(self):
        open(test_file, 'w').close()
        os.link(test_file, test_link)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "86"

    # -------------------------------------------------------------------------

    def test_file_hardlink_bash(self):
        open(test_file, 'w').close()
        subprocess.Popen(["ln", test_file, test_link],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "265"

    # -------------------------------------------------------------------------

    def test_file_rename(self):
        open(test_file, 'w').close()
        os.rename(test_file, test_file + '.rmv')
        os.rename(test_file + '.rmv', test_file)
        data = json.loads(get_last_event())
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_file_remove(self):
        open(test_file, 'w').close()
        os.remove(test_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "87"

    # -------------------------------------------------------------------------

    def test_ignore(self):
        data1 = json.loads(get_last_event())
        filename = test_file + '.swp'
        c = open(filename, 'w').close()
        data2 = json.loads(get_last_event())
        assert data1 == data2
        time.sleep(0.05)
        remove(filename)

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
        time.sleep(0.05)
        remove("/tmp/test_file2")

    # -------------------------------------------------------------------------

    def test_move_external_bash(self):
        filename = test_file + '2'
        open(filename, 'w').close()
        subprocess.Popen(["mv", filename, "/tmp/test_file2"],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "316"
        time.sleep(0.05)
        remove("/tmp/test_file2")

    # -------------------------------------------------------------------------

    def test_move_internal(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        os.rename(filename, test_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_move_internal_bash(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        subprocess.Popen(["mv", filename, test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "316"

    # -------------------------------------------------------------------------

    def test_echo_bash(self):
        subprocess.Popen("echo 'Test string' > {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"

    # -------------------------------------------------------------------------

    def test_sed_bash(self):
        subprocess.Popen("echo 'Test string' > {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
        subprocess.Popen(["sed", "-i", "s|Test|Hello|g", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"

    # -------------------------------------------------------------------------

    def test_touch_bash(self):
        subprocess.Popen(["touch", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"

    # -------------------------------------------------------------------------

    def test_mkdir(self):
        os.mkdir(test_folder)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "83"

    # -------------------------------------------------------------------------

    def test_mkdir_bash(self):
        subprocess.Popen(["mkdir", "-p", test_folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "83"

    # -------------------------------------------------------------------------

    def test_rmdir(self):
        os.mkdir(test_folder)
        os.rmdir(test_folder)
        time.sleep(0.05)
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "84"

    # -------------------------------------------------------------------------

    def test_rmdir_bash(self):
        os.mkdir(test_folder)
        subprocess.Popen(["rmdir", test_folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "84"

    # -------------------------------------------------------------------------

    def test_move_folder_external(self):
        folder = "/tmp/test_folder"
        os.mkdir(test_folder)
        os.rename(test_folder, folder)
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "82"
        time.sleep(0.05)
        remove(folder)

    # -------------------------------------------------------------------------

    def test_move_folder_external_bash(self):
        folder = "/tmp/test_folder"
        os.mkdir(test_folder)
        subprocess.Popen(["mv", test_folder, folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "316"
        time.sleep(0.05)
        remove(folder)

    # -------------------------------------------------------------------------

    def test_move_folder_internal(self):
        folder = "/tmp/test_folder"
        os.mkdir(folder)
        os.rename(folder, test_folder)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_move_folder_internal_bash(self):
        folder = "/tmp/test_folder"
        os.mkdir(folder)
        subprocess.Popen(["mv", folder, test_folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "316"

    # -------------------------------------------------------------------------

    def test_folder_chown(self):
        os.mkdir(test_folder)
        os.chown(test_folder, 0, 0)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "92"

    # -------------------------------------------------------------------------

    def test_folder_chown_bash(self):
        os.mkdir(test_folder)
        subprocess.Popen(["chown", "root", test_folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "260"

    # -------------------------------------------------------------------------

    def test_folder_chmod(self):
        os.mkdir(test_folder)
        os.chmod(test_folder, 0o777)
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "90"

    # -------------------------------------------------------------------------

    def test_folder_chmod_bash(self):
        os.mkdir(test_folder)
        subprocess.Popen(["chmod", "+x", test_folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "268"

    # -------------------------------------------------------------------------

    def test_mknod(self):
        os.mknod(test_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "133"

    # -------------------------------------------------------------------------

    def test_mknod_bash(self):
        subprocess.Popen(["mknod", test_file, "c", "240", "0"],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "133"

    # -------------------------------------------------------------------------

    def test_mkfifo(self):
        os.mkfifo(test_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "133"

    # -------------------------------------------------------------------------

    def test_mkfifo_bash(self):
        subprocess.Popen(["mkfifo", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "133"

### Remaining tests
# - Link from external folder
# - Link from internal to external folder
# - Nano/vi on File?
# - Hard/SymLink to dir
# - > and >> to a file
# - Cp to a file or dir
# - Something with eval
# - Something with exec