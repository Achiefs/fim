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
    time.sleep(0.2)
    with open(events_json, 'r') as f:
        for line in f: pass
        last_line = line.strip()
    return last_line

def get_event(reversed_index):
    time.sleep(0.2)
    with open(events_json, 'r') as f:
        line = f.readlines()[-reversed_index]
    return line

# -----------------------------------------------------------------------------

def remove(item):
    if os.path.exists(item):
        try:
            subprocess.Popen(["rm", "-rf", item],
                stdout=subprocess.PIPE).communicate()
        except:
            print("Cannot remove item -> {}".format(item))


# -----------------------------------------------------------------------------

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
class TestAuditd:

    def setup_method(self):
        with open(events_json, 'w') as f:
            f.truncate(0)
        time.sleep(0.2)

    def teardown_method(self):
        time.sleep(0.2)
        remove(test_link)
        remove(test_file)
        remove(test_folder)

    # -------------------------------------------------------------------------

    def test_file_create(self):
        open(test_file, 'w').close()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"

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

    def test_file_bash_chmod(self):
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

    def test_file_bash_chown(self):
        open(test_file, 'w').close()
        subprocess.Popen(["chown", "root", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "260"

    # -------------------------------------------------------------------------

    def test_file_symlink(self):
        open(test_file, 'w').close()
        os.symlink(test_file, test_link)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "88"

    # -------------------------------------------------------------------------

    def test_file_bash_symlink(self):
        open(test_file, 'w').close()
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
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "86"

    # -------------------------------------------------------------------------

    def test_file_bash_hardlink(self):
        open(test_file, 'w').close()
        subprocess.Popen(["ln", test_file, test_link],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
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
        filename = test_file + '.swp'
        open(filename, 'w').close()
        size = os.path.getsize(events_json)
        remove(filename)
        assert size == 0

    # -------------------------------------------------------------------------

    def test_false_move(self):
        subprocess.Popen(["mv", test_file, test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['syscall'] == "316"

    # -------------------------------------------------------------------------

    def test_move_external(self):
        filename = test_file + '2'
        moved_file = "/tmp/test_file2"
        open(filename, 'w').close()
        os.rename(filename, moved_file)
        data = json.loads(get_last_event())
        remove(moved_file)
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_move_bash_external(self):
        filename = test_file + '2'
        open(filename, 'w').close()
        subprocess.Popen(["mv", filename, "/tmp/test_file2"],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        remove("/tmp/test_file2")
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "316"

    # -------------------------------------------------------------------------

    def test_move_internal(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        os.rename(filename, test_file)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_move_bash_internal(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        subprocess.Popen(["mv", filename, test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "316"

    # -------------------------------------------------------------------------

    def test_bash_echo(self):
        subprocess.Popen("echo 'Test string' > {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"

    # -------------------------------------------------------------------------

    def test_bash_sed(self):
        subprocess.Popen("echo 'Test string' > {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
        subprocess.Popen(["sed", "-i", "s|Test|Hello|g", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_event(-1))
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"

        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_bash_touch(self):
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

    def test_bash_mkdir(self):
        subprocess.Popen(["mkdir", "-p", test_folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "83"

    # -------------------------------------------------------------------------

    def test_rmdir(self):
        os.mkdir(test_folder)
        os.rmdir(test_folder)
        data = json.loads(get_last_event())
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "84"

    # -------------------------------------------------------------------------

    def test_bash_rmdir(self):
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
        remove(folder)
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_move_folder_bash_external(self):
        folder = "/tmp/test_folder"
        os.mkdir(test_folder)
        subprocess.Popen(["mv", test_folder, folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        remove(folder)
        assert data['operation'] == "DELETE"
        assert data['syscall'] == "316"

    # -------------------------------------------------------------------------

    def test_move_folder_internal(self):
        folder = "/tmp/test_folder"
        os.mkdir(folder)
        os.rename(folder, test_folder)
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "82"

    # -------------------------------------------------------------------------

    def test_move_folder_bash_internal(self):
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

    def test_folder_bash_chown(self):
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

    def test_folder_bash_chmod(self):
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

    def test_bash_mknod(self):
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

    def test_bash_mkfifo(self):
        subprocess.Popen(["mkfifo", test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "133"

    # -------------------------------------------------------------------------

    def test_bash_copy(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        subprocess.Popen(["cp", filename, test_file],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        remove(filename)
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "257"

    # -------------------------------------------------------------------------

    def test_folder_bash_copy(self):
        folder = "/tmp/test_folder"
        os.mkdir(folder)
        subprocess.Popen(["cp", "-r", folder, test_folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        remove(folder)
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "83"

    # -------------------------------------------------------------------------

    def test_folder_symlink(self):
        folder = test_folder + ".link"
        os.mkdir(test_folder)
        os.symlink(test_folder, folder)
        data = json.loads(get_last_event())
        remove(folder)
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "88"

    # -------------------------------------------------------------------------

    def test_folder_bash_symlink(self):
        folder = test_folder + ".link"
        os.mkdir(test_folder)
        subprocess.Popen(["ln", "-s", test_folder, folder],
            stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        remove(folder)
        assert data['operation'] == "CREATE"
        assert data['syscall'] == "266"

    # -------------------------------------------------------------------------

    def test_bash_append(self):
        open(test_file, 'w').close()
        subprocess.Popen("echo 'Test string2' >> {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
        data = json.loads(get_last_event())
        assert data['operation'] == "NORMAL"
        assert data['syscall'] == "257"
