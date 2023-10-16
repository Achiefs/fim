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
release = platform.release()
delay = 0.1

def get_last_event():
    ctr = 0
    size = os.path.getsize(events_json)
    while size == 0 and ctr < 60:
        time.sleep(delay)
        size = os.path.getsize(events_json)
        ctr += 1
    with open(events_json, 'r') as f:
        for line in f: pass
        last_line = line.strip()
    return last_line

def get_event(syscall=None, operation=None):
    size_ctr = 0
    size = os.path.getsize(events_json)
    while size == 0 and size_ctr < 60:
        time.sleep(delay)
        size = os.path.getsize(events_json)
        size_ctr += 1

    if syscall != None:
        find_ctr = 0
        while find_ctr < 40:
            time.sleep(delay)
            with open(events_json, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    event = json.loads(line)
                    if event['syscall'] == syscall:
                        if operation != None:
                            if operation == event['operation']:
                                return event
                        else:
                            return event
            find_ctr += 1
    else:
        return get_last_event()


# -----------------------------------------------------------------------------

def remove(item):
    if os.path.exists(item):
        try:
            subprocess.run(["rm", "-rf", item])
        except:
            print("Cannot remove item -> {}".format(item))


# -----------------------------------------------------------------------------

@pytest.mark.skipif(system == "Windows", reason="Cannot run on Windows")
class TestAuditd:

    def setup_method(self):
        time.sleep(delay)
        f = open(events_json, 'w')
        f.truncate(0)
        f.close()

    def teardown_method(self):
        time.sleep(delay)
        remove(test_link)
        remove(test_file)
        remove(test_folder)

    # -------------------------------------------------------------------------

    def test_file_create(self):
        open(test_file, 'w').close()

        if "el7" in release:
            event = get_event("2", "CREATE")
        else:
            event = get_event("257", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_write(self):
        open(test_file, 'w').close()
        w = open(test_file, 'w')
        w.write("This is a test")
        w.close()
        
        if "el7" in release:
            event = get_event("2", "NORMAL")
        else:
            event = get_event("257", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_chmod(self):
        open(test_file, 'w').close()
        os.chmod(test_file, 0o777)
        event = get_event("90", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_bash_chmod(self):
        open(test_file, 'w').close()
        subprocess.run(["chmod", "+x", test_file])
        event = get_event("268", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_chown(self):
        open(test_file, 'w').close()
        os.chown(test_file, 0, 0)
        event = get_event("92", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_bash_chown(self):
        open(test_file, 'w').close()
        subprocess.run(["chown", "root", test_file])
        event = get_event("260", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_symlink(self):
        open(test_file, 'w').close()
        os.symlink(test_file, test_link)
        event = get_event("88", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_bash_symlink(self):
        open(test_file, 'w').close()
        subprocess.run(["ln", "-s", test_file, test_link])
        
        if "el7" in release:
            event = get_event("88", "CREATE")
        else:
            event = get_event("266", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_hardlink(self):
        open(test_file, 'w').close()
        os.link(test_file, test_link)
        event = get_event("86", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_bash_hardlink(self):
        open(test_file, 'w').close()
        subprocess.run(["ln", test_file, test_link])
        event = get_event("265", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_rename(self):
        open(test_file, 'w').close()
        os.rename(test_file, test_file + '.rmv')
        os.rename(test_file + '.rmv', test_file)
        event = get_event("82")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_file_remove(self):
        open(test_file, 'w').close()
        os.remove(test_file)
        event = get_event("87", "DELETE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_ignore(self):
        filename = test_file + '.swp'
        open(filename, 'w').close()
        size = os.path.getsize(events_json)
        remove(filename)
        assert size == 0

    # -------------------------------------------------------------------------

    def test_false_move(self):
        open(test_file, 'w').close()
        subprocess.run(["mv", test_file, test_file])
        
        if "el7" in release:
            event = get_event("2")
        else:
            event = get_event("316")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_external(self):
        filename = test_file + '2'
        moved_file = "/tmp/test_file2"
        open(filename, 'w').close()
        os.rename(filename, moved_file)
        remove(moved_file)

        event = get_event("82")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_bash_external(self):
        filename = test_file + '2'
        open(filename, 'w').close()
        subprocess.run(["mv", filename, "/tmp/test_file2"])
        remove("/tmp/test_file2")

        event = get_event("316")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_internal(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        os.rename(filename, test_file)
        event = get_event("82", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_bash_internal(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        subprocess.run(["mv", filename, test_file])
        event = get_event("316", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_echo(self):
        subprocess.Popen("echo 'Test string' > {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
                
        if "el7" in release:
            event = get_event("2", "CREATE")
        else:
            event = get_event("257", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_sed(self):
        subprocess.Popen("echo 'Test string' > {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
        subprocess.run(["sed", "-i", "s|Test|Hello|g", test_file])
        
        if "el7" in release:
            event = get_event("2", "CREATE")
        else:
            event = get_event("257", "CREATE")
        assert event is not None

        event = get_event("82", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_touch(self):
        subprocess.run(["touch", test_file])
        
        if "el7" in release:
            event = get_event("2", "CREATE")
        else:
            event = get_event("257", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_mkdir(self):
        os.mkdir(test_folder)
        event = get_event("83", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_mkdir(self):
        subprocess.run(["mkdir", "-p", test_folder])
        event = get_event("83", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_rmdir(self):
        os.mkdir(test_folder)
        os.rmdir(test_folder)
        event = get_event("84", "DELETE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_rmdir(self):
        os.mkdir(test_folder)
        subprocess.run(["rmdir", test_folder])
        event = get_event("84", "DELETE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_folder_external(self):
        folder = "/tmp/test_folder"
        os.mkdir(test_folder)
        os.rename(test_folder, folder)
        remove(folder)

        event = get_event("82")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_folder_bash_external(self):
        folder = "/tmp/test_folder"
        os.mkdir(test_folder)
        subprocess.run(["mv", test_folder, folder])
        remove(folder)

        event = get_event("316")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_folder_internal(self):
        folder = "/tmp/test_folder"
        os.mkdir(folder)
        os.rename(folder, test_folder)
        event = get_event("82", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_move_folder_bash_internal(self):
        folder = "/tmp/test_folder"
        os.mkdir(folder)
        subprocess.run(["mv", folder, test_folder])
        event = get_event("316", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_folder_chown(self):
        os.mkdir(test_folder)
        os.chown(test_folder, 0, 0)
        event = get_event("92", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_folder_bash_chown(self):
        os.mkdir(test_folder)
        subprocess.run(["chown", "root", test_folder])
        event = get_event("260", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_folder_chmod(self):
        os.mkdir(test_folder)
        os.chmod(test_folder, 0o777)
        event = get_event("90", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_folder_bash_chmod(self):
        os.mkdir(test_folder)
        subprocess.run(["chmod", "+x", test_folder])
        event = get_event("268", "NORMAL")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_mknod(self):
        os.mknod(test_file)
        event = get_event("133", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_mknod(self):
        subprocess.run(["mknod", test_file, "c", "240", "0"])
        event = get_event("133", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_mkfifo(self):
        os.mkfifo(test_file)
        event = get_event("133", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_mkfifo(self):
        subprocess.run(["mkfifo", test_file])
        event = get_event("133", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_bash_copy(self):
        filename = "/tmp/test_file"
        open(filename, 'w').close()
        subprocess.run(["cp", filename, test_file])
        remove(filename)
        
        if "el7" in release:
            event = get_event("2", "CREATE")
        else:
            event = get_event("257", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_folder_bash_copy(self):
        folder = "/tmp/test_folder"
        os.mkdir(folder)
        subprocess.run(["cp", "-r", folder, test_folder])
        remove(folder)

        event = get_event("83", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_folder_symlink(self):
        folder = test_folder + ".link"
        os.mkdir(test_folder)
        os.symlink(test_folder, folder)
        remove(folder)

        event = get_event("88", "CREATE")
        assert event is not None

    # -------------------------------------------------------------------------

    def test_folder_bash_symlink(self):
        folder = test_folder + ".link"
        os.mkdir(test_folder)
        subprocess.run(["ln", "-s", test_folder, folder])
        remove(folder)
        
        if "el7" in release:
            event = get_event("88", "CREATE")
        else:
            event = get_event("266", "CREATE")
        assert event is not None
        

    # -------------------------------------------------------------------------

    def test_bash_append(self):
        open(test_file, 'w').close()
        subprocess.Popen("echo 'Test string2' >> {}".format(test_file),
            shell=True, stdout=subprocess.PIPE).communicate()
        
        if "el7" in release:
            event = get_event("2", "NORMAL")
        else:
            event = get_event("257", "NORMAL")
        assert event is not None
