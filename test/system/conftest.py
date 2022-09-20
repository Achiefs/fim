import pytest
import os
import shutil
import subprocess

events_json = '/var/lib/fim/events.json'
audit_log = '/var/log/audit/audit.log'


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()


    if rep.when == "call" and rep.failed:
        test_name = rep.nodeid.split("::")[2]
        try:
            os.mkdir(test_name)
        except FileExistsError:
            pass
        shutil.copyfile(events_json, test_name+"/events.json")
        proc = subprocess.Popen(['tail', '-n', "20", audit_log], stdout=subprocess.PIPE)
        (out, err) = proc.communicate()
        f = open(test_name + "/audit.log", 'w')
        f.write(out.decode('UTF-8'))
        f.close()
