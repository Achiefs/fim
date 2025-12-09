use super::*;
use tokio_test::block_on;
use std::fs;

// ------------------------------------------------------------------------

fn remove_test_file(filename: &str) {
    fs::remove_file(filename).unwrap()
}

fn create_empty_event() -> AuditEvent {
    AuditEvent {
        id: String::from(""),
        timestamp: String::from(""),
        hostname: String::from(""),
        node: String::from(""),
        version: String::from(""),
        path: String::from(""),
        file: String::from(""),
        size: 0,
        labels: Vec::new(),
        operation: String::from(""),
        checksum: String::from(""),
        fpid: 0,
        system: String::from(""),
        command: String::from(""),
        ogid: String::from(""),
        rdev: String::from(""),
        proctitle: String::from(""),
        cap_fver: String::from(""),
        inode: String::from(""),
		cap_fp: String::from(""),
        cap_fe: String::from(""),
		item: String::from(""),
        cap_fi: String::from(""),
		dev: String::from(""),
        mode: String::from(""),
		cap_frootid: String::from(""),
        ouid: String::from(""),
		paths: Vec::new(),
        cwd: String::from(""),
		syscall: String::from(""),
        ppid: String::from(""),
		comm: String::from(""),
        fsuid: String::from(""),
		pid: String::from(""),
        a0: String::from(""),
		a1: String::from(""),
        a2: String::from(""),
		a3: String::from(""),
        arch: String::from(""),
		auid: String::from(""),
        items: String::from(""),
		gid: String::from(""),
        euid: String::from(""),
		sgid: String::from(""),
        uid: String::from(""),
		tty: String::from(""),
        success: String::from(""),
		exit: String::from(""),
        ses: String::from(""),
		key: String::from(""),
        suid: String::from(""),
		egid: String::from(""),
        fsgid: String::from(""),
		exe: String::from(""),
        source: String::from("")
    }
}

fn create_test_event() -> AuditEvent {
    AuditEvent {
        id: String::from("ID"),
		timestamp: String::from("TIMESTAMP"),
        hostname: String::from("HOSTNAME"),
		node: String::from("NODE"),
        version: String::from("VERSION"),
		path: String::from("PATH"),
        file: String::from("FILE"),
		size: 0,
		labels: Vec::new(),
        operation: String::from("OPERATION"),
		checksum: String::from("CHECKSUM"),
        fpid: 0,
        system: String::from("SYSTEM"),
		command: String::from("COMMAND"),
        ogid: String::from("OGID"),
		rdev: String::from("RDEV"),
        proctitle: String::from("PROCTITLE"),
		cap_fver: String::from("CAP_FVER"),
        inode: String::from("INODE"),
		cap_fp: String::from("CAP_FP"),
        cap_fe: String::from("CAP_FE"),
		item: String::from("ITEM"),
        cap_fi: String::from("CAP_FI"),
		dev: String::from("DEV"),
        mode: String::from("MODE"),
		cap_frootid: String::from("CAP_FROOTID"),
        ouid: String::from("OUID"),
		paths: Vec::new(),
        cwd: String::from("CWD"),
		syscall: String::from("SYSCALL"),
        ppid: String::from("PPID"),
		comm: String::from("COMM"),
        fsuid: String::from("FSUID"),
		pid: String::from("PID"),
        a0: String::from("A0"),
		a1: String::from("A1"),
        a2: String::from("A2"),
		a3: String::from("A3"),
        arch: String::from("ARCH"),
		auid: String::from("AUID"),
        items: String::from("ITEMS"),
		gid: String::from("GID"),
        euid: String::from("EUID"),
		sgid: String::from("SGID"),
        uid: String::from("UID"),
		tty: String::from("TTY"),
        success: String::from("SUCCESS"),
		exit: String::from("EXIT"),
        ses: String::from("SES"),
		key: String::from("KEY"),
        suid: String::from("SUID"),
		egid: String::from("EGID"),
        fsgid: String::from("FSGID"),
		exe: String::from("EXE"),
        source: String::from("SOURCE")
    }
}

// ------------------------------------------------------------------------

#[ignore] // Just for GH runner error (Passed on local)
#[test]
fn test_from() {
    if utils::get_os() == "linux" {
        let cfg = Config::new(&utils::get_os(),
            Some("test/unit/config/linux/audit_from_test.yml"));
        let syscall = HashMap::<String, String>::from([
            (String::from("syscall"), String::from("syscall")),
            (String::from("ppid"), String::from("ppid")),
            (String::from("comm"), String::from("comm")),
            (String::from("fsuid"), String::from("fsuid")),
            (String::from("pid"), String::from("pid")),
            (String::from("a0"), String::from("a0")),
            (String::from("a1"), String::from("a1")),
            (String::from("a2"), String::from("a2")),
            (String::from("a3"), String::from("a3")),
            (String::from("arch"), String::from("arch")),
            (String::from("auid"), String::from("auid")),
            (String::from("items"), String::from("items")),
            (String::from("gid"), String::from("gid")),
            (String::from("euid"), String::from("euid")),
            (String::from("sgid"), String::from("sgid")),
            (String::from("uid"), String::from("uid")),
            (String::from("tty"), String::from("tty")),
            (String::from("success"), String::from("success")),
            (String::from("exit"), String::from("exit")),
            (String::from("ses"), String::from("ses")),
            (String::from("key"), String::from("key")),
            (String::from("suid"), String::from("suid")),
            (String::from("egid"), String::from("egid")),
            (String::from("fsgid"), String::from("fsgid")),
            (String::from("exe"), String::from("exe"))
        ]);

        let cwd = HashMap::<String, String>::from([
            (String::from("cwd"), String::from("cwd"))
        ]);

        /*let parent = HashMap::<String, String>::from([
            (String::from("name"), String::from("/tmp"))
        ]);*/

        let paths = Vec::from([
            HashMap::<String, String>::from([
                (String::from("name"), String::from("/etc")),
                (String::from("nametype"), String::from("PARENT"))
            ]),
            HashMap::<String, String>::from([
                (String::from("nametype"), String::from("nametype")),
                (String::from("name"), String::from("/tmp/test.txt")),
                (String::from("ogid"), String::from("ogid")),
                (String::from("rdev"), String::from("rdev")),
                (String::from("cap_fver"), String::from("cap_fver")),
                (String::from("inode"), String::from("inode")),
                (String::from("cap_fp"), String::from("cap_fp")),
                (String::from("cap_fe"), String::from("cap_fe")),
                (String::from("item"), String::from("item")),
                (String::from("cap_fi"), String::from("cap_fi")),
                (String::from("dev"), String::from("dev")),
                (String::from("mode"), String::from("mode")),
                (String::from("cap_frootid"), String::from("cap_frootid")),
                (String::from("ouid"), String::from("ouid")),

            ])
        ]);

        /*let path = HashMap::<String, String>::from([
            (String::from("nametype"), String::from("nametype")),
            (String::from("name"), String::from("name")),
            (String::from("ogid"), String::from("ogid")),
            (String::from("rdev"), String::from("rdev")),
            (String::from("cap_fver"), String::from("cap_fver")),
            (String::from("inode"), String::from("inode")),
            (String::from("cap_fp"), String::from("cap_fp")),
            (String::from("cap_fe"), String::from("cap_fe")),
            (String::from("item"), String::from("item")),
            (String::from("cap_fi"), String::from("cap_fi")),
            (String::from("dev"), String::from("dev")),
            (String::from("mode"), String::from("mode")),
            (String::from("cap_frootid"), String::from("cap_frootid")),
            (String::from("ouid"), String::from("ouid")),
        ]);*/

        let proctitle = HashMap::<String, String>::from([
            (String::from("proctitle"), String::from("736564002D6900737C68656C6C6F7C4849217C670066696C6531302E747874")),
            (String::from("msg"), String::from("audit(1659026449.689:6434)"))
        ]);

        let event = AuditEvent::from(syscall.clone(), cwd.clone(), proctitle, paths.clone(), cfg.clone()).get_audit_event();
        assert_eq!(String::from("1659026449689"), event.timestamp);
        assert_eq!(utils::get_hostname(), event.hostname);
        assert_eq!(String::from("FIM"), event.node);
        assert_eq!(String::from(config::VERSION), event.version);
        assert_eq!(String::from("/tmp"), event.path);
        assert_eq!(String::from("test.txt"), event.file);
        assert_eq!(0, event.size);
        //assert_eq!(..., event.labels);
        //assert_eq!(..., event.parent);
        assert_eq!(String::from("nametype"), event.operation);
        assert_eq!(String::from("UNKNOWN"), event.checksum);
        assert_eq!(utils::get_pid(), event.fpid);
        assert_eq!(utils::get_os(), event.system);
        assert_eq!(String::from("sed -i s|hello|HI!|g file10.txt"), event.command);
        assert_eq!(String::from("ogid"), event.ogid);
        assert_eq!(String::from("rdev"), event.rdev);
        assert_eq!(String::from("736564002D6900737C68656C6C6F7C4849217C670066696C6531302E747874"), event.proctitle);
        assert_eq!(String::from("cap_fver"), event.cap_fver);
        assert_eq!(String::from("inode"), event.inode);
        assert_eq!(String::from("cap_fp"), event.cap_fp);
        assert_eq!(String::from("cap_fe"), event.cap_fe);
        assert_eq!(String::from("item"), event.item);
        assert_eq!(String::from("cap_fi"), event.cap_fi);
        assert_eq!(String::from("dev"), event.dev);
        assert_eq!(String::from("mode"), event.mode);
        assert_eq!(String::from("ouid"), event.ouid);
        assert_eq!(String::from("cwd"), event.cwd);
        assert_eq!(String::from("syscall"), event.syscall);
        assert_eq!(String::from("ppid"), event.ppid);
        assert_eq!(String::from("comm"), event.comm);
        assert_eq!(String::from("fsuid"), event.fsuid);
        assert_eq!(String::from("pid"), event.pid);
        assert_eq!(String::from("a0"), event.a0);
        assert_eq!(String::from("a1"), event.a1);
        assert_eq!(String::from("a2"), event.a2);
        assert_eq!(String::from("a3"), event.a3);
        assert_eq!(String::from("arch"), event.arch);
        assert_eq!(String::from("auid"), event.auid);
        assert_eq!(String::from("items"), event.items);
        assert_eq!(String::from("gid"), event.gid);
        assert_eq!(String::from("euid"), event.euid);
        assert_eq!(String::from("sgid"), event.sgid);
        assert_eq!(String::from("uid"), event.uid);
        assert_eq!(String::from("tty"), event.tty);
        assert_eq!(String::from("success"), event.success);
        assert_eq!(String::from("exit"), event.exit);
        assert_eq!(String::from("ses"), event.ses);
        assert_eq!(String::from("key"), event.key);
        assert_eq!(String::from("suid"), event.suid);
        assert_eq!(String::from("egid"), event.egid);
        assert_eq!(String::from("fsgid"), event.fsgid);
        assert_eq!(String::from("exe"), event.exe);
        assert_eq!(String::from("audit"), event.source);

        let proctitle = HashMap::<String, String>::from([
            (String::from("proctitle"), String::from("bash")),
            (String::from("msg"), String::from("audit(1659026449.689:6434)"))
        ]);
        let event = AuditEvent::from(syscall, cwd, proctitle, paths.clone(), cfg.clone()).get_audit_event();
        assert_eq!(String::from("bash"), event.proctitle);

    }
}

// ------------------------------------------------------------------------

#[test]
fn test_clone() {
    let event = create_test_event();
    let cloned = event.clone();
    assert_eq!(event.id, cloned.id);
    assert_eq!(event.timestamp, cloned.timestamp);
    assert_eq!(event.hostname, cloned.hostname);
    assert_eq!(event.node, cloned.node);
    assert_eq!(event.version, cloned.version);
    assert_eq!(event.path, cloned.path);
    assert_eq!(event.file, cloned.file);
    assert_eq!(event.size, cloned.size);
    assert_eq!(event.labels, cloned.labels);
    assert_eq!(event.operation, cloned.operation);
    assert_eq!(event.checksum, cloned.checksum);
    assert_eq!(event.fpid, cloned.fpid);
    assert_eq!(event.system, cloned.system);
    assert_eq!(event.command, cloned.command);
    assert_eq!(event.ogid, cloned.ogid);
    assert_eq!(event.rdev, cloned.rdev);
    assert_eq!(event.proctitle, cloned.proctitle);
    assert_eq!(event.cap_fver, cloned.cap_fver);
    assert_eq!(event.inode, cloned.inode);
    assert_eq!(event.cap_fp, cloned.cap_fp);
    assert_eq!(event.cap_fe, cloned.cap_fe);
    assert_eq!(event.item, cloned.item);
    assert_eq!(event.cap_fi, cloned.cap_fi);
    assert_eq!(event.dev, cloned.dev);
    assert_eq!(event.mode, cloned.mode);
    assert_eq!(event.cap_frootid, cloned.cap_frootid);
    assert_eq!(event.ouid, cloned.ouid);
    assert_eq!(event.paths, cloned.paths);
    //assert_eq!(event.parent, cloned.parent);
    assert_eq!(event.cwd, cloned.cwd);
    assert_eq!(event.syscall, cloned.syscall);
    assert_eq!(event.ppid, cloned.ppid);
    assert_eq!(event.comm, cloned.comm);
    assert_eq!(event.fsuid, cloned.fsuid);
    assert_eq!(event.pid, cloned.pid);
    assert_eq!(event.a0, cloned.a0);
    assert_eq!(event.a1, cloned.a1);
    assert_eq!(event.a2, cloned.a2);
    assert_eq!(event.a3, cloned.a3);
    assert_eq!(event.arch, cloned.arch);
    assert_eq!(event.auid, cloned.auid);
    assert_eq!(event.items, cloned.items);
    assert_eq!(event.gid, cloned.gid);
    assert_eq!(event.euid, cloned.euid);
    assert_eq!(event.sgid, cloned.sgid);
    assert_eq!(event.uid, cloned.uid);
    assert_eq!(event.tty, cloned.tty);
    assert_eq!(event.success, cloned.success);
    assert_eq!(event.exit, cloned.exit);
    assert_eq!(event.ses, cloned.ses);
    assert_eq!(event.key, cloned.key);
    assert_eq!(event.suid, cloned.suid);
    assert_eq!(event.egid, cloned.egid);
    assert_eq!(event.fsgid, cloned.fsgid);
    assert_eq!(event.exe, cloned.exe);
    assert_eq!(event.source, cloned.source);
}

// ------------------------------------------------------------------------

#[test]
fn test_is_empty() {
    let empty = create_empty_event();
    let event = create_test_event();
    assert_eq!(empty.is_empty(), true);
    assert_eq!(event.is_empty(), false);
}

// ------------------------------------------------------------------------

#[test]
fn test_to_json() {
    let json = create_test_event().to_json();
    let string = String::from("{\
        \"id\":\"ID\",\
        \"timestamp\":\"TIMESTAMP\",\
        \"hostname\":\"HOSTNAME\",\
        \"node\":\"NODE\",\
        \"version\":\"VERSION\",\
        \"path\":\"PATH\",\
        \"file\":\"FILE\",\
        \"size\":0,\
        \"labels\":[],\
        \"operation\":\"OPERATION\",\
        \"checksum\":\"CHECKSUM\",\
        \"fpid\":0,\
        \"system\":\"SYSTEM\",\
        \"command\":\"COMMAND\",\
        \"ogid\":\"OGID\",\
        \"rdev\":\"RDEV\",\
        \"proctitle\":\"PROCTITLE\",\
        \"cap_fver\":\"CAP_FVER\",\
        \"inode\":\"INODE\",\
        \"cap_fp\":\"CAP_FP\",\
        \"cap_fe\":\"CAP_FE\",\
        \"item\":\"ITEM\",\
        \"cap_fi\":\"CAP_FI\",\
        \"dev\":\"DEV\",\
        \"mode\":\"MODE\",\
        \"cap_frootid\":\"CAP_FROOTID\",\
        \"ouid\":\"OUID\",\
        \"paths\":[],\
        \"cwd\":\"CWD\",\
        \"syscall\":\"SYSCALL\",\
        \"ppid\":\"PPID\",\
        \"comm\":\"COMM\",\
        \"fsuid\":\"FSUID\",\
        \"pid\":\"PID\",\
        \"a0\":\"A0\",\
        \"a1\":\"A1\",\
        \"a2\":\"A2\",\
        \"a3\":\"A3\",\
        \"arch\":\"ARCH\",\
        \"auid\":\"AUID\",\
        \"items\":\"ITEMS\",\
        \"gid\":\"GID\",\
        \"euid\":\"EUID\",\
        \"sgid\":\"SGID\",\
        \"uid\":\"UID\",\
        \"tty\":\"TTY\",\
        \"success\":\"SUCCESS\",\
        \"exit\":\"EXIT\",\
        \"ses\":\"SES\",\
        \"key\":\"KEY\",\
        \"suid\":\"SUID\",\
        \"egid\":\"EGID\",\
        \"fsgid\":\"FSGID\",\
        \"exe\":\"EXE\",\
        \"source\":\"SOURCE\"\
    }");
    assert_eq!(json, string);
}

// ------------------------------------------------------------------------

#[test]
fn test_log() {
    let cfg = Config::new(&utils::get_os(), Some("test/unit/config/common/test_log_auditevent.yml"));
    let filename = "test_auditevent.json";
    let event = create_test_event();
    event.log(cfg.clone());

    let expected = "{\
        \"id\":\"ID\",\
        \"timestamp\":\"TIMESTAMP\",\
        \"hostname\":\"HOSTNAME\",\
        \"node\":\"NODE\",\
        \"version\":\"VERSION\",\
        \"path\":\"PATH\",\
        \"file\":\"FILE\",\
        \"size\":0,\
        \"labels\":[],\
        \"operation\":\"OPERATION\",\
        \"checksum\":\"CHECKSUM\",\
        \"fpid\":0,\
        \"system\":\"SYSTEM\",\
        \"command\":\"COMMAND\",\
        \"ogid\":\"OGID\",\
        \"rdev\":\"RDEV\",\
        \"proctitle\":\"PROCTITLE\",\
        \"cap_fver\":\"CAP_FVER\",\
        \"inode\":\"INODE\",\
        \"cap_fp\":\"CAP_FP\",\
        \"cap_fe\":\"CAP_FE\",\
        \"item\":\"ITEM\",\
        \"cap_fi\":\"CAP_FI\",\
        \"dev\":\"DEV\",\
        \"mode\":\"MODE\",\
        \"cap_frootid\":\"CAP_FROOTID\",\
        \"ouid\":\"OUID\",\
        \"paths\":[],\
        \"cwd\":\"CWD\",\
        \"syscall\":\"SYSCALL\",\
        \"ppid\":\"PPID\",\
        \"comm\":\"COMM\",\
        \"fsuid\":\"FSUID\",\
        \"pid\":\"PID\",\
        \"a0\":\"A0\",\
        \"a1\":\"A1\",\
        \"a2\":\"A2\",\
        \"a3\":\"A3\",\
        \"arch\":\"ARCH\",\
        \"auid\":\"AUID\",\
        \"items\":\"ITEMS\",\
        \"gid\":\"GID\",\
        \"euid\":\"EUID\",\
        \"sgid\":\"SGID\",\
        \"uid\":\"UID\",\
        \"tty\":\"TTY\",\
        \"success\":\"SUCCESS\",\
        \"exit\":\"EXIT\",\
        \"ses\":\"SES\",\
        \"key\":\"KEY\",\
        \"suid\":\"SUID\",\
        \"egid\":\"EGID\",\
        \"fsgid\":\"FSGID\",\
        \"exe\":\"EXE\",\
        \"source\":\"SOURCE\"\
    }\n";

    let log = utils::read_file(filename);
    assert_eq!(log, expected);

    remove_test_file(filename);
}

// ------------------------------------------------------------------------

#[test]
fn test_send() {
    let event = create_test_event();
    let cfg = Config::new(&utils::get_os(), None);
    block_on( event.send(cfg) );
}

// ------------------------------------------------------------------------

#[test]
fn test_send_splunk() {
    let event = create_test_event();
    let cfg = Config::new(&utils::get_os(), Some("test/unit/config/common/test_send_splunk.yml"));
    block_on( event.send(cfg) );
}

// ------------------------------------------------------------------------

#[test]
fn test_process() {
    let cfg = Config::new(&utils::get_os(), None);
    let ruleset = Ruleset::new(&utils::get_os(), None);  
    let event = create_test_event();

    block_on(event.process(cfg.clone(), ruleset.clone()));
    block_on(event.process(cfg.clone(), ruleset.clone()));
    block_on(event.process(cfg.clone(), ruleset.clone()));
}