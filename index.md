# FIM
FIM is a File Integrity Monitoring tool that tracks any event performed over your files.
It is capable of keeping historical data of your files. It checks the filesystem changes in the background.
FIM is the fastest alternative to other software like Ossec to perform file integrity monitoring.
It can be integrated with other security tools like Ossec or Wazuh.
The produced data can be ingested and analyzed with tools like ElasticSearch/OpenSearch.
Developed with Rust, the next generation of programming language.

## Features
- Filesystem monitor
- Identification of changes in content, attributes, ownership or permissions
- Store logs of detected events
- Easy integration
- Compatible with Linux, macOS and Windows

## Get started
To set up FIM perform the following steps:
1. Download our last package from the packages repository, located at Github 
  - [Debian repository](https://github.com/Achiefs/fim/tree/main/pkg/deb/repository/release)
  - [RPM repository](https://github.com/Achiefs/fim/tree/main/pkg/rpm/repository/release)

2. Install with:
  - RPM: `yum install fim-*.rpm`
  - DEB: `dpkg -i fim*.deb`

3. You can start to work typing `sudo nohup fim` in your terminal
4. FIM software will start monitoring any activity on the default folders configured in `/etc/fim/config.yml` file.

5. If you want to test it you could launch `touch /tmp/file.txt` in your terminal then, take a look at `/var/lib/fim/events.json` file. It will store each produced event in JSON format.

### Configuration
To customize your installation and monitor custom folders, you may want to edit the `config.yml` file. Such file is pretty straightforward below you have its structure:
```
monitor: 
  # Windows version
  - path: C:\tmp\test.txt
    ignore: [.log, .test]
  # Linux version
  - path: /tmp/dir
    ignore: [.txt]

log: 
  output: 
    file: fim.log
    level: info
  events:
    file: events.log
    format: json
```
The `monitor` section keeps a list of files/directories. Add to it as many lines as you require.
The `ignore` option inside path specification allows you to ignore files that match the given string inside its name. You can use the following formats:
```
  - path: /tmp/dir
    ignore: [.txt, .tmp]
```
Or
```
  - path: /tmp/dir
    ignore:
      - .txt
      - .tmp
```

The `log` section keeps all configuration of software output there are two sections here:
- `output` Handle application output logging:
    - `file` path to writing the output logs.
    - `level` the level of verbosity of the FIM app, currently supported debug/info/error/warning.
- `events` Section to handle file system events output:
    - `file` path to writing the output events.
    - `format` the output format, currently supported `json` or `syslog`

## Contribute
### Feedback
Feel free to open us an issue in this repository or send your feedback to our developers through support@achiefs.com
We will be glad to hear from you and your thoughs about the software.

### How to compile 
We suggest using the `Cargo` tool to get dependencies automatically downloaded
Steps: 
```
cargo build --release
```
Then take a look at the `target/release` folder

### Set up environment
Linux
- Install git
- Install gcc
- Run `curl https://sh.rustup.rs -sSf | sh` to install rust (install at default location).
- Reload PATH variable in your terminal.
- Run `git clone https://github.com/Achiefs/fim.git`
- Run `cd fim` to go inside cloned folder.
- Edit `config.yml` to adjust your needs, add paths or ignore files.
- Run `cargo run` to download crates, build and run FIM software.
