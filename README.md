# FIM
[![Join us on Slack](https://img.shields.io/badge/Chat-Join%20us%20on%20Slack-blue)](https://join.slack.com/t/filemonitor/shared_invite/zt-1au9t0hf4-yOsW6D3pGPqzzYsAJt9Dvg)
![GitHub](https://img.shields.io/github/license/Achiefs/fim)
[![Coverage Status](https://coveralls.io/repos/github/Achiefs/fim/badge.svg)](https://coveralls.io/github/Achiefs/fim)

FIM is a File Integrity Monitoring tool that tracks any event over your files.
It is capable of keeping historical data of your files. It checks the filesystem changes in the background.
FIM is the fastest alternative to other software like Ossec to perform file integrity monitoring.
It could integrate with other security tools like Ossec or Wazuh.
The produced data can be ingested and analyzed with tools like ElasticSearch/OpenSearch.
It has developed with Rust, the best core programming language.

## Features
- Filesystem monitor (File change monitor).
- Identification of changes in content, attributes, ownership or permissions (Linux Audit data).
- Store logs of detected events.
- Easy integration with Elasticsearch/OpenSearch Wazuh indexer.
- Compatible with Linux, macOS and Windows.

## Get started
To set up FIM perform the following steps:
1. Download our last package from the packages repository, located at Github
  - [Debian repository](https://github.com/Achiefs/fim/tree/main/pkg/deb/repository/release)
  - [RPM repository](https://github.com/Achiefs/fim/tree/main/pkg/rpm/repository/release)

2. Install with:
  - RPM: `yum install fim-*.rpm`
  - DEB: `dpkg -i fim*.deb`
  - CARGO: `cargo install --git https://github.com/Achiefs/fim.git`

3. You can start to work typing `sudo nohup fim` in your terminal
4. FIM software will start monitoring any activity on the default folders configured in `/etc/fim/config.yml` file.

5. If you want to test it you could launch `touch /tmp/file.txt` in your terminal then, take a look at `/var/lib/fim/events.json` file. It will store each produced event in JSON format.

### Configuration
To customize your installation take a look at our [Documentation Wiki](https://github.com/Achiefs/fim/wiki)

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

### Invest
Any kind of contribution will be invested into the project webpage, code development or advertising.
If you want to contribute with the project you could contact us at support@achiefs.com
