# File integrity monitoring in Rust
Hello everybody,

This software aims to improve the File integrity monitoring that we perform nowadays.
File integrity monitoring is a common task in a security environment that all world is demanding.
For that reason, we want to produce faster and easy to use open-source FIM tool improving similar functionality from Ossec.

## First steps: Package installation (RPM and DEB only)
To install FIM packages you only need to perform a few steps:
1. Download our last package from the packages repository, located at Github `fim/pkg/{rpm,deb}/repository/release`

2. Install with
RPM: `yum install fim-*.rpm`
DEB: `apt install fim-*.deb`

3. You can start to work typing `sudo nohup fim` in your terminal
4. FIM software will start monitoring any activity on the default folders configured in `/etc/fim/config.yml` file.

5. If you want to test it you could launch `touch /tmp/file.txt` in your terminal then, take a look at `/usr/share/fim/events.json` file. It will store each produced event in JSON format.


## Contributing: How to compile 
We suggest using the `Cargo` tool to get dependencies automatically downloaded
Steps: 
```
cargo build --release
```

### Set up environment
Linux
- Install git
- Install gcc
- Run `curl https://sh.rustup.rs -sSf | sh` to install rust (install at default location).
- Reload PATH variable in your terminal.
- Run `git clone https://github.com/Achiefs/fim.git`
- Run `cd fim` to go inside cloned folder.
- Edit `config.yml` to adjust your needs, add paths or ignore files.
- Run `cargo run` to download crates, build and run Fim software.

## How to use
You need to modify the `config.yml` file to adjust to your needs.
This file has to be on the same path as the binary file.
Run `fim` with:
Linux
```
sudo ./fim
```

Windows
```
./fim.exe
```

### Configuration file
To customize your installation and monitor all required files, you may want to edit the `config.yml` file. Such file is pretty straightforward below you have its structure:
```
monitor: 
  # Windows version
  - path: C:\tmp\test.txt
    ignore: .log
  # Linux version
  - path: /tmp/dir
    ignore: .txt

log: 
  output: 
    file: fim.log
    level: debug
  events:
    file: events.log
    format: json
```
The `monitor` section keeps a list of files/directories. Add to it as many lines as you require.
By now the recursion is only supported by adding nested folders.

The `log` section keeps all configuration of software output there are two sections here:
- `output` Handle application output logging:
    - `file` path to writing the output logs.
    - `level` the level of verbosity of the FIM app, currently supported debug/info/error/warning.
- `events` Section to handle file system events output:
    - `file` path to writing the output events.
    - `format` the output format, currently supported `json` or `syslog`
