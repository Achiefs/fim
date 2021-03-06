# File integrity monitoring in Rust
Hello everybody,

This software aims to improve the File integrity monitoring that we perform nowadays.
File integrity monitoring is a common task in a security environment that all world is demanding.
For that reason, we want to produce faster and easy to use open-source FIM tool improving similar functionality from Ossec.

## How to compile 
We suggest using the `Cargo` tool to get dependencies automatically downloaded
Steps: 
```
cargo build --release
```

## Set up environment
Linux
- Install git
- Install gcc
- Run `curl https://sh.rustup.rs -sSf | sh` to install rust (install at default location).
- run `git clone https://github.com/Achiefs/fim.git`
- run `cargo run` to download crates, build and run Fim.
- Edit `config.yml` to adjust your needs.

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
  - C:\tmp\test.txt
  - C:\tmp\dir

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
