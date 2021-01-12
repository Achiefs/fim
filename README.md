# File integrity monitoring in Rust
Hello everybody,

This software aims to improve the File integrity monitoring that we perform nowadays.
File integrity monitoring is a common task in a security environment that all world is demanding.
For that reason, we want to produce faster and easy to use open-source FIM tool improving similar software from Ossec.

## How to compile 
We suggest using the `Cargo` tool to get dependencies automatically downloaded
Steps: 
```
cargo build --release
```

## How to use
You need to modify the `config.yml` file to adjust to your needs.
This file has to be on the same path as the binary file.
Run fim with:
Linux
```
sudo ./fim
```

Windows
```
./fim.exe
```