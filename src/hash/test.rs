const MAX_FILE_READ: usize = 64;

use super::*;
use std::fs;
use std::fs::File;
use std::io::prelude::*;

// ------------------------------------------------------------------------

fn create_test_file(filename: String) {
    File::create(filename).unwrap().write_all(b"This is a test!").unwrap();
}

fn remove_test_file(filename: String) {
    fs::remove_file(filename).unwrap()
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_sha224() {
    let filename = String::from("test_get_checksum_file_sha224");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Sha224),
        String::from("818e532a43c2a992f2ae4621cfd43a31e53a7ecf18fdf4197bf14f49"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_sha256() {
    let filename = String::from("test_get_checksum_file_sha256");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Sha256),
        String::from("d583835b95283b2a761111ce4447994e03d26c19c80c2ea20457f1fec7df8cfa"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_sha384() {
    let filename = String::from("test_get_checksum_file_sha384");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Sha384),
        String::from("48f68e385328dbce00e8262800211f8420921eb83ca8d177714659733\
            00c9408f1b8838120d8a812d3a2dfd12f18386a"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_sha512() {
    let filename = String::from("test_get_checksum_file_sha512");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Sha512),
        String::from("46512636eeeb22dee0d60f3aba6473b1fb3258dc0c9ed6fbdbf26bed0\
            6df796bc70d4c1f6d50ca977b45f35b494e4bd9fb34e55a1576d6d9a3b5e1ab059953ee"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_keccak224() {
    let filename = String::from("test_get_checksum_file_keccak224");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Keccak224),
        String::from("7e7f3494791a7a9ae579e8d30525851bd94a97dd9acc1168e9863d08"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_keccak256() {
    let filename = String::from("test_get_checksum_file_keccak256");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Keccak256),
        String::from("e2b4c41ace98cd6c8ef616130eceec37fea33a6411394e21688994e68b5c2b51"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_keccak384() {
    let filename = String::from("test_get_checksum_file_keccak384");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Keccak384),
        String::from("d04fc1be648b68adfddbb66a34badb94fe1f7329846a68353bc32cb85\
            159be1e45f3ffb6837d50e7029b959a47779c11"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_file_keccak512() {
    let filename = String::from("test_get_checksum_file_keccak512");
    create_test_file(filename.clone());
    assert_eq!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Keccak512),
        String::from("17688bfb5a968484f0d3bacb9a7af2b38880931008395be007c107871\
            be0dd9d4f037a2660b90daeffea994473fd7f18dd48503bdab5ffe7ebeab8f3b58cfca4"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_not_exists() {
    assert_ne!(get_checksum(String::from("not_exists"), MAX_FILE_READ, ShaType::Sha512), String::from("This is a test"));
    assert_eq!(get_checksum(String::from("not_exists"), MAX_FILE_READ, ShaType::Sha512), String::from("UNKNOWN"));
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_dir() {
    assert_eq!(get_checksum(String::from("src"), MAX_FILE_READ, ShaType::Sha224), String::from("UNKNOWN"));
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_over_limit() {
    let filename = String::from("test_get_checksum_over_limit");
    create_test_file(filename.clone());
    let checksum = get_checksum(filename.clone(), 0, ShaType::Sha224);
    let partial_checksum = get_partial_checksum(filename.clone(), ShaType::Sha224);
    assert_eq!(partial_checksum, checksum);
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_checksum_bad() {
    let filename = String::from("test_get_checksum_bad");
    create_test_file(filename.clone());
    assert_ne!(get_checksum(filename.clone(), MAX_FILE_READ, ShaType::Sha512), String::from("This is a test"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_sha224() {
    let filename = String::from("test_get_partial_checksum_file_sha224");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Sha224),
        String::from("565a9407ab388f0a5792d602cef19c25e7b352403b65366ad365baa9"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_sha256() {
    let filename = String::from("test_get_partial_checksum_file_sha256");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Sha256),
        String::from("90daddca226368a70f6bb065e31cc04b1c5625cd5e39df29980a7717f7227439"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_sha384() {
    let filename = String::from("test_get_partial_checksum_file_sha384");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Sha384),
        String::from("0179e8011a7e5a08afd8816421b49312c41abdd2614c683b620bf249a\
            d414af93fdf5a7810b6ff06f90a32ac2981881f"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_sha512() {
    let filename = String::from("test_get_partial_checksum_file_sha512");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Sha512),
        String::from("552cd31f0c16860ad97bd796c2937df8f3987cb41064f8dfead0919fe\
            c0e6f9ecf8f05877e8b21561397f942e726657f06c6085fa73ddc45e30ac28f96fdbe36"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_keccak224() {
    let filename = String::from("test_get_partial_checksum_file_keccak224");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Keccak224),
        String::from("688e37986babd96ef9882b67c08b66b2e135b7e96960f036ce139962"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_keccak256() {
    let filename = String::from("test_get_partial_checksum_file_keccak256");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Keccak256),
        String::from("cd7b5e4ec17af43a4825857407b1acbb48b448ae68aaaa165a98dc5710d26619"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_keccak384() {
    let filename = String::from("test_get_partial_checksum_file_keccak384");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Keccak384),
        String::from("94f7c1030c1eaad999ed1162f38168ebf7e2579580dbb2037dc788194\
            ef89f96a795f334229cd16e69de9586632b16bf"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_file_keccak512() {
    let filename = String::from("test_get_partial_checksum_file_keccak512");
    create_test_file(filename.clone());
    assert_eq!(get_partial_checksum(filename.clone(), ShaType::Keccak512),
        String::from("a438e97244e8c547730bf316d3b07437f6ff6bce8c38f00aceee3db76\
            c9fee9db81068d13ca6564369245749326954d376120328880f7dee4e1874692506297d"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_not_exists() {
    assert_ne!(get_partial_checksum(String::from("not_exists"), ShaType::Sha224), String::from("This is a test"));
    assert_eq!(get_partial_checksum(String::from("not_exists"), ShaType::Sha224), String::from("UNKNOWN"));
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_dir() {
    assert_eq!(get_partial_checksum(String::from("src"), ShaType::Sha224), String::from("UNKNOWN"));
}

// ------------------------------------------------------------------------

#[test]
fn test_get_partial_checksum_bad() {
    let filename = String::from("test_get_partial_checksum_bad");
    create_test_file(filename.clone());
    assert_ne!(get_partial_checksum(filename.clone(), ShaType::Sha224), String::from("This is a test"));
    remove_test_file(filename.clone());
}

// ------------------------------------------------------------------------

#[test]
fn test_hex_to_ascii() {
    let ascii = hex_to_ascii(String::from("746F756368002F746D702F746573742F66696C65342E747874"));
    assert_eq!(ascii, "touch /tmp/test/file4.txt");
}

// ------------------------------------------------------------------------

#[test]
fn test_hex_to_ascii_bad() {
    assert_eq!(hex_to_ascii(String::from("ABC")), "");
}