// Copyright (C) 2021, Achiefs.

// To use files IO operations.
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};
// To manage HTTP requests
use reqwest::{Client, Body};
use reqwest::header;
// To log the program process
use log::{info, debug};
// To manage paths
use std::path::Path;

fn get_template_path() -> String {
    let relative_path = "./../../config/index_template.json";
    let config_path = "/etc/fim/index_template.json";
    let default_path = "config/index_template.json";
    if Path::new(default_path).exists() {
        String::from(default_path)
    }else if Path::new("./index_template.json").exists() {
        String::from("./index_template.json")
    }else if Path::new(relative_path).exists() {
        String::from(relative_path)
    }else{
        String::from(config_path)
    }
}

pub async fn create_index(name: String, address: String, user: String, pass: String, insecure: bool){
    let template_path = get_template_path();
    info!("Loaded index template from: {}", template_path);
    let file = File::open(template_path).await.unwrap();
    let stream = FramedRead::new(file, BytesCodec::new());
    let body = Body::wrap_stream(stream);
    let url = format!("{}/{}", address, name);

    let client = Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build().unwrap();
    let response = client
        .put(url)
        .header(header::CONTENT_TYPE, "application/json")
        .basic_auth(user, Some(pass))
        .body(body)
        .send()
        .await;

    debug!("Event send Response: {:?}", response.unwrap().text().await);
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_index() {
        tokio_test::block_on( create_index(
            String::from("test"), String::from("https://127.0.0.1:9200"),
            String::from("admin"), String::from("admin"), true) );
    }

    #[test]
    fn test_get_template_path() {
        assert_eq!(get_template_path(), "config/index_template.json");
    }

}