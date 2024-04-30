// Copyright (C) 2021, Achiefs.

// To use files IO operations.
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};
// To manage HTTP requests
use reqwest::{Client, Body};
use reqwest::header;
// To log the program process
use log::{info, debug, error};
// To manage paths
use std::path::Path;
// Handle time intervals
use std::time::Duration;

use crate::appconfig::*;

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

// ----------------------------------------------------------------------------

pub async fn push_template(cfg: AppConfig){
    let template_path = get_template_path();
    info!("Loaded index template from: {}", template_path);
    let file = File::open(template_path).await.unwrap();
    let stream = FramedRead::new(file, BytesCodec::new());
    let body = Body::wrap_stream(stream);
    let url = format!("{}/_template/fim", cfg.endpoint_address);

    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .danger_accept_invalid_certs(cfg.insecure)
        .build().unwrap();
    let response = client
        .put(url)
        .header(header::CONTENT_TYPE, "application/json")
        .basic_auth(cfg.endpoint_user, Some(cfg.endpoint_pass))
        .body(body)
        .send()
        .await;

    match response {
        Ok(response) => debug!("Push index template response: {:?}",
                        response.text().await.unwrap()),
        Err(e) => error!("Error on request: {:?}", e)
    }
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    #[test]
    fn test_push_template() {
        tokio_test::block_on( push_template(
            AppConfig::new(&utils::get_os(), Some("test/unit/config/common/test_push_template.yml"))));
    }

    #[test]
    fn test_get_template_path() {
        assert_eq!(get_template_path(), "config/index_template.json");
    }

}