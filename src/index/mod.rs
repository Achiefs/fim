// Copyright (C) 2021, Achiefs.

// To use files IO operations.
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};
// To manage HTTP requests
use reqwest::{Client, Body};
use reqwest::header;

pub async fn create_index(endpoint: String){
    let file = File::open("config/index_template.json").await.unwrap();
    let stream = FramedRead::new(file, BytesCodec::new());
    let body = Body::wrap_stream(stream);

    // Include a way to create an index per day
    // Include a way to pass credentials
    let request_url = format!("{}/fim-10-10-2022", endpoint);
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build().unwrap();
    let response = client
        .put(request_url)
        .header(header::CONTENT_TYPE, "application/json")
        .basic_auth("admin", Some("admin"))
        .body(body)
        .send()
        .await;
    debug!("Event send Response: {:?}", response.unwrap().text().await);
}
