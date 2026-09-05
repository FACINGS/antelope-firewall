#![allow(dead_code)]

// Shared helpers for the upstream-affinity integration tests. Each test binary
// builds one firewall, because `from_config` registers process-wide Prometheus
// counters and a second registration of the same counter name fails.

use antelope_firewall_lib::config::{from_config, Config};
use chrono::Utc;
use reqwest::Client;
use std::time::Duration;

// A config with an empty push list, one rate limiter, and the caller's get nodes.
pub fn config_toml(
    port: u16,
    mode: &str,
    healthcheck: bool,
    limit: u64,
    get_nodes: &str,
) -> String {
    let ratelimit = format!(
        "[[ratelimit]]\nname = \"base\"\nlimit_on = \"attempt\"\nbucket_type = \"ip\"\nlimit = {}\nwindow_duration = 60\n\n",
        limit
    );
    config_toml_parts(port, mode, healthcheck, "", &ratelimit, get_nodes, None)
}

// The same config with each block supplied by the caller. `root_extra` carries
// root keys, which toml requires before any table header.
pub fn config_toml_parts(
    port: u16,
    mode: &str,
    healthcheck: bool,
    root_extra: &str,
    ratelimit: &str,
    get_nodes: &str,
    push_nodes: Option<&str>,
) -> String {
    let healthcheck_block = if healthcheck {
        "[healthcheck]\ninterval = 2\ngrace_period = 600\n\n"
    } else {
        ""
    };
    let push_key = match push_nodes {
        Some(_) => String::new(),
        None => "push_nodes = []\n".to_string(),
    };
    format!(
        "routing_mode = \"{}\"\naddress = \"127.0.0.1:{}\"\n{}{}\n{}{}{}{}",
        mode,
        port,
        push_key,
        root_extra,
        healthcheck_block,
        ratelimit,
        get_nodes,
        push_nodes.unwrap_or("")
    )
}

pub fn push_node(name: &str, host: &str, pinnable: Option<bool>) -> String {
    let pinnable_line = match pinnable {
        Some(value) => format!("pinnable = {}\n", value),
        None => String::new(),
    };
    format!(
        "[[push_nodes]]\nname = \"{}\"\nurl = \"http://{}/\"\n{}\n",
        name, host, pinnable_line
    )
}

pub fn get_node(name: &str, host: &str, pinnable: Option<bool>) -> String {
    get_node_with_weight(name, host, pinnable, None)
}

pub fn get_node_with_weight(
    name: &str,
    host: &str,
    pinnable: Option<bool>,
    weight: Option<u64>,
) -> String {
    let pinnable_line = match pinnable {
        Some(value) => format!("pinnable = {}\n", value),
        None => String::new(),
    };
    let weight_line = match weight {
        Some(value) => format!("weight = {}\n", value),
        None => String::new(),
    };
    format!(
        "[[get_nodes]]\nname = \"{}\"\nurl = \"http://{}/\"\n{}{}\n",
        name, host, pinnable_line, weight_line
    )
}

pub async fn start(config_text: &str) {
    let config = toml::from_str::<Config>(config_text).expect("test config contains an error");
    let firewall = from_config(config)
        .await
        .expect("test config unable to build");
    tokio::spawn(async move {
        let _ = firewall.build().run().await;
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
}

// Answer the health checker with a head time inside the grace period.
pub fn mock_healthy_get_info(server: &mut mockito::Server) {
    let body = format!(
        "{{\"head_block_time\":\"{}\"}}",
        Utc::now().format("%Y-%m-%dT%H:%M:%S.%f")
    );
    server
        .mock("POST", "/v1/chain/get_info")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create();
}

pub fn mock_json(server: &mut mockito::Server, path: &str, body: &str) {
    server
        .mock("POST", path)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create();
}

pub async fn post(port: u16, path_and_query: &str) -> reqwest::Response {
    post_body(port, path_and_query, "{}").await
}

pub async fn post_body(port: u16, path_and_query: &str, body: &str) -> reqwest::Response {
    Client::new()
        .post(format!("http://127.0.0.1:{}{}", port, path_and_query))
        .body(body.to_string())
        .send()
        .await
        .expect("error sending request to the firewall")
}

// Send as a client the firewall reads from the forwarded header, which the
// caller's config names in client_ip_header.
pub async fn post_as(port: u16, path_and_query: &str, client_ip: &str) -> reqwest::Response {
    Client::new()
        .post(format!("http://127.0.0.1:{}{}", port, path_and_query))
        .header("x-forwarded-for", client_ip)
        .body("{}")
        .send()
        .await
        .expect("error sending request to the firewall")
}

pub fn upstream_header(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get("x-antelope-upstream")
        .map(|value| value.to_str().expect("header not text").to_string())
}

pub fn expose_header(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get("access-control-expose-headers")
        .map(|value| value.to_str().expect("header not text").to_string())
}
