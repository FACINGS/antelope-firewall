// Proposition 3 of the upstream-affinity test plan: a name the health checker
// marks unhealthy falls back to the routing mode.

mod common;

use antelope_firewall_lib::config::HEALTH_CHECKER;
use common::*;
use reqwest::Url;
use std::time::Duration;

const PORT: u16 = 3105;

async fn wait_until_unhealthy(url: &Url) {
    for _ in 0..100 {
        {
            let guard = HEALTH_CHECKER.read().await;
            if let Some(ref checker) = *guard {
                if !checker.is_healthy(url).await {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("node at {} never turned unhealthy", url);
}

#[tokio::test]
async fn unhealthy_named_node_falls_back_to_routing_mode() {
    let mut node_a = mockito::Server::new_async().await;
    let mut node_b = mockito::Server::new_async().await;
    mock_healthy_get_info(&mut node_a);
    mock_json(
        &mut node_a,
        "/v1/chain/get_table_rows",
        "{\"served_by\":\"a\"}",
    );
    node_b
        .mock("POST", "/v1/chain/get_info")
        .with_status(500)
        .with_body("unhealthy")
        .create();
    mock_json(
        &mut node_b,
        "/v1/chain/get_table_rows",
        "{\"served_by\":\"b\"}",
    );

    let nodes = format!(
        "{}{}",
        get_node("a", &node_a.host_with_port(), None),
        get_node("b", &node_b.host_with_port(), None)
    );
    start(&config_toml(PORT, "round_robin", true, 1000, &nodes)).await;

    let node_b_url = Url::parse(&format!("http://{}/", node_b.host_with_port())).expect("bad url");
    wait_until_unhealthy(&node_b_url).await;

    let response = post(PORT, "/v1/chain/get_table_rows?upstream=b").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), Some("a".into()));
    assert_eq!(
        response.text().await.expect("no body"),
        "{\"served_by\":\"a\"}"
    );
}
