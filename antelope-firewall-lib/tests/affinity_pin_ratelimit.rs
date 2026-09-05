// The pin ceiling: one client IP cannot hold one node by name for more than its
// share of a window, and over the ceiling the request is answered by the routing
// mode rather than refused.

mod common;

use common::*;

const PORT: u16 = 3113;

#[tokio::test]
async fn over_the_ceiling_the_pin_drops_and_the_routing_mode_answers() {
    let mut node_a = mockito::Server::new_async().await;
    let mut node_b = mockito::Server::new_async().await;
    mock_json(&mut node_a, "/v1/chain/get_info", "{\"served_by\":\"a\"}");
    mock_json(&mut node_b, "/v1/chain/get_info", "{\"served_by\":\"b\"}");

    // The weight makes the routing mode's own pick deterministic, so a dropped
    // pin is visible as an answer from the other node.
    let nodes = format!(
        "{}{}",
        get_node_with_weight("a", &node_a.host_with_port(), None, Some(10)),
        get_node("b", &node_b.host_with_port(), None)
    );
    let ratelimit = "[[ratelimit]]\nname = \"base\"\nlimit_on = \"attempt\"\nbucket_type = \"ip\"\nlimit = 1000\nwindow_duration = 60\n\n";
    let root_extra = "client_ip_header = \"x-forwarded-for\"\npinned_requests_per_window = 1\npinned_window_seconds = 60\n";
    start(&config_toml_parts(
        PORT,
        "least_connections",
        false,
        root_extra,
        ratelimit,
        &nodes,
        None,
    ))
    .await;

    // The ceiling is exact: one pinned read per window admits one.
    let response = post_as(PORT, "/v1/chain/get_info?upstream=b", "198.51.100.7").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), Some("b".into()));

    let response = post_as(PORT, "/v1/chain/get_info?upstream=b", "198.51.100.7").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), Some("a".into()));
    assert_eq!(
        response.text().await.expect("no body"),
        "{\"served_by\":\"a\"}"
    );

    // The ceiling is per client, so another client still pins.
    let response = post_as(PORT, "/v1/chain/get_info?upstream=b", "203.0.113.9").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), Some("b".into()));
}
