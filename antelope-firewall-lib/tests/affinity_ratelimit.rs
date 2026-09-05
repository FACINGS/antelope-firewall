// Proposition 1 of the upstream-affinity test plan: a request carrying the
// affinity parameter passes the same filters and rate limiters.

mod common;

use common::*;

const PORT: u16 = 3106;

#[tokio::test]
async fn parameter_request_is_rate_limited_like_any_other() {
    let mut node = mockito::Server::new_async().await;
    mock_json(&mut node, "/v1/chain/get_info", "{\"served_by\":\"a\"}");

    let nodes = get_node("a", &node.host_with_port(), None);
    start(&config_toml(PORT, "round_robin", false, 1, &nodes)).await;

    for _ in 0..2 {
        let response = post(PORT, "/v1/chain/get_info?upstream=a").await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.text().await.expect("no body"),
            "{\"served_by\":\"a\"}"
        );
    }
    let response = post(PORT, "/v1/chain/get_info?upstream=a").await;
    assert_eq!(response.status(), 429);
}
