// Proposition 2 of the upstream-affinity test plan under the random routing mode.

mod common;

use common::*;

const PORT: u16 = 3103;

#[tokio::test]
async fn pins_by_name_under_random() {
    let mut node_a = mockito::Server::new_async().await;
    let mut node_b = mockito::Server::new_async().await;
    mock_json(&mut node_a, "/v1/chain/get_info", "{\"served_by\":\"a\"}");
    mock_json(&mut node_b, "/v1/chain/get_info", "{\"served_by\":\"b\"}");

    let nodes = format!(
        "{}{}",
        get_node("a", &node_a.host_with_port(), None),
        get_node("b", &node_b.host_with_port(), None)
    );
    start(&config_toml(PORT, "random", false, 1000, &nodes)).await;

    for _ in 0..8 {
        let response = post(PORT, "/v1/chain/get_info?upstream=b").await;
        assert_eq!(response.status(), 200);
        assert_eq!(upstream_header(&response), Some("b".into()));
        assert_eq!(
            response.text().await.expect("no body"),
            "{\"served_by\":\"b\"}"
        );
    }
}
