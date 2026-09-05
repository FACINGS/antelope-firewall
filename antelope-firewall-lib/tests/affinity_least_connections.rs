// Propositions 2 and 3 of the upstream-affinity test plan under the least
// connections routing mode.

mod common;

use common::*;

const PORT: u16 = 3102;

#[tokio::test]
async fn pins_by_name_and_skips_an_unpinnable_name() {
    let mut node_a = mockito::Server::new_async().await;
    let mut node_b = mockito::Server::new_async().await;
    let mut node_c = mockito::Server::new_async().await;
    mock_json(&mut node_a, "/v1/chain/get_info", "{\"served_by\":\"a\"}");
    mock_json(&mut node_b, "/v1/chain/get_info", "{\"served_by\":\"b\"}");
    mock_json(&mut node_c, "/v1/chain/get_info", "{\"served_by\":\"c\"}");

    // The weight makes the routing mode's own pick deterministic: with no
    // connection counts yet, least connections divides one by the weight.
    let nodes = format!(
        "{}{}{}",
        get_node_with_weight("a", &node_a.host_with_port(), None, Some(10)),
        get_node("b", &node_b.host_with_port(), Some(true)),
        get_node("c", &node_c.host_with_port(), Some(false))
    );
    start(&config_toml(PORT, "least_connections", false, 1000, &nodes)).await;

    for _ in 0..4 {
        let response = post(PORT, "/v1/chain/get_info?upstream=b").await;
        assert_eq!(response.status(), 200);
        assert_eq!(upstream_header(&response), Some("b".into()));
    }

    // An unpinnable name is not an error and does not select the node.
    let response = post(PORT, "/v1/chain/get_info?upstream=c").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), Some("a".into()));
    assert_eq!(
        response.text().await.expect("no body"),
        "{\"served_by\":\"a\"}"
    );
}
