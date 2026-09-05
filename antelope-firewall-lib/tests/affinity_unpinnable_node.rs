// Proposition 6 of the upstream-affinity test plan: an unpinnable node's answer
// carries neither header, named or not.

mod common;

use common::*;

const PORT: u16 = 3104;

#[tokio::test]
async fn unpinnable_answer_carries_neither_header() {
    let mut node = mockito::Server::new_async().await;
    mock_json(&mut node, "/v1/chain/get_info", "{\"served_by\":\"a\"}");

    let nodes = get_node("a", &node.host_with_port(), Some(false));
    start(&config_toml(PORT, "round_robin", false, 1000, &nodes)).await;

    for path in ["/v1/chain/get_info", "/v1/chain/get_info?upstream=a"] {
        let response = post(PORT, path).await;
        assert_eq!(response.status(), 200);
        assert_eq!(upstream_header(&response), None);
        assert_eq!(expose_header(&response), None);
    }
}
