// A node that redirects hands the answer to another host, and that host is not
// the node the header would name, so the answer names no upstream.

mod common;

use common::*;

const PORT: u16 = 3116;

#[tokio::test]
async fn a_redirected_answer_names_no_upstream() {
    let mut node_a = mockito::Server::new_async().await;
    let mut node_b = mockito::Server::new_async().await;
    mock_json(&mut node_b, "/v1/chain/get_info", "{\"served_by\":\"b\"}");
    node_b
        .mock("GET", "/v1/chain/get_info")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{\"served_by\":\"b\"}")
        .create();
    node_a
        .mock("POST", "/v1/chain/get_info")
        .with_status(302)
        .with_header(
            "location",
            &format!("http://{}/v1/chain/get_info", node_b.host_with_port()),
        )
        .with_body("")
        .create();

    let nodes = format!(
        "{}{}",
        get_node("a", &node_a.host_with_port(), None),
        get_node("b", &node_b.host_with_port(), None)
    );
    start(&config_toml(PORT, "round_robin", false, 1000, &nodes)).await;

    let response = post(PORT, "/v1/chain/get_info?upstream=a").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), None);
    assert_eq!(expose_header(&response), None);
    assert_eq!(
        response.text().await.expect("no body"),
        "{\"served_by\":\"b\"}"
    );
}
