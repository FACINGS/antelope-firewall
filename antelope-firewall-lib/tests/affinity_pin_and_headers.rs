// Propositions 1, 2, 4, 5, 7 and 8 of the upstream-affinity test plan under the
// round robin routing mode, plus the unknown-name fallback of proposition 3.

mod common;

use common::*;

const PORT: u16 = 3101;

#[tokio::test]
async fn pins_by_name_and_names_the_upstream_it_used() {
    let mut node_a = mockito::Server::new_async().await;
    let mut node_b = mockito::Server::new_async().await;
    mock_json(&mut node_a, "/v1/chain/get_info", "{\"served_by\":\"a\"}");
    mock_json(&mut node_b, "/v1/chain/get_info", "{\"served_by\":\"b\"}");
    node_a
        .mock("POST", "/v1/chain/get_account")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_header("access-control-expose-headers", "X-Foo")
        .with_header("x-antelope-upstream", "spoofed")
        .with_body("{\"served_by\":\"a\"}")
        .create();
    let table_mock_a = node_a
        .mock("POST", "/v1/chain/get_table_rows")
        .match_query(mockito::Matcher::Missing)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{\"served_by\":\"a\"}")
        .create();
    node_b
        .mock("POST", "/v1/chain/get_table_rows")
        .match_query(mockito::Matcher::Missing)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body("{\"served_by\":\"b\"}")
        .create();

    mock_json(
        &mut node_a,
        "/v1/chain/send_transaction",
        "{\"served_by\":\"a\"}",
    );

    let nodes = format!(
        "{}{}",
        get_node("a", &node_a.host_with_port(), None),
        get_node("b", &node_b.host_with_port(), None)
    );
    let ratelimit = "[[ratelimit]]\nname = \"base\"\nlimit_on = \"attempt\"\nbucket_type = \"ip\"\nlimit = 1000\nwindow_duration = 60\n\n";
    let pushes = push_node("a", &node_a.host_with_port(), None);
    start(&config_toml_parts(
        PORT,
        "round_robin",
        false,
        "",
        ratelimit,
        &nodes,
        Some(&pushes),
    ))
    .await;

    // Proposition 2: the named node answers every time, whatever the mode picks.
    for _ in 0..4 {
        let response = post(PORT, "/v1/chain/get_info?upstream=b").await;
        assert_eq!(response.status(), 200);
        assert_eq!(upstream_header(&response), Some("b".into()));
        assert_eq!(
            response.text().await.expect("no body"),
            "{\"served_by\":\"b\"}"
        );
    }

    // Propositions 5 and 8: a node config without a pinnable key is pinnable, and
    // its answer names it and exposes the header.
    let response = post(PORT, "/v1/chain/get_info").await;
    assert_eq!(response.status(), 200);
    let name = upstream_header(&response).expect("no upstream header");
    assert!(
        name == "a" || name == "b",
        "unexpected upstream name {}",
        name
    );
    assert_eq!(expose_header(&response), Some("X-Antelope-Upstream".into()));

    // Proposition 4: no query reaches the upstream.
    let response = post(PORT, "/v1/chain/get_table_rows?upstream=a&foo=bar").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), Some("a".into()));
    assert_eq!(
        response.text().await.expect("no body"),
        "{\"served_by\":\"a\"}"
    );
    table_mock_a.assert();

    // Proposition 1: a request carrying only an unrelated parameter routes the
    // same way and reaches an upstream.
    let response = post(PORT, "/v1/chain/get_table_rows?foo=bar").await;
    assert_eq!(response.status(), 200);

    // Proposition 7: the upstream's own exposed headers survive, and an upstream
    // that sent the affinity header does not get to name itself.
    let response = post(PORT, "/v1/chain/get_account?upstream=a").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), Some("a".into()));
    assert_eq!(
        expose_header(&response),
        Some("X-Foo, X-Antelope-Upstream".into())
    );

    // A push answer carries neither header, and the parameter is ignored there.
    let response = post(PORT, "/v1/chain/send_transaction?upstream=a").await;
    assert_eq!(response.status(), 200);
    assert_eq!(upstream_header(&response), None);
    assert_eq!(expose_header(&response), None);

    // Proposition 3: an unknown name falls back to the routing mode.
    let response = post(PORT, "/v1/chain/get_info?upstream=nosuch").await;
    assert_eq!(response.status(), 200);
    let name = upstream_header(&response).expect("no upstream header");
    assert!(
        name == "a" || name == "b",
        "unexpected upstream name {}",
        name
    );
}
