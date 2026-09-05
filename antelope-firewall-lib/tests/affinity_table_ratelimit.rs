// A table rate limiter applies to a request that carries the affinity parameter,
// so the parameter buys no extra table reads.

mod common;

use common::*;

const PORT: u16 = 3114;

#[tokio::test]
async fn table_limiter_counts_a_parameter_request() {
    let mut node = mockito::Server::new_async().await;
    mock_json(&mut node, "/v1/chain/get_table_rows", "{\"rows\":[]}");

    let nodes = get_node("a", &node.host_with_port(), None);
    let ratelimit = "[[ratelimit]]\nname = \"table\"\nlimit_on = \"attempt\"\nbucket_type = \"table\"\nlimit = 1\nwindow_duration = 3600\nselect_accounts = [\"eosio.token::accounts\"]\n\n";
    start(&config_toml_parts(
        PORT,
        "round_robin",
        false,
        "",
        ratelimit,
        &nodes,
        None,
    ))
    .await;

    let body = "{\"scope\":\"a.wam\",\"code\":\"eosio.token\",\"table\":\"accounts\"}";
    for _ in 0..2 {
        let response = post_body(PORT, "/v1/chain/get_table_rows?upstream=a", body).await;
        assert_eq!(response.status(), 200);
    }
    let response = post_body(PORT, "/v1/chain/get_table_rows?upstream=a", body).await;
    assert_eq!(response.status(), 429);
}
