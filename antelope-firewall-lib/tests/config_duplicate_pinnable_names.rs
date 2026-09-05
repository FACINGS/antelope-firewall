// Proposition 8 of the upstream-affinity test plan: two pinnable entries of one
// list cannot share a name.

use antelope_firewall_lib::config::{from_config, Config};

#[tokio::test]
async fn rejects_two_pinnable_nodes_with_one_name() {
    let text = concat!(
        "routing_mode = \"round_robin\"\n",
        "address = \"127.0.0.1:3107\"\n",
        "push_nodes = []\n",
        "ratelimit = []\n\n",
        "[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9001/\"\n\n",
        "[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9002/\"\n"
    );
    let config = toml::from_str::<Config>(text).expect("test config contains an error");
    assert!(from_config(config).await.is_err());
}
