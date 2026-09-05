// Proposition 8 of the upstream-affinity test plan: the uniqueness rule binds
// pinnable entries of one list only.

use antelope_firewall_lib::config::{from_config, Config};

#[tokio::test]
async fn accepts_a_repeated_unpinnable_name_and_a_name_in_both_lists() {
    let text = concat!(
        "routing_mode = \"round_robin\"\n",
        "address = \"127.0.0.1:3108\"\n",
        "ratelimit = []\n\n",
        "[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9001/\"\n\n",
        "[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9002/\"\npinnable = false\n\n",
        "[[push_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9003/\"\n"
    );
    let config = toml::from_str::<Config>(text).expect("test config contains an error");
    assert!(from_config(config).await.is_ok());
}
