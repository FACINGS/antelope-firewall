// A window of zero seconds ends the moment it starts, so every count resets and
// the ceiling admits every pin. The config is refused instead.

use antelope_firewall_lib::config::{from_config, Config};

#[tokio::test]
async fn rejects_a_zero_pin_window() {
    let text = concat!(
        "routing_mode = \"round_robin\"\n",
        "address = \"127.0.0.1:3117\"\n",
        "push_nodes = []\n",
        "ratelimit = []\n",
        "pinned_window_seconds = 0\n\n",
        "[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9001/\"\n"
    );
    let config = toml::from_str::<Config>(text).expect("test config contains an error");
    assert!(from_config(config).await.is_err());
}
