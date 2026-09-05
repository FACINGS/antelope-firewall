// The pin limiter owns the name "pinned", so no configured ratelimiter can take
// it and collide with it in the metrics or in a log line.

use antelope_firewall_lib::config::{from_config, Config};

#[tokio::test]
async fn rejects_a_ratelimiter_named_pinned() {
    let text = concat!(
        "routing_mode = \"round_robin\"\n",
        "address = \"127.0.0.1:3115\"\n",
        "push_nodes = []\n\n",
        "[[ratelimit]]\nname = \"pinned\"\nlimit_on = \"attempt\"\nbucket_type = \"ip\"\nlimit = 10\nwindow_duration = 60\n\n",
        "[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9001/\"\n"
    );
    let config = toml::from_str::<Config>(text).expect("test config contains an error");
    assert!(from_config(config).await.is_err());
}
