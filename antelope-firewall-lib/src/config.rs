// Parses config and returns a firewall

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    net::SocketAddr,
    sync::Arc,
};

use chrono::Duration;
use jsonpath::Selector;
use reqwest::Url;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{
    filter::Filter,
    firewall_builder::{AntelopeFirewall, PinLimiter, RoutingModeState},
    healthcheck::HealthChecker,
    prometheus::start_prometheus_exporter,
    ratelimiter::{IncrementMode, RateLimiter},
    NodeEntry,
};

fn default_true() -> bool {
    true
}

// Reserved so a configured ratelimiter cannot collide with the pin limiter in
// the metrics or in a log line.
const PIN_LIMITER_NAME: &str = "pinned";

fn default_pinned_requests_per_window() -> u64 {
    30
}

fn default_pinned_window_seconds() -> u64 {
    60
}

fn default_max_request_body_size() -> u64 {
    1024 * 64 // 64 KB — backwards compatible with prior hardcoded limit
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub routing_mode: RoutingMode,
    pub address: String,
    pub prometheus_address: Option<String>,

    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: u64,

    // Header carrying the real client IP when the firewall runs behind a trusted
    // reverse proxy (e.g. "cf-connecting-ip"). When set, per-IP rate limiting and
    // block lists key on the header value instead of the socket peer (which would
    // be the proxy). Only safe when the proxy is the sole ingress path, since the
    // header is otherwise client-spoofable. Unset preserves socket-peer keying.
    pub client_ip_header: Option<String>,

    // Ceiling on requests one client IP can pin to one node name inside a
    // window. Over the ceiling the pin is dropped and the request takes the
    // routing mode, so a client cannot steer a share of the traffic it chooses
    // at one node, and cannot learn which node answers by asking for it.
    #[serde(default = "default_pinned_requests_per_window")]
    pub pinned_requests_per_window: u64,

    #[serde(default = "default_pinned_window_seconds")]
    pub pinned_window_seconds: u64,

    pub healthcheck: Option<HealthcheckConfig>,

    pub filter: Option<FilterConfig>,
    pub ratelimit: Vec<RatelimitConfig>,

    pub push_nodes: Vec<Node>,
    pub get_nodes: Vec<Node>,
}

#[derive(Deserialize, Debug)]
pub struct Node {
    pub name: String,
    pub url: String,
    pub weight: Option<u64>,

    // A pinnable node can be asked for by name through the `upstream` query
    // parameter, and names itself on the response. Set it to false for an entry
    // that is itself a load balancer, where the name identifies no single node.
    #[serde(default = "default_true")]
    pub pinnable: bool,
}

#[derive(Deserialize, Debug)]
pub struct HealthcheckConfig {
    pub interval: u64,
    pub grace_period: u64,
}

#[derive(Deserialize, Debug)]
pub struct FilterConfig {
    pub block_contracts: Option<Vec<String>>,
    pub block_ips: Option<Vec<String>>,
    pub allow_only_contracts: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatelimitType {
    #[serde(rename = "attempt")]
    Attempt,
    #[serde(rename = "failure")]
    Failure,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatelimitBucket {
    #[serde(rename = "contract")]
    Contract,
    #[serde(rename = "ip")]
    IP,
    #[serde(rename = "authorizer")]
    Sender,
    #[serde(rename = "table")]
    Table,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RatelimitConfig {
    pub name: String,
    pub limit_on: RatelimitType,
    pub bucket_type: RatelimitBucket,

    pub limit: u64,
    pub window_duration: u64,
    pub select_accounts: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    #[serde(rename = "round_robin")]
    RoundRobin,
    #[serde(rename = "least_connections")]
    LeastConnections,
    #[serde(rename = "random")]
    Random,
}

impl RoutingMode {
    pub fn to_state(&self) -> RoutingModeState {
        match self {
            RoutingMode::RoundRobin => RoutingModeState::base_round_robin(),
            RoutingMode::LeastConnections => RoutingModeState::base_least_connected(),
            RoutingMode::Random => RoutingModeState::base_random(),
        }
    }
}

lazy_static::lazy_static! {
    pub static ref BLOCKED_IPS: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
    pub static ref BLOCKED_CONTRACTS: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
    pub static ref ALLOW_ONLY_CONTRACTS: RwLock<HashSet<String>> = RwLock::new(HashSet::new());

    pub static ref PUSH_ENDPOINTS: HashSet<String> = HashSet::from([
        "/v1/chain/push_transaction".into(),
        "/v1/chain/send_transaction".into(),
        "/v1/chain/push_transactions".into(),
        "/v1/chain/send_transaction2".into(),
        "/v1/chain/compute_transaction".into(),
        "/v1/chain/send_read_only_transaction".into(),
        "/v1/chain/push_block".into(),
    ]);
    pub static ref GET_ENDPOINTS: HashSet<String> = HashSet::from([
        "/v1/chain/get_account".into(),
        "/v1/chain/get_block".into(),
        "/v1/chain/get_block_info".into(),
        "/v1/chain/get_info".into(),
        "/v1/chain/get_block_header_state".into(),
        "/v1/chain/get_abi".into(),
        "/v1/chain/get_currency_balance".into(),
        "/v1/chain/get_currency_stats".into(),
        "/v1/chain/get_required_keys".into(),
        "/v1/chain/get_producers".into(),
        "/v1/chain/get_raw_code_and_abi".into(),
        "/v1/chain/get_scheduled_transactions".into(),
        "/v1/chain/get_table_by_scope".into(),
        "/v1/chain/get_table_rows".into(),
        "/v1/chain/get_code".into(),
        "/v1/chain/get_raw_abi".into(),
        "/v1/chain/get_activated_protocol_features".into(),
        "/v1/chain/get_accounts_by_authorizers".into(),
        "/v1/chain/get_transaction_status".into(),
        "/v1/chain/get_producer_schedule".into()
    ]);

    pub static ref PUSH_NODES: RwLock<HashSet<NodeEntry>> = RwLock::new(HashSet::new());
    pub static ref GET_NODES: RwLock<HashSet<NodeEntry>> = RwLock::new(HashSet::new());

    pub static ref HEALTH_CHECKER: RwLock<Option<Arc<HealthChecker>>> = RwLock::new(None);

    pub static ref SELECT_ACCOUNTS: RwLock<HashMap<String, HashSet<String>>> = RwLock::new(HashMap::new());
}

// A pinnable name travels as a response header value and comes back as a query
// value. This charset keeps it valid as both, so the name a client sends is
// compared as it arrives and needs no decoding.
fn is_valid_pinnable_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

// Turn one configured node list into the set the matching engine hands to the
// router. Two pinnable entries of one list cannot share a name: a shared name
// would let two processes answer under it, and a client that asks for the name
// could not tell them apart. One list cannot carry a URL twice either, because
// the second entry would replace the first and take its name with it.
fn build_node_set(nodes: Vec<Node>) -> Result<HashSet<NodeEntry>, String> {
    let mut entries = HashSet::new();
    let mut pinnable_names = HashSet::new();
    // Routing keeps only the scheme, host and port of a node url, so two entries
    // that differ in path or query address one node and would let a client hold
    // it under two names.
    let mut origins = HashSet::new();
    for node in nodes {
        let weight = node.weight.unwrap_or(1);
        if weight == 0 {
            return Err(format!(
                "Weight for node '{}' must be greater than 0.",
                node.name
            ));
        }
        if node.pinnable && !pinnable_names.insert(node.name.clone()) {
            return Err(format!(
                "Duplicate name for pinnable node '{}'. Pinnable names must be unique.",
                node.name
            ));
        }
        if node.pinnable && !is_valid_pinnable_name(&node.name) {
            return Err(format!(
                "Name for pinnable node '{}' can only carry letters, digits, and the characters . _ -",
                node.name
            ));
        }
        let url = node
            .url
            .parse::<Url>()
            .map_err(|_| format!("Could not parse node '{}' as url.", node.url))?;
        let origin = (
            url.scheme().to_string(),
            url.host_str().map(str::to_string),
            url.port_or_known_default(),
        );
        if !origins.insert(origin) {
            return Err(format!(
                "Duplicate origin for node '{}'. Each scheme, host and port must appear once per list.",
                node.name
            ));
        }
        let inserted = entries.insert(NodeEntry {
            url,
            weight,
            name: node.name.clone(),
            pinnable: node.pinnable,
        });
        if !inserted {
            return Err(format!(
                "Duplicate url for node '{}'. Each url must appear once per list.",
                node.name
            ));
        }
    }
    Ok(entries)
}

pub async fn from_config(config: Config) -> Result<AntelopeFirewall, String> {
    // TODO: Add proper error handling
    if let Some(socket_str) = config.prometheus_address {
        let prometheus_address: SocketAddr = socket_str.parse().unwrap();
        start_prometheus_exporter(prometheus_address)
            .map_err(|_| "Could not start prometheus exporter")?;
    }

    let socket_addr: SocketAddr = config.address.parse().unwrap();
    let mut firewall = AntelopeFirewall::new(
        config.routing_mode.to_state(),
        socket_addr,
        config.max_request_body_size,
        config.client_ip_header,
    );

    if let Some(filter_config) = config.filter {
        if (filter_config.block_contracts.clone().map_or(0, |v| v.len()) > 0)
            && (filter_config
                .allow_only_contracts
                .clone()
                .map_or(0, |v| v.len())
                > 0)
        {
            return Err("Cannot block and allow contracts at the same time.".into());
        }

        let mut ip_guard = BLOCKED_IPS.write().await;
        let mut contract_guard = BLOCKED_CONTRACTS.write().await;
        let mut allow_contract_guard = ALLOW_ONLY_CONTRACTS.write().await;
        if let Some(ips) = filter_config.block_ips {
            for ip in ips {
                ip_guard.insert(ip);
            }
        }
        if let Some(contracts) = filter_config.block_contracts {
            for contract in contracts {
                contract_guard.insert(contract);
            }
        }
        if let Some(contracts) = filter_config.allow_only_contracts {
            for contract in contracts {
                allow_contract_guard.insert(contract);
            }
        }
    }

    firewall = firewall.add_filter(Filter::new(
        "Filter".into(),
        Box::new(|(req, body, _)| {
            Box::pin(async move {
                if !PUSH_ENDPOINTS.contains(req.uri.path())
                    && !GET_ENDPOINTS.contains(req.uri.path())
                {
                    return false;
                } else if BLOCKED_IPS.read().await.contains(&req.ip.to_string()) {
                    return false;
                } else {
                    let selector = Selector::new("$.unpacked_trx.actions.*.account").unwrap();
                    let contract_guard = BLOCKED_CONTRACTS.read().await;
                    let allow_contract_guard = ALLOW_ONLY_CONTRACTS.read().await;
                    if contract_guard.is_empty() && allow_contract_guard.is_empty() {
                        return true;
                    } else if contract_guard.is_empty() {
                        return selector
                            .find(&body)
                            .into_iter()
                            .filter_map(|found| found.as_str().map(|account| account.to_string()))
                            .all(|account| allow_contract_guard.contains(&account));
                    } else {
                        return !selector
                            .find(&body)
                            .into_iter()
                            .filter_map(|found| found.as_str().map(|account| account.to_string()))
                            .any(|account| contract_guard.contains(&account));
                    }
                }
            })
        }),
        None,
    ));

    let mut names = HashSet::new();
    for ratelimit in config.ratelimit {
        if ratelimit.name == PIN_LIMITER_NAME {
            return Err(format!(
                "Name '{}' is reserved for the pin limiter and cannot name a ratelimiter.",
                PIN_LIMITER_NAME
            ));
        }
        if names.contains(&ratelimit.name) {
            return Err(format!(
                "Duplicate name for ratelimiter '{}'. Names must be unique.",
                ratelimit.name
            ));
        } else {
            names.insert(ratelimit.name.clone());
        }

        {
            let mut select_accounts_guard = SELECT_ACCOUNTS.write().await;
            if let Some(select_accounts) = ratelimit.select_accounts {
                select_accounts_guard
                    .insert(ratelimit.name.clone(), HashSet::from_iter(select_accounts));
            }
        }

        let select_accounts_guard = SELECT_ACCOUNTS.write().await;
        firewall = firewall.add_ratelimiter(RateLimiter::new(
            ratelimit.name,
            Box::new(|_| Box::pin(async { true })),
            match ratelimit.bucket_type {
                RatelimitBucket::Contract => Box::new(|(name, _, body, _)| {
                    Box::pin(async move {
                        let selector = Selector::new("$.unpacked_trx.actions.*.account").unwrap();
                        let unfiltered = selector
                            .find(&body)
                            .into_iter()
                            .filter_map(|found| found.as_str().map(|account| account.to_string()))
                            .collect::<HashSet<String>>();
                        let select_accounts_map = SELECT_ACCOUNTS.read().await;
                        if let Some(select_accounts) = select_accounts_map.get(name.as_ref()) {
                            unfiltered
                                .into_iter()
                                .filter(|account| select_accounts.contains(account))
                                .collect::<HashSet<String>>()
                        } else {
                            unfiltered
                        }
                    })
                }),
                RatelimitBucket::IP => Box::new(|(_, req, _, _)| {
                    Box::pin(async move { HashSet::from([req.ip.to_string()]) })
                }),
                RatelimitBucket::Sender => Box::new(|(name, _, body, _)| {
                    Box::pin(async move {
                        let selector =
                            Selector::new("$.unpacked_trx.actions.*.authorization.*.actor")
                                .unwrap();
                        let unfiltered = selector
                            .find(&body)
                            .into_iter()
                            .filter_map(|found| found.as_str().map(|actor| actor.to_string()))
                            .collect::<HashSet<String>>();
                        let select_accounts_map = SELECT_ACCOUNTS.read().await;
                        if let Some(select_accounts) = select_accounts_map.get(name.as_ref()) {
                            unfiltered
                                .into_iter()
                                .filter(|account| select_accounts.contains(account))
                                .collect::<HashSet<String>>()
                        } else {
                            unfiltered
                        }
                    })
                }),
                RatelimitBucket::Table => Box::new(|(name, req, body, _)| {
                    Box::pin(async move {
                        let unfiltered = if req.uri.path() == "/v1/chain/get_table_rows"
                            || req.uri.path() == "/v1/chain/get_table_by_scope"
                        {
                            let contract_opt = body.get("code").and_then(|val| val.as_str());
                            let table_opt = body.get("table").and_then(|val| val.as_str());
                            match (contract_opt, table_opt) {
                                (Some(contract), Some(table)) => {
                                    HashSet::from([format!("{}::{}", contract, table)])
                                }
                                _ => HashSet::new(),
                            }
                        } else {
                            HashSet::new()
                        };
                        let select_accounts_map = SELECT_ACCOUNTS.read().await;
                        let filtered =
                            if let Some(select_accounts) = select_accounts_map.get(name.as_ref()) {
                                unfiltered
                                    .into_iter()
                                    .filter(|account| select_accounts.contains(account))
                                    .collect::<HashSet<String>>()
                            } else {
                                unfiltered
                            };
                        filtered
                            .into_iter()
                            .map(|table| format!("{}::{}", req.ip.to_string(), table))
                            .collect::<HashSet<String>>()
                    })
                }),
            },
            Box::new(move |_| Box::pin(async move { ratelimit.limit })),
            match ratelimit.limit_on {
                RatelimitType::Attempt => {
                    IncrementMode::Before(Box::new(|_| Box::pin(async move { 1 })))
                }
                RatelimitType::Failure => IncrementMode::After(Box::new(|(_, _, res, _)| {
                    Box::pin(async move {
                        if res.1.is_success() {
                            0
                        } else {
                            1
                        }
                    })
                })),
            },
            None,
            ratelimit.window_duration,
        ));
    }

    // Bound how much traffic one client can steer to one node name. Over the
    // ceiling the pin is dropped and the request takes the routing mode, so the
    // request is answered and the response names the node that answered it.
    if config.pinned_window_seconds == 0 {
        return Err("pinned_window_seconds must be greater than 0.".into());
    }
    firewall = firewall.set_pin_limiter(PinLimiter::new(
        config.pinned_requests_per_window,
        config.pinned_window_seconds,
    ));

    let push_nodes = build_node_set(config.push_nodes)?;

    let mut push_nodes_guard = PUSH_NODES.write().await;
    *push_nodes_guard = push_nodes.clone();
    drop(push_nodes_guard);

    let get_nodes = build_node_set(config.get_nodes)?;

    let mut get_nodes_guard = GET_NODES.write().await;
    *get_nodes_guard = get_nodes.clone();
    drop(get_nodes_guard);

    let nodes: HashSet<Url> = get_nodes
        .iter()
        .chain(push_nodes.iter())
        .map(|node| node.url.clone())
        .collect();

    firewall = firewall.add_matching_rule(Box::new(move |(req, _, _, _)| {
        Box::pin(async move {
            if GET_ENDPOINTS.contains(req.uri.path()) {
                return GET_NODES.read().await.clone();
            } else if PUSH_ENDPOINTS.contains(req.uri.path()) {
                return PUSH_NODES.read().await.clone();
            }
            HashSet::new()
        })
    }));

    if let Some(healthcheck) = config.healthcheck {
        {
            let mut healthcheck_guard = HEALTH_CHECKER.write().await;
            *healthcheck_guard = Some(
                HealthChecker::start(
                    nodes.into_iter().collect(),
                    Duration::seconds(healthcheck.interval as i64),
                    Duration::seconds(healthcheck.grace_period as i64),
                )
                .await,
            );
        }
        firewall = firewall.add_matching_rule(Box::new(move |(_, _, _, nodes)| {
            Box::pin(async move {
                let healthcheck_guard = HEALTH_CHECKER.read().await;
                if let Some(ref h) = *healthcheck_guard {
                    h.filter_healthy_urls(nodes).await
                } else {
                    nodes
                }
            })
        }));
    }

    Ok(firewall)
}

#[cfg(test)]
mod tests {
    use core::time;
    use std::thread;

    use chrono::Utc;
    use hyper::StatusCode;
    use reqwest::Client;
    use serde_json::from_str;

    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn parses_body() {
        let _ = env_logger::builder().is_test(true).try_init();

        let default_config = include_str!("../test-configs/basic.toml");
        let config =
            toml::from_str::<Config>(default_config).expect("Default config contains an error");
        let firewall = from_config(config)
            .await
            .expect("Default config unable to build");

        tokio::spawn(async move {
            let err = firewall.build().run().await;
            panic!("Error!: {:?}", err);
        });
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Chain id is correct from get_block_info
        let client = Client::new();
        let result = client
            .post("http://127.0.0.1:3000/v1/chain/get_block_info")
            .body("{\"block_num\":100}")
            .send()
            .await;
        let response = result.expect("Encountered error getting info");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.expect("Error while getting bytes");
        let json_body = from_str::<serde_json::Value>(&body).expect("response not json");
        if let Some(id) = json_body
            .as_object()
            .and_then(|map| map.get("id").and_then(|o| o.as_str()))
        {
            assert_eq!(
                id,
                "0000006492871283c47f6ef57b00cf534628eb818c34deb87ea68a3557254c6b"
            );
        } else {
            panic!("invalid body")
        }

        // table ratelimit is applied successfully
        for _ in 0..2 {
            let client = Client::new();
            let result = client
                .post("http://127.0.0.1:3000/v1/chain/get_table_rows")
                .body("{\"scope\":\"mjurenka.ab\",\"code\":\"eosio.token\",\"table\":\"accounts\"}")
                .send()
                .await;
            let response = result.expect("Encountered error getting table");
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.text().await.expect("Error while getting bytes");
            let json_body = from_str::<serde_json::Value>(&body).expect("response not json");
            if let Some(rows) = json_body
                .as_object()
                .and_then(|map| map.get("rows").and_then(|o| o.as_array()))
            {
                assert_eq!(rows.len(), 0);
            } else {
                panic!("invalid body")
            }
        }

        let client = Client::new();
        let result = client
            .post("http://127.0.0.1:3000/v1/chain/get_table_rows")
            .body("{\"scope\":\"mjurenka.ab\",\"code\":\"eosio.token\",\"table\":\"accounts\"}")
            .send()
            .await;
        let response = result.expect("Encountered error getting table");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // table ratelimit does not apply for out of scope table
        let client = Client::new();
        let result = client
            .post("http://127.0.0.1:3000/v1/chain/get_table_rows")
            .body("{\"scope\":\"mjurenka.ab\",\"code\":\"eosio.token\",\"table\":\"stat\"}")
            .send()
            .await;
        let response = result.expect("Encountered error getting table");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await.expect("Error while getting bytes");
        let json_body = from_str::<serde_json::Value>(&body).expect("response not json");
        if let Some(rows) = json_body
            .as_object()
            .and_then(|map| map.get("rows").and_then(|o| o.as_array()))
        {
            assert_eq!(rows.len(), 0);
        } else {
            panic!("invalid body")
        }
    }
}

#[cfg(test)]
mod node_tests {
    use super::*;

    #[test]
    fn rejects_two_entries_for_one_origin() {
        let nodes = vec![
            Node {
                name: "a".into(),
                url: "http://node:8888/?alias=a".into(),
                weight: Some(1),
                pinnable: true,
            },
            Node {
                name: "b".into(),
                url: "http://node:8888/?alias=b".into(),
                weight: Some(1),
                pinnable: true,
            },
        ];
        assert!(build_node_set(nodes).is_err());
    }

    #[test]
    fn a_node_without_the_key_is_pinnable() {
        let config = toml::from_str::<Config>(
            "routing_mode = \"round_robin\"\naddress = \"127.0.0.1:3000\"\npush_nodes = []\nratelimit = []\n\n[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9001/\"\n",
        )
        .expect("test config contains an error");
        assert!(config.get_nodes[0].pinnable);
    }

    #[test]
    fn a_node_can_turn_pinnable_off() {
        let config = toml::from_str::<Config>(
            "routing_mode = \"round_robin\"\naddress = \"127.0.0.1:3000\"\npush_nodes = []\nratelimit = []\n\n[[get_nodes]]\nname = \"a\"\nurl = \"http://127.0.0.1:9001/\"\npinnable = false\n",
        )
        .expect("test config contains an error");
        assert!(!config.get_nodes[0].pinnable);
    }

    #[test]
    fn rejects_two_pinnable_entries_with_one_name() {
        let nodes = vec![
            Node {
                name: "a".into(),
                url: "http://127.0.0.1:9001/".into(),
                weight: None,
                pinnable: true,
            },
            Node {
                name: "a".into(),
                url: "http://127.0.0.1:9002/".into(),
                weight: None,
                pinnable: true,
            },
        ];
        assert!(build_node_set(nodes).is_err());
    }

    #[test]
    fn rejects_a_pinnable_name_outside_the_charset() {
        let nodes = vec![Node {
            name: "local rpc".into(),
            url: "http://127.0.0.1:9001/".into(),
            weight: None,
            pinnable: true,
        }];
        assert!(build_node_set(nodes).is_err());
    }

    #[test]
    fn accepts_an_unpinnable_name_outside_the_charset() {
        let nodes = vec![Node {
            name: "local rpc".into(),
            url: "http://127.0.0.1:9001/".into(),
            weight: None,
            pinnable: false,
        }];
        assert!(build_node_set(nodes).is_ok());
    }

    #[test]
    fn accepts_a_repeated_name_when_one_entry_is_unpinnable() {
        let nodes = vec![
            Node {
                name: "a".into(),
                url: "http://127.0.0.1:9001/".into(),
                weight: None,
                pinnable: true,
            },
            Node {
                name: "a".into(),
                url: "http://127.0.0.1:9002/".into(),
                weight: None,
                pinnable: false,
            },
        ];
        assert_eq!(build_node_set(nodes).expect("set rejected").len(), 2);
    }
}
