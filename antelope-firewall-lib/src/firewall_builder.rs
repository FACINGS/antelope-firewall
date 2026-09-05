use itertools::Itertools;
use prometheus_exporter::prometheus::core::{AtomicF64, GenericCounter};
use prometheus_exporter::prometheus::register_counter;
use rand::distributions::WeightedIndex;
use rand::prelude::Distribution;
use reqwest::Url;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use log::{debug, error as err, info, warn};

use crate::config::GET_ENDPOINTS;
use crate::de::Transaction;
use crate::matching_engine::MatchingEngine;
use crate::prometheus::{
    CLIENT_ERROR_NODE_RESPONSES, REQUESTS_FAILED_TO_ROUTE, REQUESTS_RECEIVED,
    SERVER_ERROR_NODE_RESPONSES, SUCCESS_NODE_RESPONSES,
};
use crate::util::{
    full, get_blocked_response, get_error_response, get_options_response, get_ratelimit_response,
};
use crate::{filter::Filter, ratelimiter::RateLimiter};
use crate::{MatchingFn, NodeEntry, RequestInfo};

use hyper::body::{Body, Bytes};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use itertools::FoldWhile::{Continue, Done};

lazy_static::lazy_static! {
    static ref MATCHING_COUNTERS: RwLock<HashMap<String, (
        GenericCounter<AtomicF64>,
        GenericCounter<AtomicF64>,
        GenericCounter<AtomicF64>,
        GenericCounter<AtomicF64>
    )>> = RwLock::new(HashMap::new());
}

pub enum RoutingModeState {
    RoundRobin(HashMap<String, AtomicU64>),
    LeastConnected(HashMap<String, AtomicU64>),
    Random,
}

impl RoutingModeState {
    pub fn base_round_robin() -> Self {
        RoutingModeState::RoundRobin(HashMap::new())
    }
    pub fn base_least_connected() -> Self {
        RoutingModeState::LeastConnected(HashMap::new())
    }
    pub fn base_random() -> Self {
        RoutingModeState::Random
    }
}

pub struct AntelopeFirewall {
    filters: Vec<Filter>,
    ratelimiters: Vec<RateLimiter>,
    matching_engine: MatchingEngine,
    routing_mode: RoutingModeState,
    socket_addr: SocketAddr,
    max_request_body_size: u64,
    client_ip_header: Option<String>,
    pin_limiter: Option<PinLimiter>,
}

#[derive(Error, Debug, Clone)]
pub enum AntelopeFirewallError {
    #[error("Failed to start a server on socket: `{1}`, received error: `{0}`")]
    StartingServerFailed(String, SocketAddr),
    #[error("Failed to accept a new TCP connection, received error: `{0}`")]
    AcceptTCPConnectionFailed(String),
    #[error("Failed to parse the request body, received error: `{0}`")]
    ParseBodyFailed(String),
    #[error("Failed to parse the response body, received error: `{0}`")]
    ParseResponseBodyFailed(String),
}

use AntelopeFirewallError::*;

// Ceiling on the keys the pin limiter holds. A key is one client address and
// one node name, so a flood of addresses would otherwise grow the map without
// limit.
const MAX_PIN_KEYS: usize = 10_000;

// Query parameter a client uses to ask for the upstream that answered its
// previous request. The value is compared for exact equality against the
// configured node names and is never used to build a URL.
// Response header naming the upstream that answered.
const UPSTREAM_HEADER: &str = "X-Antelope-Upstream";
const EXPOSE_HEADERS: &str = "Access-Control-Expose-Headers";

// Two urls address the same node when the scheme, the host and the port match.
fn same_origin(chosen: &Url, answered: &Url) -> bool {
    chosen.scheme() == answered.scheme()
        && chosen.host_str() == answered.host_str()
        && chosen.port_or_known_default() == answered.port_or_known_default()
}

// Read the requested upstream name out of a query string.
fn upstream_param(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("upstream="))
        .filter(|name| !name.is_empty())
}

// The upstream name a request asks for. Only a read endpoint can ask: a push
// carries no corroboration, and a client that steers a transaction to a node it
// names is a lever this firewall does not offer.
pub(crate) fn requested_upstream(request_info: &RequestInfo) -> Option<&str> {
    if !GET_ENDPOINTS.contains(request_info.uri.path()) {
        return None;
    }
    upstream_param(request_info.uri.query())
}

// Build the value of the expose header, keeping what the upstream sent.
fn expose_header_value(existing: Vec<&str>) -> String {
    let mut entries: Vec<&str> = existing
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect();
    if !entries
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(UPSTREAM_HEADER))
    {
        entries.push(UPSTREAM_HEADER);
    }
    entries.join(", ")
}

// Pick the client IP from a configured forwarded header, taking the first entry
// of a comma-separated list (X-Forwarded-For style) and falling back to the
// socket peer when the header is unset, absent, or unparseable.
fn client_ip_from_headers(
    header_name: Option<&str>,
    headers: &hyper::HeaderMap,
    peer: IpAddr,
) -> IpAddr {
    let Some(name) = header_name else {
        return peer;
    };
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|first| first.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

// Exact fixed window counter over the pinned requests of one client address
// and node name. The generic rate limiter is a weighted sliding window that
// admits up to twice its limit, which is not the ceiling this config documents.
pub struct PinLimiter {
    limit: u64,
    window: std::time::Duration,
    state: tokio::sync::Mutex<HashMap<String, (std::time::Instant, u64)>>,
}

impl PinLimiter {
    pub fn new(limit: u64, window_seconds: u64) -> Self {
        PinLimiter {
            limit,
            window: std::time::Duration::from_secs(window_seconds),
            state: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    // Admit one more pinned request for this key inside the current window.
    pub async fn admits(&self, key: String) -> bool {
        if self.limit == 0 {
            return false;
        }
        let now = std::time::Instant::now();
        let mut state = self.state.lock().await;
        let expired = match state.get(&key) {
            Some((started, _)) => now.duration_since(*started) >= self.window,
            None => true,
        };
        if expired {
            // A key the map already holds reuses its own slot. A key it does
            // not hold needs room, and a full map of live counters refuses the
            // pin rather than evicting a counter that still bounds a client.
            if !state.contains_key(&key) && !Self::make_room(&mut state, now, self.window) {
                return false;
            }
            state.insert(key, (now, 1));
            return true;
        }
        let counted = state.get_mut(&key).expect("the key was read a moment ago");
        if counted.1 >= self.limit {
            return false;
        }
        counted.1 += 1;
        true
    }

    // Sweep the windows that ended and report whether the map has room for one
    // more key.
    fn make_room(
        state: &mut HashMap<String, (std::time::Instant, u64)>,
        now: std::time::Instant,
        window: std::time::Duration,
    ) -> bool {
        if state.len() < MAX_PIN_KEYS {
            return true;
        }
        state.retain(|_, (started, _)| now.duration_since(*started) < window);
        state.len() < MAX_PIN_KEYS
    }
}

impl AntelopeFirewall {
    pub fn new(
        routing_mode: RoutingModeState,
        socket_addr: SocketAddr,
        max_request_body_size: u64,
        client_ip_header: Option<String>,
    ) -> Self {
        AntelopeFirewall {
            filters: Vec::new(),
            ratelimiters: Vec::new(),
            matching_engine: MatchingEngine::new(),
            routing_mode,
            socket_addr,
            max_request_body_size,
            client_ip_header,
            pin_limiter: None,
        }
    }

    // Resolve the client IP used for rate limiting and block lists. When a
    // trusted-proxy header is configured, prefer its value and fall back to the
    // socket peer when the header is absent or unparseable.
    fn resolve_client_ip(&self, headers: &hyper::HeaderMap, peer: IpAddr) -> IpAddr {
        client_ip_from_headers(self.client_ip_header.as_deref(), headers, peer)
    }
    pub fn add_filter(mut self, filter: Filter) -> Self {
        self.filters.push(filter);
        self
    }
    pub fn add_ratelimiter(mut self, ratelimiter: RateLimiter) -> Self {
        self.ratelimiters.push(ratelimiter);
        self
    }
    pub fn set_pin_limiter(mut self, limiter: PinLimiter) -> Self {
        self.pin_limiter = Some(limiter);
        self
    }
    pub fn add_matching_rule(mut self, rule: Box<MatchingFn>) -> Self {
        self.matching_engine.add_rule(rule);
        self
    }

    pub fn build(self) -> Arc<Self> {
        Arc::new(self)
    }
    pub async fn run(self: Arc<Self>) -> Result<(), AntelopeFirewallError> {
        info!("Starting server on {}", self.socket_addr);

        let listener = TcpListener::bind(self.socket_addr).await.map_err(|e| {
            AntelopeFirewallError::StartingServerFailed(e.to_string(), self.socket_addr)
        })?;

        // TODO: Start Prometheus

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| AntelopeFirewallError::AcceptTCPConnectionFailed(e.to_string()))?;

            let new_self = Arc::clone(&self);
            tokio::task::spawn(async move {
                let address = stream
                    .peer_addr()
                    .map(|addr| addr.ip())
                    .unwrap_or(IpAddr::from([127, 0, 0, 1]));

                if let Err(err) = http1::Builder::new()
                    .serve_connection(stream, service_fn(|r| new_self.handle_request(r, address)))
                    .await
                {
                    err!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
        ip: IpAddr,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, AntelopeFirewallError> {
        REQUESTS_RECEIVED.inc();

        // Parse thr request, try to put body into JSON
        let (parts, body) = req.into_parts();
        let ip = self.resolve_client_ip(&parts.headers, ip);
        info!("Received Request from {} for url {}", ip, parts.uri);

        // Check size hint, return 413 error if too big
        let max = body.size_hint().upper().unwrap_or(u64::MAX);
        if max > self.max_request_body_size {
            let mut resp = Response::new(full("Body too big"));
            *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
            info!("Request from {} too large", ip);
            return Ok(resp);
        }

        let request_info = Arc::new(RequestInfo::new(
            parts.headers.clone(),
            parts.uri.clone(),
            ip,
        ));
        let body_bytes = match parts.method {
            Method::POST => {
                let body_bytes_result = body.collect().await;
                match body_bytes_result {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        info!(
                            "Error occurred while parsing request body: {}",
                            e.to_string()
                        );
                        return Ok(get_error_response(full(
                            "Error occurred while parsing request body.",
                        )));
                    }
                }
            }
            _ => Bytes::new(),
        };

        let body_json = Arc::new(match parts.method {
            Method::POST if body_bytes.len() == 0 => serde_json::Value::Null,
            Method::POST => match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                Ok(mut parsed) => {
                    if let Some(root) = parsed.as_object_mut() {
                        let mut cloned = root.clone();
                        let trx_root_opt = if let Some(m) = root.get_mut("transaction") {
                            m.as_object_mut()
                        } else {
                            Some(&mut cloned)
                        };

                        if let Some(hex) = trx_root_opt
                            .and_then(|t| t.get_mut("packed_trx"))
                            .and_then(|e| e.as_str())
                            .and_then(|s| hex::decode(s).ok())
                        {
                            if let Some(serialized) = crate::de::from_bytes::<Transaction>(&hex[..])
                                .ok()
                                .and_then(|trx| serde_json::to_value(&trx).ok())
                            {
                                root.insert("unpacked_trx".into(), serialized);
                            }
                        }
                    }
                    parsed
                }
                Err(e) => {
                    info!("Unable to parse POST request body as JSON: {}", e);
                    return Ok(get_error_response(full("Unable to parse body as JSON.")));
                }
            },
            _ => serde_json::Value::Null,
        });

        // Check if the request should be filtered out
        for filter in &self.filters {
            if !filter
                .should_request_pass(Arc::clone(&request_info), Arc::clone(&body_json))
                .await
            {
                info!(
                    "Blocking {}'s request to {} because of filter rule.",
                    ip, parts.uri
                );
                return Ok(get_blocked_response());
            }
        }

        if parts.method == Method::OPTIONS {
            return Ok(get_options_response());
        }

        // Check if the request should be rate limited
        for ratelimiter in &self.ratelimiters {
            if !ratelimiter
                .should_request_pass(Arc::clone(&request_info), Arc::clone(&body_json))
                .await
            {
                info!(
                    "Blocking {}'s request to {} because of ratelimiter {}",
                    ip, parts.uri, ratelimiter.name
                );
                return Ok(get_ratelimit_response(ratelimiter.get_window_duration()));
            }
        }

        // Find end nodes that can accept the request with the matching engine
        let urls = self
            .matching_engine
            .find_matching_urls(Arc::clone(&request_info), Arc::clone(&body_json))
            .await;
        if urls.len() == 0 {
            info!("Unable to route {}'s request to {}", ip, parts.uri);
            REQUESTS_FAILED_TO_ROUTE.inc();
            return Ok(get_error_response(full(
                "Failed to find a route for your request.",
            )));
        }

        // A client can ask for the node that answered its previous request. The
        // name is honored only when it matches a pinnable node of the matched,
        // health filtered set. An unknown, unhealthy or unpinnable name is not
        // an error and falls through to the routing mode.
        let pinned = requested_upstream(&request_info).and_then(|name| {
            urls.iter()
                .find(|node| node.pinnable && node.name == name)
                .cloned()
        });

        // One client cannot hold a node by name for more than its share of a
        // window. Over the ceiling the pin drops and the routing mode picks, so
        // the answer still names the node that served it.
        let pinned = match (pinned, &self.pin_limiter) {
            (Some(node), Some(limiter)) => {
                if limiter.admits(format!("{}::{}", ip, node.name)).await {
                    Some(node)
                } else {
                    info!(
                        "Dropping the upstream pin for {}'s request to {}",
                        ip, parts.uri
                    );
                    None
                }
            }
            (node, _) => node,
        };

        let chosen = match pinned {
            Some(node) => Some(node),
            None => match self.routing_mode {
                RoutingModeState::LeastConnected(ref counts) => Some(
                    urls.into_iter()
                        .map(|node| {
                            let load = counts
                                .get(&node.url.host().unwrap().to_string())
                                .map(|a| a.load(std::sync::atomic::Ordering::SeqCst))
                                .unwrap_or(1) as f32
                                / node.weight as f32;
                            (node, load)
                        })
                        .min_by(|(_, w1), (_, w2)| {
                            w1.partial_cmp(w2).unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .expect("There were no possible urls even though it was checked earlier")
                        .0,
                ),
                RoutingModeState::RoundRobin(ref counts) => {
                    let count = counts
                        .get(request_info.uri.path())
                        .map(|a| a.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
                        .unwrap_or(0);

                    let modulated = count % urls.iter().map(|node| node.weight).sum::<u64>();
                    urls.iter()
                        .fold_while(
                            (modulated, Option::<NodeEntry>::None),
                            |(weights_left, s), node| {
                                if weights_left < node.weight {
                                    Done((0, Some(node.clone())))
                                } else {
                                    Continue((
                                        weights_left.checked_sub(node.weight).unwrap_or(0),
                                        s,
                                    ))
                                }
                            },
                        )
                        .into_inner()
                        .1
                }
                RoutingModeState::Random => {
                    let nodes: Vec<NodeEntry> = urls.into_iter().collect();
                    let weights: Vec<u64> = nodes.iter().map(|node| node.weight).collect();
                    let dist = WeightedIndex::new(weights).unwrap();
                    Some(nodes[dist.sample(&mut rand::thread_rng())].clone())
                }
            },
        };

        let mut url = chosen
            .as_ref()
            .map(|node| node.url.clone())
            .unwrap_or_else(|| Url::parse("https://127.0.0.1/").unwrap());

        let prometheus_url_name = url
            .host_str()
            .unwrap_or("unknown")
            .replace(|c: char| c != '_' && !c.is_alphanumeric(), "_");
        {
            let guard = MATCHING_COUNTERS.read().await;
            if !guard.contains_key(&prometheus_url_name) {
                drop(guard);
                let processed_counter = register_counter!(
                    format!("node_{}_processed", prometheus_url_name),
                    format!("Number of requests sent to node {}", prometheus_url_name)
                )
                .unwrap();
                let success_counter = register_counter!(
                    format!("node_{}_success", prometheus_url_name),
                    format!(
                        "Number of requests sent to node {} that returned success",
                        prometheus_url_name
                    )
                )
                .unwrap();
                let client_error_counter = register_counter!(
                    format!("node_{}_client_error", prometheus_url_name),
                    format!(
                        "Number of requests sent to node {} that returned a 4** error",
                        prometheus_url_name
                    )
                )
                .unwrap();
                let server_error_counter = register_counter!(
                    format!("node_{}_server_error", prometheus_url_name),
                    format!(
                        "Number of requests sent to node {} that returned a 5** error",
                        prometheus_url_name
                    )
                )
                .unwrap();
                processed_counter.inc();

                let mut guard = MATCHING_COUNTERS.write().await;
                guard.insert(
                    prometheus_url_name.clone(),
                    (
                        processed_counter,
                        success_counter,
                        client_error_counter,
                        server_error_counter,
                    ),
                );
            } else {
                guard.get(&prometheus_url_name).unwrap().0.inc();
            }
        }

        // No allowlisted endpoint reads a query, so none is forwarded. The path
        // is set on its own because set_path percent encodes a question mark.
        url.set_path(parts.uri.path());
        url.set_query(None);

        // Send the request
        let mut headers = parts.headers;
        //headers.insert("X-Forwarded-For", ip.to_string().parse().unwrap());
        if let Some(host) = url.host_str() {
            headers.insert("Host", host.parse().unwrap());
        }

        info!("Forwarding {}'s request to {} to {}", ip, parts.uri, url);
        let client = reqwest::Client::builder()
            .deflate(true)
            .gzip(true)
            .redirect(reqwest::redirect::Policy::limited(50))
            .build()
            .unwrap();
        let node_result = client
            .post(url.clone())
            .headers(headers)
            .body(body_bytes)
            .send()
            .await;

        match node_result {
            Ok(response) => {
                let node_status = response.status();
                // A redirect can move the answer to another host, and that host
                // is not the node the header would name.
                let answered_by = response.url().clone();

                {
                    let guard = MATCHING_COUNTERS.read().await;
                    let (_, success_counter, client_error_counter, server_error_counter) =
                        guard.get(&prometheus_url_name).unwrap();
                    if node_status.is_success() {
                        SUCCESS_NODE_RESPONSES.inc();
                        success_counter.inc();
                    } else if node_status.is_client_error() {
                        CLIENT_ERROR_NODE_RESPONSES.inc();
                        client_error_counter.inc();
                    } else if node_status.is_server_error() {
                        SERVER_ERROR_NODE_RESPONSES.inc();
                        server_error_counter.inc();
                    }
                }

                // Respond to the client
                let mut client_res = Response::builder().status(response.status());
                client_res
                    .headers_mut()
                    .map(|h| h.clone_from(response.headers()));

                if let Some(headers) = client_res.headers_mut() {
                    // An upstream does not get to name itself, or to echo the
                    // name of a node it is not.
                    headers.remove(UPSTREAM_HEADER);
                    // A push answer names nothing: only a read is corroborated,
                    // and the name would tell a sender where its transaction went.
                    let names_upstream = GET_ENDPOINTS.contains(parts.uri.path());
                    if let Some(node) = chosen
                        .as_ref()
                        .filter(|node| node.pinnable && names_upstream)
                        .filter(|node| {
                            let same = same_origin(&node.url, &answered_by);
                            if !same {
                                warn!(
                                    "Node {} redirected to {}, so the response names no upstream",
                                    node.url, answered_by
                                );
                            }
                            same
                        })
                    {
                        match hyper::header::HeaderValue::from_str(&node.name) {
                            Ok(name) => {
                                let sent: Vec<String> = headers
                                    .get_all(EXPOSE_HEADERS)
                                    .iter()
                                    .map(|value| value.to_str().map(|text| text.to_string()).ok())
                                    .collect::<Option<Vec<String>>>()
                                    .unwrap_or_default();
                                // A value the firewall cannot read is left where
                                // it is, and the name is exposed beside it.
                                let readable =
                                    sent.len() == headers.get_all(EXPOSE_HEADERS).iter().count();
                                headers.insert(UPSTREAM_HEADER, name);
                                let exposed = expose_header_value(
                                    sent.iter().map(|value| value.as_str()).collect(),
                                );
                                if let Ok(value) = hyper::header::HeaderValue::from_str(&exposed) {
                                    if readable {
                                        headers.remove(EXPOSE_HEADERS);
                                        headers.insert(EXPOSE_HEADERS, value);
                                    } else {
                                        headers.append(
                                            EXPOSE_HEADERS,
                                            hyper::header::HeaderValue::from_static(
                                                UPSTREAM_HEADER,
                                            ),
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Node name '{}' is not a valid header value: {}",
                                    node.name, e
                                );
                            }
                        }
                    }
                }

                let status = response.status();
                let response_bytes = response.bytes().await.unwrap();

                let returned_value = match serde_json::from_slice::<serde_json::Value>(
                    &response_bytes,
                ) {
                    Ok(val) => val,
                    Err(e) => {
                        info!("Unable to forward request to url: {}, received status: {}, encountered error: {}", url, status, e.to_string());
                        //let s = response_bytes.iter().map(|b| *b as char).collect::<String>().into()
                        //info!("First 100 chars of error response: {}", s.chars().take(100).collect::<String>());
                        return Ok(get_error_response(full("Error forwarding request.")));
                    }
                };
                let response_json = Arc::new((returned_value, node_status));

                // Update any ratelimiters that need to be notified on failure
                for ratelimiter in &self.ratelimiters {
                    if !ratelimiter.increment_mode.should_run_before_request() {
                        ratelimiter
                            .post_increment(
                                Arc::clone(&request_info),
                                Arc::clone(&body_json),
                                Arc::clone(&response_json),
                            )
                            .await;
                    }
                }
                info!("Sending response for {}'s request to {}", ip, parts.uri);

                let final_response = client_res.body(full(response_bytes)).unwrap();
                Ok(final_response)
            }
            Err(e) => {
                info!(
                    "Unable to forward request to url: {}, encountered error: {}",
                    url,
                    e.to_string()
                );
                Ok(get_error_response(full("Error forwarding request.")))
            }
        }
    }
}

#[cfg(test)]
mod client_ip_tests {
    use super::client_ip_from_headers;
    use hyper::HeaderMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 1, 0, 224))
    }

    #[test]
    fn falls_back_to_peer_when_header_not_configured() {
        let headers = HeaderMap::new();
        assert_eq!(client_ip_from_headers(None, &headers, peer()), peer());
    }

    #[test]
    fn uses_configured_header_value() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "66.249.66.1".parse().unwrap());
        assert_eq!(
            client_ip_from_headers(Some("cf-connecting-ip"), &headers, peer()),
            "66.249.66.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn takes_first_entry_of_forwarded_list() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.7, 162.158.1.1, 10.0.0.134".parse().unwrap(),
        );
        assert_eq!(
            client_ip_from_headers(Some("x-forwarded-for"), &headers, peer()),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn falls_back_to_peer_when_header_absent() {
        let headers = HeaderMap::new();
        assert_eq!(
            client_ip_from_headers(Some("cf-connecting-ip"), &headers, peer()),
            peer()
        );
    }

    #[test]
    fn falls_back_to_peer_on_unparseable_value() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        assert_eq!(
            client_ip_from_headers(Some("cf-connecting-ip"), &headers, peer()),
            peer()
        );
    }

    #[test]
    fn parses_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "2606:4700::1".parse().unwrap());
        assert_eq!(
            client_ip_from_headers(Some("cf-connecting-ip"), &headers, peer()),
            "2606:4700::1".parse::<IpAddr>().unwrap()
        );
    }
}

#[cfg(test)]
mod upstream_param_tests {
    use super::{expose_header_value, same_origin, upstream_param};
    use reqwest::Url;

    #[test]
    fn one_origin_answers_for_itself() {
        let node = Url::parse("http://127.0.0.1:8888/").unwrap();
        assert!(same_origin(
            &node,
            &Url::parse("http://127.0.0.1:8888/v1/chain/get_info").unwrap()
        ));
        assert!(!same_origin(
            &node,
            &Url::parse("http://127.0.0.1:9999/v1/chain/get_info").unwrap()
        ));
        assert!(!same_origin(
            &node,
            &Url::parse("https://127.0.0.1:8888/v1/chain/get_info").unwrap()
        ));
        assert!(!same_origin(
            &node,
            &Url::parse("http://example.test:8888/v1/chain/get_info").unwrap()
        ));
    }

    #[test]
    fn reads_the_name_from_a_query() {
        assert_eq!(
            upstream_param(Some("upstream=local-rpc")),
            Some("local-rpc")
        );
        assert_eq!(
            upstream_param(Some("foo=bar&upstream=local-rpc")),
            Some("local-rpc")
        );
    }

    #[test]
    fn reads_no_name_when_the_parameter_is_absent_or_empty() {
        assert_eq!(upstream_param(None), None);
        assert_eq!(upstream_param(Some("foo=bar")), None);
        assert_eq!(upstream_param(Some("upstream=")), None);
        assert_eq!(upstream_param(Some("upstreams=a")), None);
    }

    #[test]
    fn expose_value_appends_to_what_the_upstream_sent() {
        assert_eq!(expose_header_value(vec![]), "X-Antelope-Upstream");
        assert_eq!(
            expose_header_value(vec!["X-Foo"]),
            "X-Foo, X-Antelope-Upstream"
        );
        assert_eq!(
            expose_header_value(vec!["X-Foo, X-Bar", "X-Baz"]),
            "X-Foo, X-Bar, X-Baz, X-Antelope-Upstream"
        );
        assert_eq!(
            expose_header_value(vec!["x-antelope-upstream"]),
            "x-antelope-upstream"
        );
    }
}

#[cfg(test)]
mod pin_limiter_tests {
    use super::PinLimiter;

    #[tokio::test]
    async fn admits_exactly_the_ceiling_per_key() {
        let limiter = PinLimiter::new(2, 60);
        assert!(limiter.admits("198.51.100.7::b".into()).await);
        assert!(limiter.admits("198.51.100.7::b".into()).await);
        assert!(!limiter.admits("198.51.100.7::b".into()).await);
    }

    #[tokio::test]
    async fn counts_each_client_and_name_apart() {
        let limiter = PinLimiter::new(1, 60);
        assert!(limiter.admits("198.51.100.7::b".into()).await);
        assert!(!limiter.admits("198.51.100.7::b".into()).await);
        assert!(limiter.admits("203.0.113.9::b".into()).await);
        assert!(limiter.admits("198.51.100.7::c".into()).await);
    }

    #[tokio::test]
    async fn a_ceiling_of_zero_admits_nothing() {
        let limiter = PinLimiter::new(0, 60);
        assert!(!limiter.admits("198.51.100.7::b".into()).await);
    }

    #[tokio::test]
    async fn a_full_map_of_live_counters_refuses_a_new_key() {
        let limiter = PinLimiter::new(2, 60);
        for index in 0..super::MAX_PIN_KEYS {
            assert!(limiter.admits(format!("198.51.100.7::{}", index)).await);
        }
        assert!(!limiter.admits("203.0.113.9::b".into()).await);
        // The counter of a key the map holds is untouched by the refusal.
        assert!(limiter.admits("198.51.100.7::0".into()).await);
        assert!(!limiter.admits("198.51.100.7::0".into()).await);
    }

    #[tokio::test]
    async fn a_window_that_ended_starts_the_count_again() {
        let limiter = PinLimiter::new(1, 0);
        assert!(limiter.admits("198.51.100.7::b".into()).await);
        assert!(limiter.admits("198.51.100.7::b".into()).await);
    }
}
