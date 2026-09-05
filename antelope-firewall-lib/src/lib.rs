use std::{
    collections::HashSet,
    future::Future,
    hash::{Hash, Hasher},
    net::IpAddr,
    pin::Pin,
    sync::Arc,
};

use hyper::{HeaderMap, StatusCode, Uri};
use reqwest::Url;
use serde_json::Value;

pub mod firewall_builder;

pub mod api_responses;
pub mod config;
pub mod de;
pub mod filter;
pub mod healthcheck;
pub mod json_data_cache;
pub mod matching_engine;
pub mod prometheus;
pub mod ratelimiter;

mod util;

// One upstream node the firewall can route to. The name and the pinnable flag
// come from the node's config entry, so a picked entry can name itself on the
// response. Two entries are the same node when they carry the same URL.
#[derive(Debug, Clone, Eq)]
pub struct NodeEntry {
    pub url: Url,
    pub weight: u64,
    pub name: String,
    pub pinnable: bool,
}

impl PartialEq for NodeEntry {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Hash for NodeEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

#[derive(Debug)]
pub struct RequestInfo {
    headers: HeaderMap,
    uri: Uri,
    ip: IpAddr,
}

impl RequestInfo {
    pub fn new(headers: HeaderMap, uri: Uri, ip: IpAddr) -> Self {
        RequestInfo { headers, uri, ip }
    }
}

pub type Fut<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

pub type FilterFn = dyn Fn((Arc<RequestInfo>, Arc<Value>, Arc<Value>)) -> Fut<bool> + Send + Sync;
pub type MapFn<T> = dyn Fn((Arc<RequestInfo>, Arc<Value>, Arc<Value>)) -> Fut<T> + Send + Sync;
pub type RatelimiterMapFn<T> =
    dyn Fn((Arc<String>, Arc<RequestInfo>, Arc<Value>, Arc<Value>)) -> Fut<T> + Send + Sync;
pub type PostMapFn<T> = dyn Fn(
        (
            Arc<RequestInfo>,
            Arc<Value>,
            Arc<(Value, StatusCode)>,
            Arc<Value>,
        ),
    ) -> Fut<T>
    + Send
    + Sync;
pub type MatchingFn = dyn Fn((Arc<RequestInfo>, Arc<Value>, Arc<Value>, HashSet<NodeEntry>)) -> Fut<HashSet<NodeEntry>>
    + Send
    + Sync;
