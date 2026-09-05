use std::{collections::HashSet, sync::Arc};

use serde_json::Value;

use crate::{MatchingFn, NodeEntry, RequestInfo};

pub struct MatchingEngine {
    rules: Vec<Box<MatchingFn>>,
}

impl MatchingEngine {
    pub fn new() -> Self {
        MatchingEngine { rules: Vec::new() }
    }

    /// Matching fn should append urls to the hashset
    pub fn add_rule(&mut self, rule: Box<MatchingFn>) {
        self.rules.push(rule);
    }

    pub async fn find_matching_urls(
        &self,
        request_info: Arc<RequestInfo>,
        body: Arc<Value>,
    ) -> HashSet<NodeEntry> {
        let mut urls = HashSet::new();
        for rule in &self.rules {
            urls = rule((
                Arc::clone(&request_info),
                Arc::clone(&body),
                Arc::new(Value::Null),
                urls,
            ))
            .await;
        }
        urls
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use hyper::{header::HeaderName, HeaderMap, Method, Uri};
    use reqwest::Url;
    use serde_json::Map;

    use super::*;

    fn node(name: &str, url: &str) -> NodeEntry {
        NodeEntry {
            url: Url::from_str(url).unwrap(),
            weight: 2,
            name: name.into(),
            pinnable: true,
        }
    }

    #[tokio::test]
    async fn accepts_multiple_rules() {
        let mut engine = MatchingEngine::new();
        engine.add_rule(Box::new(|(_, _, _, _)| {
            Box::pin(async { HashSet::from([node("a", "https://google.com/")]) })
        }));
        engine.add_rule(Box::new(|(_, _, _, _)| {
            Box::pin(async { HashSet::from([node("b", "http://facebook.com/")]) })
        }));
        engine.add_rule(Box::new(|(_, _, _, _)| {
            Box::pin(async { HashSet::from([node("c", "http://127.0.0.1:3030")]) })
        }));
        engine
            .find_matching_urls(
                Arc::new(RequestInfo::new(
                    HeaderMap::new(),
                    Uri::from_static("https://google.com/"),
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                )),
                Arc::new(Value::Object(Map::new())),
            )
            .await;
    }

    #[tokio::test]
    async fn calls_all_fns() {
        let mut engine = MatchingEngine::new();
        engine.add_rule(Box::new(|(request, _, _, mut existing)| {
            Box::pin(async move {
                match request
                    .headers
                    .get(hyper::header::HOST)
                    .map(|o| o.to_str().unwrap())
                {
                    Option::None => HashSet::from([]),
                    Option::Some(x) => {
                        if x == "Hello" {
                            existing.extend(HashSet::from([node("a", "https://google.com/")]));
                            existing
                        } else {
                            existing
                        }
                    }
                }
            })
        }));
        engine.add_rule(Box::new(|(request, _, _, mut existing)| {
            Box::pin(async move {
                match request
                    .headers
                    .get(hyper::header::HOST)
                    .map(|o| o.to_str().unwrap())
                {
                    Option::None => HashSet::from([]),
                    Option::Some(x) => {
                        if x == "Hello" {
                            existing.extend(HashSet::from([node("b", "https://facebook.com/")]));
                            existing
                        } else {
                            existing
                        }
                    }
                }
            })
        }));

        let mut headers = HeaderMap::new();
        headers.append(hyper::header::HOST, "Hello".parse().unwrap());

        let matched = engine
            .find_matching_urls(
                Arc::new(RequestInfo::new(
                    headers,
                    Uri::from_static("https://google.com/"),
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                )),
                Arc::new(Value::Object(Map::new())),
            )
            .await;
        assert_eq!(matched.len(), 2);
    }

    #[tokio::test]
    async fn no_rules_returns_empty() {
        let engine = MatchingEngine::new();

        let mut headers = HeaderMap::new();
        headers.append(hyper::header::HOST, "Hello".parse().unwrap());

        let matched = engine
            .find_matching_urls(
                Arc::new(RequestInfo::new(
                    headers,
                    Uri::from_static("https://google.com/"),
                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                )),
                Arc::new(Value::Object(Map::new())),
            )
            .await;
        assert_eq!(matched.len(), 0);
    }
}
