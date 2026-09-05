
# antelope-firewall: A combination Ratelimiter/Firewall/Load Balancer for Antelope RPC nodes

This repo contains two crates, antelope-firewall and antelope-firewall-lib. antelope-firewall-lib is a framework that allows a developer to more easily write their own ratelimiter, and antelope-firewall is a simple cli wrapper for the basic configuration of antelope-firewall-lib.

Features:
  - Load balance to multiple get and push RPC nodes through either weighted round robin, weighted random, or weighted least connected.
  - Filter out requests by IP, or target account (allow or denylist) for transactions.
  - Ratelimit requests using [sliding window algorithm](https://medium.com/@m-elbably/rate-limiting-the-sliding-window-algorithm-daa1d91e6196#:~:text=The%20Sliding%20Window%20Algorithm%20is,rate%20limiting%20in%20various%20applications.) by request IP, or target account or authorizer for transactions.
  - Prometheus exporter for remote monitoring

Non-features:
  - Does not unwrap SSL requests. We do not replace Nginx and HAProxy solutions, we recommend you place this behind HAProxy to deal with SSL certificate, then forward requests to antelope-firewall.

# Running

## With Docker

1. Clone the repo and edit the `docker-compose.yml` file to suit your needs. If you decide to change the firewall or prometheus ports in the config you must also change which ports are exposed in the `config.toml`

2. Ensure a config file exists at `/etc/antelope-firewall/config.toml` (or whatever your setup is in the docker compose file). An example config file with documentation exists as `default_config.toml`. You cand find more info about how to edit the config in the ["Configure" section of this document.](https://github.com/animuslabs/antelope-firewall?tab=readme-ov-file#configure)

3. Build the docker image. `docker compose build`

4. Run docker. `docker compose up -d`

## Without Docker

1. Ensure you have the following dependencies installed
```
sudo apt install openssl
```

2. Go to the [Github releases page](adb) and download the most recent *.deb file. Install with `sudo dpkg -i antelope-firewall_*.deb` This will install antelope-firewall as a binary and create the systemd service `antelope-firewall`.

3. You will then need to edit the config file at `/etc/antelope-firewall/config.toml` as described in the ["Configure" section of this document.](https://github.com/animuslabs/antelope-firewall?tab=readme-ov-file#configure)

4. Once you have a config file, enable and start the service using `systemctl enable antelope-firewall` and `systemctl start antelope-firewall`

### Prometheus

This firewall runs a Prometheus exporter on a port configurable in the config. It is recommended that you limit which servers can connect to this port via an nftables rule.

# Configuring
The file `default_config.toml` contains default settings which will work for most users. It does not filter out anything, and sets a ratelimiter that will only allow a given IP to submit transactions until it sends 5 failing requests in a minute.

## Request body size limit

By default the firewall rejects requests with a body larger than 64 KB (65536 bytes) with a `413 Payload Too Large` response. This is sufficient for most RPC traffic but too small for `set_contract` deployments. To raise the limit, add `max_request_body_size` to the top level of your config:

```toml
# Allow up to 4 MB request bodies (e.g. for contract deployments)
max_request_body_size = 4194304
```

If omitted, the default of 65536 (64 KB) applies.

## Node configuration

The most important thing to change is the list of nodes that the firewall will delegate requests to. For example purposes the following is used:

```
[[push_nodes]]
name = "push_one"
url = "http://127.0.0.1:5000"
weight = 1

[[get_nodes]]
name = "get_one"
url = "http://127.0.0.1:5001"
weight = 1

[[get_nodes]]
name = "get_two"
url = "http://127.0.0.1:5002"
weight = 1

[[get_nodes]]
name = "get_three"
url = "http://127.0.0.1:5003"
weight = 1
```

This will result in having the firewall proxy "read" requests to three urls, and "write" requests to one url. A full list of which requests are "read" or "write" is included in the comments of `default_config.toml`. You will very likely need to edit this based on your setup. For example, if you wanted to add another url that can be used as a proxy, simply duplicate the first `[[push_nodes]]` section and edit the respective entries. Weight corresponds to how much a node will be favored when it comes to selecting a destination for a request. Two pinnable entries of the same list cannot share a name, and no url can appear twice in one list; a name may appear in both lists, which is how one node serves reads and writes.

### Upstream affinity

Every response to a read endpoint from a pinnable node carries the header `X-Antelope-Upstream: <name>`, where the name is the node's `name` from `get_nodes`. The response also lists that header in `Access-Control-Expose-Headers`, so a browser can read it cross-origin. A client that wants the same node again sends `?upstream=<name>` on its next read request, and the firewall routes to that node when the name matches a node that accepts the path, is pinnable, and the health checker currently marks healthy. A name that matches nothing eligible is not an error: the request takes the routing mode and the response names the node that answered it.

Affinity applies to read endpoints only. A push response carries neither header, and the parameter is ignored there.

```toml
[[get_nodes]]
name = "greymass"
url = "https://eos.greymass.com"
# An entry that is itself a load balancer sets pinnable = false, because the
# name identifies no single node. The default is true.
pinnable = false
```

A pinnable name can carry letters, digits, and the characters `.`, `_` and `-`, so that it travels unchanged as a header value and as a query value.

One client cannot hold a node by name for an unbounded share of the traffic. The firewall counts pinned requests per client IP and node name in a fixed window, and over the ceiling it drops the pin rather than the request: the routing mode picks, and the response names the node that answered. The count is exact, so the ceiling is the number of pinned requests one client can send for one name inside a window. Both keys are optional and default to 30 requests per 60 seconds. The name `pinned` is reserved for this counter and cannot name a `[[ratelimit]]` entry.

```toml
pinned_requests_per_window = 30
pinned_window_seconds = 60
```

# Testing
All tests can be run with `cargo test` in the root of the repository

## Building
### Dependencies
`sudo apt install openssl libssl-dev`
### Build
`cargo build --release --bin antelope-firewall`
