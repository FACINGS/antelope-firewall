# Dockerfile
FROM rust

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release

ENTRYPOINT ["./target/release/antelope-firewall"]
CMD ["-c", "/etc/antelope-firewall/config.toml"]

EXPOSE 3000
EXPOSE 3001

