# LetsACME Examples

Lego/traefik requires the ACME server to use the HTTPS protocol, so all the following test cases use the HTTPS protocol. You can quickly start an HTTPS test server by running `docker compose up -d`.

Before starting the test, please ensure that the CA certificate is trusted by your system.

## Docker Compose

this example will show how letsacme works with other containers like **caddy** and **traefik**.

check [docker-compose.yaml](./docker-compose.yaml)

```bash
docker compose up -d
```

check Traefik Dashboard [https://traefik.localhost:9443](https://traefik.localhost:9443)

check Caddy Dashboard [https://caddy.localhost:8443](https://caddy.localhost:8443)

## Certbot

certbot use `REQUESTS_CA_BUNDLE` environment variable to trust the ca certificate.

```bash
cd examples
mkdir -p "./certbot"
export REQUESTS_CA_BUNDLE="./letsacme/acme_ca.crt"
certbot certonly --standalone --agree-tos -m "example@exapmle.com" \
    --server "https://localhost:3000/acme/directory" \
    --config-dir "./certbot" --work-dir "./certbot" --logs-dir "./certbot" \
    -d "localhost" -d "*.localhost"
```

## Acme.sh

acme.sh use `--ca-bundle` to trust the ca certificate

```bash
cd examples
mkdir -p "./acme.sh"
~/.acme.sh/acme.sh --server https://localhost:3000/acme/directory --standalone --issue -d "127.0.0.1" --home "./acme.sh" --cert-file "./acme.sh/localhost.crt" --key-file "./acme.sh/localhost.key" --fullchain-file "./acme.sh/localhost.fullchain.crt" -d localhost -d "*.localhost" --force --ca-bundle ./letsacme/acme_ca.crt
```

## Lego

**Lego custom server required HTTPS protocol**

if you do not trust the CA certificate, Lego provides two environment variables to trust the ca server

- [LEGO_CA_CERTIFICATES](https://go-acme.github.io/lego/usage/cli/options/index.html#lego_ca_certificates)

- [LEGO_CA_SERVER_NAME](https://go-acme.github.io/lego/usage/cli/options/index.html#lego_ca_server_name)

```bash
cd examples
export LEGO_CA_CERTIFICATES="./letsacme/acme_ca.crt"
export LEGO_CA_SERVER_NAME="localhost"
mkdir -p './lego'
lego --server "https://localhost:3000/acme/directory" --email "example@example.com" --accept-tos --tls --path "./lego" -d "localhost" -d "1.1.1.1" run
```

## Caddy

```bash
cd examples
caddy run --config Caddyfile
```

if you run caddy using docker, you can specifies the `ca_root` in the Caddyfile. [DOC](https://caddyserver.com/docs/caddyfile/directives/tls#ca_root)

```
tls {
    ca "https://localhost:3000/acme/directory"
    ca_root "/path/to/acme_ca.crt"
}
```
check [https://caddy.localhost:8443](https://caddy.localhost:8443)

## Traefik

see [traefik.yml](traefik.yml) / [traefik_config/traefik_localhost.yml](traefik_config/traefik_localhost.yml)


```bash
cd examples
# in this example, we use cloudflare dns challenge, so we need to set a cloudflare api key
export CF_DNS_API_TOKEN="letsacme_example"
traefik
```
traefik.yml use `acme.caCertificates` to set the ca certificate

```yaml
certificatesResolvers:
  letsacme:
    acme:
      email: "example@example.com"
      caServer: "https://letsacme/acme/directory"
      caCertificates: /etc/traefik/acme_ca.crt
```
check [https://traefik.localhost:9443](https://traefik.localhost:9443)
