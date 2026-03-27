# LetsACME Examples

Lego/traefik requires the ACME server to use the HTTPS protocol, so all the following test cases use the HTTPS protocol. You can quickly start an HTTPS test server by running `docker compose up -d`.

Before starting the test, please ensure that the CA certificate is trusted by your system.

## Docker Compose

```
docker compose up -d
```

[docker-cmpose.yaml](../docker-compose.yaml)


## Certbot

```bash
cd exapmles
mkdir -p "./certbot"
certbot certonly --standalone --agree-tos -m "example@exapmle.com" \
    --server "https://localhost:3000/acme/directory" \
    --config-dir "./certbot" --work-dir "./certbot" --logs-dir "./certbot" \
    -d "localhost" -d "*.localhost"
```

## Acme.sh

```bash
cd exapmles
mkdir -p "./acme.sh"
~/.acme.sh/acme.sh --server https://localhost:3000/acme/directory --standalone --issue -d "127.0.0.1" --home "./acme.sh" --cert-file "./acme.sh/localhost.crt" --key-file "./acme.sh/localhost.key" --fullchain-file "./acme.sh/localhost.fullchain.crt" -d localhost -d "*.localhost" --force
```

## Lego

**Lego custom server required HTTPS protocol**

```bash
cd exapmles
mkdir -p './lego'
lego --server "https://localhost:3000/acme/directory" --email "example@example.com" --accept-tos --tls --path "./lego" -d "localhost" -d "1.1.1.1" run
```

## Caddy

Visit [https://localhost/](https://localhost/)

```bash
cd exapmles
caddy run
```

## Traefik

see [traefik.yml](traefik.yml) / [traefik_config/traefik_localhost.yml](traefik_config/traefik_localhost.yml)

Visit [https://traefik.localhost:8443/dashboard/](https://traefik.localhost:8443/dashboard/)

```bash
cd exapmles
# in this example, we use cloudflare dns challenge, so we need to set a cloudflare api key
export CF_DNS_API_TOKEN="letsacme_example"
traefik
```
