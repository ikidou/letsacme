# LetsACME

A simple ACME server for homelab and local development.

Features:
- Use custom CA certificate
- Trust Client by default, no validation
- No Local storage Required

## Examples

### Docker & Compose

```bash
docker compose up -d
```

```bash
docker run --rm --name letsacme -p 3000:3000 -v "./letsacme:/data" ikidou/letsacme:latest -https
```

### Start a default server

```bash
letsacme
# or
letsacme -https
```

- Default port: 3000
- Default protocol: HTTP
- CA: `./acme_ca.crt`
- Key: `./acme_ca.key`
- Server Cert: `./acme_server.crt`
- Server Key: `./acme_server.key`

### Custom CA

```bash
letsacme -port 443 -https -ca-cert="/path/to/your_ca.crt" -ca-key="/path/to/your_ca.key"
```

## Test Tools

- [Certbot](https://certbot.eff.org/)
- [Lego](https://github.com/go-acme/lego)
- [Acme.sh](https://acme.sh/)
- [Caddy](https://caddyserver.com/)
- [Traefik](https://traefik.io/)
