![example workflow](https://github.com/nielsandriesse/session-open-group-server/actions/workflows/build.yml/badge.svg)

[API Documentation](https://github.com/nielsandriesse/session-open-group-server/wiki/API-Documentation)

[CLI Reference](https://github.com/nielsandriesse/session-open-group-server/wiki/CLI-Reference)

Want to build from source? See [BUILDING.md](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md).

## Installation Instructions

```
apt-get session-open-group-server
mkdir /usr/local/session-open-group-server
openssl genpkey -algorithm x25519 -out /usr/local/session-open-group-server/x25519_private_key.pem
openssl pkey -in x25519_private_key.pem -pubout -out /usr/local/session-open-group-server/x25519_public_key.pem
systemctl enable session-open-group-server.service
systemctl start session-open-group-server.service
```
