![example workflow](https://github.com/nielsandriesse/session-open-group-server/actions/workflows/build.yml/badge.svg)

[API Documentation](https://github.com/nielsandriesse/session-open-group-server/wiki/API-Documentation)

[CLI Reference](https://github.com/nielsandriesse/session-open-group-server/wiki/CLI-Reference)

Want to build from source? See [BUILDING.md](https://github.com/nielsandriesse/session-open-group-server/blob/main/BUILDING.md).

## Installation Instructions

| Dependency    | Version       |
| ------------- |:-------------:|
| openssl       | 1.1.1         |

### Step 1: Pull in the Session open group server executable:

```
apt-get session-open-group-server
```

### Step 2: Create an X25519 key pair for your server:

```
mkdir /usr/local/session-open-group-server
openssl genpkey -algorithm x25519 -out /usr/local/session-open-group-server/x25519_private_key.pem
openssl pkey -in x25519_private_key.pem -pubout -out /usr/local/session-open-group-server/x25519_public_key.pem
```

### Step 3: Start your server:

```
systemctl enable session-open-group-server.service
systemctl start session-open-group-server.service
```
