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
sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
sudo apt update
sudo apt install session-open-group-server
```

### Step 2: Check that it's running:

```
systemctl status session-open-group-server.service
```
