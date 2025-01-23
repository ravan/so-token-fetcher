# SUSE Observability Token Fetcher

SUSE Observability does not provide the ability to automatically obtain the initial CLI token that is used to create other
service tokens via the CLI. You would have to manually:

- Log into the SUSE Observability instance.
- From the top left corner, select CLI.
- Note the API token defined on the page.

This repository defines a token fetcher that can automatically obtain the CLI token by simulating the user interaction
using http calls.  The following authentication setups in SUSE Observability are support:

- Keycloak
- Default login

## Usage

The commandline application can be run in several ways using the options,

```bash
OPTIONS:
   --url value                  SUSE Observability URL
   --username value, -u value   Login user
   --password value, -p value   Login password. Can also be provided with env var 'SO_PASSWORD'
   --auth-type value, -t value  Authentication type. Valid values 'default', 'keycloak'
   --output value, -o value     Output file name that will contain CLI token (default: "token.txt")
   --verbose, -v                (default: false)
```

After the application has run it will output the token to a file.

### Run from Source

```bash
git clone https://github.com/ravan/so-token-fetcher.git
cd so-token-fetcher
go run main.go --url https://xxxx -u admin -p xxx
cat token.txt
```

### Run using Docker

```bash 
docker run --rm -v .:/workspace ravan/suse-observability-token-fetcher:0.0.1 /app/so-token-fetcher -o /workspace/token.txt --url https://xxxx -u admin -p xxx

```

## Development

## Prerequisite

- [Taskfile](https://taskfile.dev/installation/)
- [Go](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/get-started/get-docker/)

### Integration Testing

Before running `main_test.go` copy the `.env.example` file to `.env` and change the settings to match you environment.

```
KEYCLOAK_SCENARIO_URL=https://xxx.app.stackstate.io
KEYCLOAK_SCENARIO_USERNAME=xxx
KEYCLOAK_SCENARIO_PASSWORD=xxx

DEFAULT_SCENARIO_URL=https://xxx.stackstate.io
DEFAULT_SCENARIO_USERNAME=xxx
DEFAULT_SCENARIO_PASSWORD=xxx
```

