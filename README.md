# Synolego

**Issue, renew and deploy ACME certificates on your Synology NAS.**

Synolego combines [Lego](https://github.com/go-acme/lego)'s DNS providers with
Synology certificate deployment. Obtain certificates from Let's Encrypt, install
them in DSM and reload the services assigned to them.

> **Pre-release:** the project is preparing its first public release. A verified
> DSM compatibility matrix is not yet available.

## What it does

- DNS-01 validation, including wildcard certificates, without exposing an HTTP challenge port.
- Certificate issuance and renewal, with Let's Encrypt as the default CA.
- Deployment to the DSM default certificate or a dedicated certificate entry.
- Recovery of interrupted deployments before requesting another certificate.
- Optional PEM and PKCS#12 exports and post-deployment hooks.

## Requirements

- A Synology NAS with root access for certificate deployment and service reloads.
- A domain managed by a [DNS provider supported by Lego](https://go-acme.github.io/lego/dns/), with the required API credentials.
- Outbound access to the ACME service, your DNS provider and DNS resolvers.

Synolego writes to DSM's certificate store. Back up your DSM certificate
configuration and Synolego data before replacing an existing certificate.

## Installation

Published binaries will be available on the [Releases page](https://github.com/kernaxis/synolego/releases).
The release targets are Linux `amd64`, `386`, `armv7` and `arm64`.

Until the first release is published, build from source on a machine with Git,
Make and the Go toolchain declared in [`go.mod`](go.mod), currently Go 1.24.5:

```sh
git clone https://github.com/kernaxis/synolego.git
cd synolego
make build GOARCH=amd64
```

This example builds for an amd64 NAS. Use `GOARCH=386`, `GOARCH=arm` (ARMv7), or
`GOARCH=arm64` for another target. ARMv5 is not included in the release targets.

Copy the resulting binary to `/tmp/synolego` on your NAS. For the amd64 example,
it is located at `dist/synolego_dev_linux_amd64/synolego`.
Then install it on the NAS as root:

```sh
cp /tmp/synolego /usr/local/bin/synolego
chmod 0755 /usr/local/bin/synolego
/usr/local/bin/synolego --version
```

## Get your first certificate

The following example uses Cloudflare. For another provider, use its Lego
provider name and credential variables.

In a root shell on the NAS, create `/root/.config/synolego/cloudflare-token`
containing your Cloudflare API token. Restrict the directory to `0700` and the
file to `0600`. The token needs **Zone / DNS / Edit** and **Zone / Zone / Read**
permissions for the relevant zone. See the
[Cloudflare provider guide](https://go-acme.github.io/lego/dns/cloudflare/).

This command **replaces DSM's default certificate**. Replace the example email
and domain with your own:

```sh
export CF_DNS_API_TOKEN_FILE=/root/.config/synolego/cloudflare-token

/usr/local/bin/synolego \
  --email admin@example.com \
  --dns cloudflare \
  --domains nas.example.com \
  --default \
  --accept-tos \
  run
```

Without `--default`, Synolego creates or reuses a dedicated certificate entry.
Assign that certificate to the desired services in DSM; subsequent deployments
follow those service assignments.

Repeat `--domains` to include additional names. Quote wildcard names, for example
`--domains '*.example.com'`. Global options go **before** `run` or `renew`.

## Renew automatically

Use the same account email, DNS provider, domain selection, certificate target
and data directory as the initial issuance:

```sh
export CF_DNS_API_TOKEN_FILE=/root/.config/synolego/cloudflare-token

/usr/local/bin/synolego \
  --email admin@example.com \
  --dns cloudflare \
  --domains nas.example.com \
  --default \
  renew
```

Run this from a root-owned script using DSM Task Scheduler, once a day. Include
the credential file environment variable in the script; scheduled tasks do not
inherit your interactive shell. Check the task's exit status and logs.

Synolego checks whether renewal is due before issuing a new certificate. An
interrupted deployment is recovered first; that invocation then exits without
requesting another certificate or replaying user hooks. See
[deployment recovery](docs/deployment-recovery.md).

## Data and configuration

Data is stored in `/usr/local/share/synolego` by default. Set `--path` or
`LEGO_PATH` to choose another directory and keep that setting consistent across
runs. The data includes ACME account keys, certificate keys and pending recovery
state: keep it private and backed up.

For an external CSR, use `--csr` with `run --private-key /path/to/key.pem`.
CSR renewals use the matching private key saved in the data directory.

Explore the available options:

```sh
synolego --help
synolego run --help
synolego renew --help
```

## Development

```sh
make fmt-check vet test race
```

See [CI and releases](docs/ci-cd.md) for lint tools, security checks and packaging.
Bug reports should include the Synolego version, NAS model, DSM version and
redacted logs. Never include DNS tokens, private keys or your data directory.

## License

Synolego is licensed under [MIT](LICENSE), with the original Lego attributions
preserved. MIT permits commercial use, modification and redistribution, provided
the copyright and license notices are retained.

Dependencies retain their own licenses; see
[third-party notices](THIRD_PARTY_NOTICES.md). Release archives include the
applicable license texts and the sources of MPL-2.0 components.
