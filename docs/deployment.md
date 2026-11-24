# Installation & Deployment

Hecate runs as a Docker Compose stack. This page covers what the stack consists of, how to install
it, how to put it behind a reverse proxy, how to build your own images, and how to update. Every
variable mentioned here is described on [Environment Variables](configuration.md). For a first try on
your own machine, [Getting Started](getting-started.md) is shorter.

## What runs

| Service | Image | Port | Data | Needed |
| --- | --- | --- | --- | --- |
| `frontend` | `ghcr.io/0x3e4/hecate-frontend` | **8080** (published) | – | yes |
| `backend` | `ghcr.io/0x3e4/hecate-backend` | 8000 (internal only) | – | yes |
| `scanner` | `ghcr.io/0x3e4/hecate-scanner` | 8080 (internal only) | `grype-db` volume | for SCA scans |
| `mongo` | `mongo:8` | internal only | `mongo-data` volume | yes |
| `opensearch` | `opensearchproject/opensearch:3` | internal only | `opensearch-data` volume | yes |
| `apprise` | `caronc/apprise` | internal only | `apprise-config` volume | for notifications |
| `docs` | `ghcr.io/0x3e4/hecate-docs` | `127.0.0.1:8001` | – | optional (`docs` profile) |

The **frontend** container is the only way in. It serves the web app and forwards `/api`, `/mcp` and
`/.well-known/oauth-*` to the backend, so the backend publishes no port. MongoDB and OpenSearch sit on
an internal `db` network that only the backend joins.

The images are published for every push to `main` (tags `latest` and `main-<sha>`) and for every
release (the version, e.g. `2.2.1`). Pin a version tag in production, so an update happens when you
choose it.

## Requirements

- Docker with the Compose plugin.
- Memory: about 4 GB for MongoDB and OpenSearch, plus up to 12 GB for the scanner while scans run
  (its limit in the compose file). A host with 16 GB runs the whole stack comfortably.
- Disk: the vulnerability database grows to tens of GB once all sources have synced (MongoDB plus the
  OpenSearch index), and the scanner keeps a ~3 GB Grype database.
- Outbound HTTPS to the data sources (NVD, EUVD, OSV, GitHub incl. `raw.githubusercontent.com`, CIRCL,
  CISA, MITRE, deps.dev, endoflife.date, and `api.vulncheck.com` once a VulnCheck token is set). Behind a TLS-inspecting proxy, mount its CA, see
  [TLS / corporate proxy](configuration.md#tls-corporate-proxy).

## Install

```bash
git clone https://github.com/0x3e4/hecate.git && cd hecate
cp docker-compose.yml.example docker-compose.yml
cp .env.example .env
```

In `.env`, set at least:

- `MONGO_USERNAME` / `MONGO_PASSWORD` and `OPENSEARCH_USERNAME` / `OPENSEARCH_PASSWORD`. The compose
  file creates the database users from them on first start.
- `TZ`, your timezone.
- For an instance others can reach: `SYSTEM_PASSWORD`, or [sign-in through your identity
  provider](admin/authentication.md), and `ENVIRONMENT=production`.
- Optionally `NVD_API_KEY` and `GHSA_TOKEN`: both raise the rate limits a lot and shorten the first
  sync from days to hours.

Then start it:

```bash
docker compose up -d
```

The web app is at `http://<host>:8080`. The first syncs start right away; NVD, EUVD and OSV take hours
on the first run, and the pages fill as data arrives. **System → Data** shows the progress.

## Reverse proxy & TLS

For anything beyond a trial, put Hecate behind a reverse proxy that terminates TLS. The
`deploy/reverse-proxy/` folder has templates for **nginx**, **Caddy** and **Traefik**. They send every
request to the frontend container on port 8080, stream `/api/v1/events` and `/mcp` without buffering,
and set the security headers (HSTS, a strict Content-Security-Policy, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, cross-origin isolation).

1. Copy the template for your proxy, replace the domain and the upstream host name.
2. When the proxy runs on the same host, bind the frontend to loopback: `127.0.0.1:8080:8080`.
3. Keep `TRUSTED_PROXY_IPS=hecate-frontend` in `.env`. The backend then sees the real client addresses,
   which the brute-force throttle and the audit log rely on.
4. If the proxy reaches the frontend from a public address, set `TRUSTED_PROXIES` on the frontend
   service to that address (the default trusts private networks).
5. With sign-in or MCP, set `AUTH_PUBLIC_URL` (and `MCP_PUBLIC_URL`) to the URL people open.

!!! warning "Shared Docker networks"
    When Hecate's containers join a network other projects use too (often the reverse proxy's), the
    names `backend` and `frontend` may resolve to their containers as well. The compose file therefore
    gives Hecate's containers the aliases `hecate-backend` and `hecate-frontend` and uses those
    (`BACKEND_UPSTREAM`, `TRUSTED_PROXY_IPS`). Point your proxy at a name only Hecate's frontend carries.

The traffic between the proxy and port 8080 is plain HTTP. Keep it on the host or a private network.

## Building your own images

To run a version that is not published yet, build the images yourself and push them to your own
registry. Run this from the repository root:

```bash
SHA=$(git rev-parse HEAD)
docker build --pull --build-arg HECATE_BUILD_SHA=$SHA -t registry.example.com/hecate-backend:latest  ./backend
docker build --pull --build-arg HECATE_BUILD_SHA=$SHA -t registry.example.com/hecate-frontend:latest ./frontend
docker build --pull --build-arg HECATE_BUILD_SHA=$SHA -t registry.example.com/hecate-scanner:latest  ./scanner
docker build --pull -f docs/Dockerfile -t registry.example.com/hecate-docs:latest .
```

In PowerShell, set the variable with `$SHA = git rev-parse HEAD` and use `$SHA` the same way.
`HECATE_BUILD_SHA` lets the [Support page](#checking-for-updates) tell which commit is running;
without it the page shows *SHA unknown*. Then change the `image:` lines in `docker-compose.yml` to your
registry.

## Hosting the documentation

The `docs` service serves this documentation from your own host, without loading anything from
elsewhere. It sits behind a compose profile:

```bash
docker compose --profile docs up -d docs
```

It listens on `127.0.0.1:8001`; publish it through your reverse proxy like the frontend. Point
`DOCS_URL` in `.env` at its public address, so the web app's *Documentation* link and the help links
open your copy. When you serve it under another address than `https://docs.hecate.pw/`, build the image
with that address, or links inside the site jump to the public one:

```bash
docker build -f docs/Dockerfile --build-arg DOCS_SITE_URL=https://docs.example.com/ -t hecate-docs .
```

## Updating

```bash
docker compose pull && docker compose up -d
```

Read the [changelog](changelog.md) before you update. A release that changes ports, routing or
required settings says so at the top of its entry.

!!! warning "Upgrading from 2.3.0-beta.6 or older"
    The frontend listens on **8080** instead of 4173, the backend publishes no port, and the reverse
    proxy sends everything to the frontend. Take `docker-compose.yml.example` over into your
    `docker-compose.yml`, set `TRUSTED_PROXY_IPS=hecate-frontend` and point your proxy at
    `hecate-frontend:8080` (or the published port).

### Checking for updates

**Support** in the sidebar compares each running component with the newest images on GitHub:

| Status | Meaning |
| --- | --- |
| Up to date | The component runs the commit of the newest `main` image. |
| New build available | A newer `main` image exists. |
| Newer than the latest build | The running commit is ahead of the newest image, e.g. a beta built before CI finished. |
| Local build, not on GitHub | The commit was built locally and never pushed. |
| Build SHA unknown | The image was built without `HECATE_BUILD_SHA`. |

*Release available* appears only when a release newer than the running version exists. Pre-release
versions (`2.3.0-beta.8`) are never offered as an update.

### Rebuilding the search index

Most updates need nothing beyond the pull above. Occasionally a release adds a field the search index
has to compute per record — [affected-version search](guide/search.md#searching-by-the-version-you-run)
is the current example. Records ingested or refreshed after the update get it automatically; to backfill
everything already stored, run once:

```bash
docker compose exec backend python -m app.cli reindex-opensearch
```

It reads from MongoDB, so nothing is lost if you skip or interrupt it — search simply keeps returning
results from whatever has been indexed so far. Expect it to take a while on a large corpus. AI
assessments and attack-path narratives of vulnerabilities exist only in the index; the reindex keeps
them on every record it rewrites.

If the backend logs `opensearch.ensure_mappings_failed` with *cannot change object mapping from
non-nested to nested*, the index predates a field type Hecate now needs, and a reindex cannot change
that. Check the two fields (this assumes the default index name and the bundled OpenSearch):

```bash
docker compose exec -T opensearch sh -c 'curl -sk -u "$OPENSEARCH_USERNAME:$OPENSEARCH_PASSWORD" https://localhost:9200/hecate-vulnerabilities/_mapping' \
  | python3 -c "import json,sys; p=list(json.load(sys.stdin).values())[0]['mappings']['properties']; print({k: p.get(k,{}).get('type','object') for k in ('impactedProducts','versionRanges')})"
```

If `versionRanges` shows `object` instead of `nested`, affected-version search cannot work and the
index has to be created again. Stop the backend first: a running backend would recreate the deleted
index on its next write, without the mapping.

```bash
docker compose stop backend
docker compose exec -T opensearch sh -c 'curl -sk -u "$OPENSEARCH_USERNAME:$OPENSEARCH_PASSWORD" -X DELETE https://localhost:9200/hecate-vulnerabilities'
docker compose run --rm backend python -m app.cli reindex-opensearch
```

The reindex creates the index with the current mapping before it writes. Once it prints
`Reindexing N vulnerabilities`, `docker compose start backend` can run alongside it. Deleting the
index removes the AI assessments and attack-path narratives of vulnerabilities, since MongoDB has no
copy of them; scan analyses are unaffected.

### Shrinking the change history

Before the compact history format, every change-history entry held a full copy of its record and of
the raw upstream data, which made the `vulnerabilities` collection several times larger than its
content. Old entries shrink on their own as records change. To shrink them all at once and give the
space back to the disk:

```bash
# see what it would save, then run it; --pause 0.5 leaves IO for other services
docker compose exec backend python -m app.cli compact-history --dry-run --limit 5000
docker compose exec backend python -m app.cli compact-history --pause 0.5

# afterwards, so WiredTiger returns the freed space
docker compose exec mongo mongosh hecate --eval 'db.runCommand({compact: "vulnerabilities"})'
```

The run reads the whole collection once, so start it at a quiet time. It prints the last document id
with every batch; `--start-after <id>` resumes from there.

## Backups

**System → General → Backup & restore** exports vulnerabilities, saved searches and the inventory as
JSON files and restores them. Scans, findings, settings and notification rules live only in MongoDB:
back up the `mongo-data` volume (or run `mongodump`) for those. The OpenSearch index can always be
rebuilt from MongoDB with `reindex-opensearch`, except for the AI assessments of vulnerabilities, which
exist only there.
