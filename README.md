```
================================================================================
                       $$$$$$$$\ $$$$$$$$\ $$\      $$\
                       $$  _____|\__$$  __|$$ | $\  $$ |
                       $$ |         $$ |   $$ |$$$\ $$ |
                       $$$$$\       $$ |   $$ $$ $$\$$ |
                       $$  __|      $$ |   $$$$  _$$$$ |
                       $$ |         $$ |   $$$  / \$$$ |
                       $$ |         $$ |   $$  /   \$$ |
                       \__|         \__|   \__/     \__|
                             >> FUCK TEH WORLD
    Event-Driven Asynchronous Multi-Threaded TCP Port Scanner + HTTP Probe 
                                    v0.2.4
================================================================================
                     .o.                  .-"""-.
                    /o o\                / .--. \
                    |nju|   file #00     | (copy) |
                     \_/                  \ '--' /
                                            '-..-'
                    KOPIMI: COPY THIS ZINE. SPREAD IT LIKE A VIRUS.
================================================================================
```

# 0x00 // WHAT IS THIS?

**FTW** is a fast, async TCP port scanner with HTTP/HTTPS fingerprinting and
a polite same-host web crawler, written in Rust for operators who own (or
have **written permission** to test) the ranges they point it at.

Three stages, one binary, one SQLite database (`ftw.db` by default) — results
stream in as they land, never buffered:

```
                    +-----------------+
                    | targets.yml     |   your OWN ranges, and nothing else
                    |  10.66.66.0/24  |
                    +--------+--------+
                             | ftw scan
                             v
                    +-----------------+
                    | ftw.db          |   scan_results: ip, port, status
                    |  scan_results   |
                    +--------+--------+
                             | ftw fingerprint (open ports only)
                             v
                    +-----------------+
                    | ftw.db          |   fingerprint_results: status,
                    |  fingerprint_   |   server, tls, php/tech signals...
                    |  results        |
                    +--------+--------+
                             | ftw crawl (2xx/3xx pages only)
                             v
                    +-----------------+
                    | ftw.db          |   crawl_pages + crawl_links
                    |  crawl_pages    |
                    +-----------------+
```

> [!WARNING]
> **AUTHORIZED RANGES ONLY.** The tool does not and cannot check whether you
> are allowed to scan a target — that part is on you, the operator. Only ever
> aim FTW at addresses you own or have explicit written permission to test.
> Unauthorized scanning is illegal in most places and will get you in trouble.
> Don't be stupid.

# 0x01 // BUILD IT

You need a Rust toolchain (cargo). Then:

```sh
cargo build --release
```

The binary lands at `./target/release/ftw`. Lint priests and test freaks,
your incantations:

```sh
cargo clippy --all-targets -- -D warnings   # must be clean
cargo test                                  # 93 tests, all green
```

# 0x02 // STAGE ONE: `ftw scan`

Fans out TCP connects with a semaphore gate, records `open` / `closed` /
`filtered` per port into `scan_results`. Overlaps get merged, giant ranges
are lazily iterated (never expanded in RAM).

Targets file — either shape works:

```yaml
targets:
  - 10.66.66.0/24
  - 192.168.1.23
```

```yaml
- 10.66.66.0/24
- 2001:db8::/120
```

Run it:

```sh
ftw scan --input targets.yml --ports 80,443 --db ftw.db
```

| flag | default | meaning |
|------|---------|---------|
| `--input` | — (required) | YAML file with your authorized CIDRs / IPs |
| `--ports` | `80,443` | comma-separated ports to knock on |
| `--concurrency` | `500` | max probes in flight |
| `--timeout` | `2` | seconds per connect probe |
| `--db` | `ftw.db` | master database file |
| `--config` | — | config file (see 0x05) |
| `-v` / `--verbose` | off | one stderr line per event |
| `-q` / `--quiet` | off | silent except errors + summary |

# 0x03 // STAGE TWO: `ftw fingerprint`

Reads **open** ports from `scan_results` — and nothing else. Closed/filtered
ports are never touched, the targets file is never re-expanded. Each open
port gets HTTP/HTTPS probing with a clear `FTW/...` User-Agent, redirects
followed (final URL recorded), at most `--body-cap` body bytes read for
parsing (never stored). One record per port lands in `fingerprint_results`
with status, `Server`, TLS outcome, PHP signals, tech signals, and fetch
metadata.

```sh
ftw fingerprint --db ftw.db --scheme auto --fetch-mode get
```

| flag | default | meaning |
|------|---------|---------|
| `--concurrency` | `100` | max requests in flight |
| `--timeout` | `5` | seconds per attempt |
| `--scheme` | `auto` | `auto` (HTTPS first, HTTP fallback), `http`, or `https` |
| `--insecure` | off | accept invalid certs — your OWN self-signed hosts only |
| `--max-redirects` | `5` | redirect limit per attempt |
| `--body-cap` | `8192` | max body bytes read per attempt |
| `--fetch-mode` | `get` | `get` (one GET), `head` (headers only), `both` (HEAD then GET) |
| `--no-prefer-https` | off | fingerprint 80 AND 443 instead of preferring 443 |
| `--db` / `--config` | `ftw.db` | database file / config file (see 0x05) |

Prefer-HTTPS: when one IP has both 80 and 443 open, only 443 is fingerprinted
(HTTPS-only — never plaintext HTTP to 443), the 80 is skipped with no row,
and a dead 443 falls back to 80 exactly once. The speedup applies to
dual-port hosts only, not everything.

PHP radar is passive-only (headers, `Set-Cookie`, final URL — never extra
requests): `x-powered-by`, `server`, `phpsessid-cookie`, `redirect-to-php`.
Tech radar reads the already-fetched body preview: WordPress, eight PHP apps
(Joomla, Drupal, Magento, phpBB, MediaWiki, PrestaShop, OpenCart, Moodle),
and TailwindCSS. No `X-Powered-By` header? Then PHP is *unconfirmed*, not
absent — versions are parsed only from `PHP/<major>.<minor>.<patch>` and
never invented.

# 0x04 // STAGE THREE: `ftw crawl`

Crawls 2xx/3xx pages from `fingerprint_results`, same host only (IP seeds
also pin the port). GET-only — never POST, never forms, never credentials.
Only `<a href>` links on `text/html` pages; `/wp-admin`, logouts, deletes,
and `action=` URLs are recorded but never visited. Bodies are streamed to a
cap and never stored — only metadata and links.

```sh
ftw crawl --db ftw.db --max-depth 2 --requests-per-minute 60
```

| flag | default | meaning |
|------|---------|---------|
| `--concurrency` | `100` | max fetches in flight |
| `--timeout` | `5` | seconds per fetch |
| `--max-depth` | `2` | link depth (0 = seed pages) |
| `--max-pages` | `1000` | total page budget |
| `--body-cap` | `262144` | max body bytes parsed per page |
| `--max-redirects` | `5` | redirect limit per page |
| `--insecure` | off | accept invalid certs (your own hosts only) |
| `--requests-per-minute` | `0` | per-domain limit, `0` = unlimited |
| `--db` / `--config` | `ftw.db` | database file / config file (see 0x05) |

Rate limiting is per canonical domain (lowercased host, one `www.` stripped,
scheme and port ignored) across ALL threads combined — never per-thread. A
worker stalled on one domain's limit holds no fetch slot, so other domains
keep flowing. Redirects followed internally by the client don't count extra
(a known limitation); failed fetches still count, because they still hit
the server.

# 0x05 // CONFIG FILE: STOP RETYPING FLAGS

Any default can live in TOML. Discovery order: `--config <FILE>`, then
`./ftw.toml`, then `$HOME/.config/ftw/config.toml`, then built-ins.
Precedence is strict: **CLI flag > config file > built-in default**.
A missing explicit `--config` path fails before any work starts; unknown
keys and invalid values fail naming the file.

```toml
[global]
db = "ftw.db"

[scan]
concurrency = 500
timeout = 2

[fingerprint]
concurrency = 100
timeout = 5
scheme = "auto"          # auto | http | https
insecure = false
max_redirects = 5
body_cap = 8192
fetch_mode = "get"       # get | head | both
prefer_https = true

[crawl]
concurrency = 100
timeout = 5
max_depth = 2
max_pages = 1000
body_cap = 262144
max_redirects = 5
insecure = false
requests_per_minute = 0  # 0 = unlimited

[crawl.rate_limits]      # per-domain overrides (canonical domains only)
"wordpress.org" = 5
"example.com" = 60
```

Set only what you want — unset options fall through, never reset to zero.
With `--verbose`, every run prints its resolved effective config to stderr
first, one line per option with its source:

```
config: crawl.requests_per_minute = 60 (config)
config: crawl.max_pages = 1000 (default)
config: crawl.concurrency = 20 (cli)
```

# 0x06 // FULL RUN, END TO END

```sh
# 1. write targets.yml with YOUR ranges, then:
ftw scan --input targets.yml --ports 80,443
ftw fingerprint --scheme auto
ftw crawl --max-depth 2 --requests-per-minute 60 --verbose
```

Or bake it all into `ftw.toml` once and just run the three bare subcommands.
Query the goods straight from SQLite:

```sh
sqlite3 ftw.db "SELECT ip, port FROM scan_results WHERE status='open';"
sqlite3 ftw.db "SELECT ip, port, status, server FROM fingerprint_results;"
sqlite3 ftw.db "SELECT url, status, title FROM crawl_pages;"
```

`-q` silences everything but errors and the stderr summary; `-v` narrates
every event plus the effective config. Stdout stays parseable either way.

# 0x07 // GREETZ & LICENSE

Greetz fly out to every sysadmin who ever left port 80 open on a Friday
afternoon. You know who you are.

This software is **KOPIMI**. Copy it, share it, remix it — copying is an act
of love. See [LICENSE](/home/oloty/Dev/FTW/LICENSE).

```
================================================================================
  ...and remember: only scan what is YOURS. The zine has spoken. EOF.
================================================================================
```
