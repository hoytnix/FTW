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
                        >> FUCK TEH WORLD <<
             authorized async TCP port scanner + HTTP probe v0.2.0
================================================================================
                     .o.                  .-"""-.
                    /o o\                / .--. \
                    |nju|  phile #00     | (copy) |
                     \_/                  \ '--' /
                                            '-..-'
                    KOPIMI: COPY THIS ZINE. SPREAD IT LIKE A VIRUS.
================================================================================
```

# 0x00 // WHAT IS THIS?

**FTW** is a fast, async TCP port scanner with an HTTP/HTTPS probe stage,
written in Rust for operators who own (or have **written permission** to test)
the ranges they point it at. Two stages, one binary, zero buffering of the
whole run — results stream to disk as they land.

```
                    +-----------------+
                    | targets.yml     |   your OWN ranges, and nothing else
                    |  10.66.66.0/24  |
                    +--------+--------+
                             | ftw scan
                             v
                    +-----------------+
                    | results.txt     |   10.66.66.4:80 open
                    |  ip:port status |   10.66.66.9:443 closed
                    +--------+--------+
                             | ftw probe  (open ports only, never re-scanned)
                             v
                    +-----------------+
                    | probe.jsonl     |   one JSON object per line:
                    |  status, server |   status, server, tls, php_detected...
                    |  tls, php...    |
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

That's it. No config files, no daemons, no database. The binary lands at
`./target/release/ftw`.

Lint priests and test freaks, your incantations:

```sh
cargo clippy --all-targets -- -D warnings   # must be clean
cargo test                                  # 11 tests, all green
```

# 0x02 // STAGE ONE: `ftw scan`

Takes a YAML file, fans out TCP connects with a semaphore gate, streams
`<ip>:<port> <status>` lines where status is `open`, `closed`, or `filtered`.

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

Overlaps get merged, giant ranges are lazily iterated (never expanded in RAM).

```sh
ftw scan --input targets.yml --ports 80,443 --output results.txt
```

| flag | default | meaning |
|------|---------|---------|
| `--input` | — (required) | YAML file with your authorized CIDRs / IPs |
| `--ports` | `80,443` | comma-separated ports to knock on |
| `--concurrency` | `500` | max probes in flight (permit taken BEFORE spawn) |
| `--timeout` | `2.0` | seconds per connect probe |
| `--output` | — (required) | streamed results file |

# 0x03 // STAGE TWO: `ftw probe`

Reads the scan output — **and nothing else**. Only lines marked `open` are
probed (deduplicated). Closed/filtered ports are never touched, the targets
file is never re-expanded, and no port absent from the scan output is probed.

One `GET /` per scheme attempt, with a clear `FTW/...` User-Agent, redirects
followed (final URL recorded), and at most `--body-cap` bytes of body read —
the body itself is discarded; only status, `Server`, and content-length
presence are noted. No dir bruteforcing, no `phpinfo.php`, no logins, no
exploits. Ever.

```sh
ftw probe --scan-output results.txt --output probe.jsonl --scheme auto
```

| flag | default | meaning |
|------|---------|---------|
| `--scan-output` | — (required) | Phase 1 results file (the ONLY input) |
| `--output` | — (required) | JSON-lines probe records, streamed |
| `--concurrency` | `100` | max probes in flight |
| `--timeout` | `5` | seconds per attempt |
| `--scheme` | `auto` | `auto` (HTTPS first, HTTP fallback), `http`, or `https` |
| `--insecure` | off | accept invalid certs — your OWN self-signed hosts only |
| `--max-redirects` | `5` | redirect limit per attempt |
| `--body-cap` | `8192` | max body bytes read per attempt |

Each output line looks like this:

```json
{"ip":"10.66.66.4","port":80,"scheme":"http","final_url":"http://10.66.66.4/",
 "status":200,"server":"nginx/1.28.3","tls":"n/a","error":null,
 "php_detected":false,"php_version":null,"php_signals":[]}
```

- `tls` is `ok` / `error` / `n/a` (plain HTTP) — recorded separately from
  HTTP status. A TLS/cert failure is **never** reported as a closed port.
- `error` is `null` on any response, else `tls_error` / `connect_error` /
  `timeout` / `other`. A failed probe is a record, not a crash.

# 0x04 // PHP RADAR (PASSIVE ONLY)

From that same single `GET` — headers, `Set-Cookie`, and the final URL. Never
the body, never extra requests. No `X-Powered-By` header? Then PHP is
*unconfirmed*, not absent: `php_detected: false`, empty signals, `null`
version. Versions are parsed only from `PHP/<major>.<minor>.<patch>` and
never invented.

| signal | fires when |
|--------|-----------|
| `x-powered-by` | `X-Powered-By` contains `PHP/` |
| `server` | `Server` contains `php` (case-insensitive) |
| `phpsessid-cookie` | any `Set-Cookie` contains `PHPSESSID` |
| `redirect-to-php` | final URL path ends in `.php` |

# 0x05 // GREETZ & LICENSE

Greetz fly out to every sysadmin who ever left port 80 open on a Friday
afternoon. You know who you are.

This software is **KOPIMI**. Copy it, share it, remix it — copying is an act
of love. See [LICENSE](/home/oloty/Dev/FTW/LICENSE).

```
================================================================================
  ...and remember: only scan what is YOURS. The zine has spoken. EOF.
================================================================================
```
