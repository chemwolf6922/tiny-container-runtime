# DNS Forwarder Design

## Purpose

A lightweight UDP DNS forwarder that runs on the NAT gateway (`10.88.0.1:53`) to handle container DNS. It:
- Resolves container names (e.g. `tcr-*`) to container IPs via a runtime lookup table (inter-container discovery)
- Forwards all other queries transparently to the host's upstream DNS resolvers

This replaces the current `resolv.conf` generation hack in `add-nat-network.sh` (which tries to detect upstream DNS behind systemd-resolved) with a single reliable `nameserver 10.88.0.1` entry for all containers.

## Architecture

```
Client ──UDP──▶ [listen_fd] ──▶ on_client_query()
                                  ├─ lookup_map hit + A query → build A response → sendto(client)
                                  └─ miss → remap txn ID → sendto(upstream[0])
                                                               │
Upstream ──UDP──▶ [upstream_fd] ──▶ on_upstream_response()
                                      └─ restore txn ID → sendto(client)

Timeout ──tev──▶ on_query_timeout()
                   └─ try next upstream, or discard if all exhausted

inotify ──tev──▶ on_resolv_conf_changed()
                   └─ reload upstream nameservers
```

Everything integrates with tev (tiny event loop) via non-blocking fd read handlers and timeouts. Zero threads, zero blocking calls.

## Key Design Decisions

### UDP-only (no TCP)

DNS clients default to UDP on port 53. TCP is only used for:
- Truncated responses (TC bit) — rare for typical container queries
- Zone transfers (AXFR) — not relevant
- Large DNSSEC responses — unlikely on embedded devices

All common resolvers (musl in Alpine, glibc) automatically use UDP. TCP support can be added later if needed.

### Transparent forwarding (no DNS parsing on forward path)

For upstream-forwarded queries, the forwarder does **zero DNS parsing**:
1. Receive raw UDP packet from client
2. Rewrite 2-byte transaction ID in header (to avoid collisions from multiple clients)
3. `sendto(upstream)` — packet forwarded byte-for-byte
4. Receive response from upstream, restore original transaction ID
5. `sendto(client)` — response forwarded byte-for-byte

This means **any record type** (A, AAAA, MX, CNAME, SRV, TXT, etc.) works automatically without per-type handling.

Minimal DNS parsing is only done on the **local lookup path**: extract QNAME and QTYPE from the question section to check the lookup table and construct A record responses.

### Why not c-ares or glibc resolver?

- **glibc resolver** (`getaddrinfo`): Blocking. Would freeze the entire single-threaded event loop for up to 30 seconds. Using it would require a thread pool, which is overkill.
- **c-ares**: It's a resolver, not a forwarder. Using it would require fully parsing incoming DNS queries into structured data, calling `ares_query()`, then re-encoding the response into a DNS wire-format packet — for every record type. More code, more bugs, external dependency, and we'd lose information from the original response (authority/additional sections, etc.).

Raw UDP forwarding is simpler, faster, and more correct.

### Multiple upstream DNS with sequential failover

`/etc/resolv.conf` may contain multiple `nameserver` lines. The forwarder:
- Parses all of them into a dynamic array at startup
- For each client query: sends to `upstream[0]` first
- On 10-second timeout: retries with `upstream[1]`, then `[2]`, etc.
- Discards the query only after all upstreams have timed out

This mirrors glibc's default behavior (5s per nameserver, ~30s total), but with 10s per upstream to give each server adequate time since we're an intermediate hop.

### Watching resolv.conf for changes (inotify)

`/etc/resolv.conf` can change at runtime (DHCP, VPN, NetworkManager, systemd-resolved). Rather than:
- Re-reading on every request (wasteful I/O on hot path)
- Re-reading on failure (penalizes the unlucky client whose query triggers the stale config)

We use **inotify on `/etc/` directory** (not the file itself):
- Many tools do atomic replacement: write temp file → `rename()`. This deletes the old inode, invalidating a file-level watch.
- Watching the directory catches `IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE` events for `resolv.conf`
- The inotify fd integrates directly with tev as a read handler — zero polling overhead

Result: upstream list is always current, no client is penalized, no wasted I/O.

### Buffer size: 4096 bytes (EDNS0)

- Original DNS (RFC 1035, 1987): 512-byte UDP message limit
- Modern DNS (EDNS0, RFC 6891, 2013): clients advertise support for larger UDP packets, typically up to 4096 bytes
- Since we're a transparent forwarder, we use 4096-byte buffers to avoid truncating EDNS0 responses
- Local lookup responses (single A record) are ~50 bytes, well within any limit

### Transaction ID remapping

Multiple clients may independently generate the same 16-bit transaction ID. The forwarder:
- Assigns its own monotonically incrementing txn ID for each upstream query
- Stores the mapping (upstream ID → original client ID + address) in `pending_map`
- Restores the original ID before replying to the client

This prevents response misdelivery when concurrent queries from different clients collide.

## Data Structures

```c
dns_forwarder_t:
  tev               - event loop handle
  lookup_map        - map: domain(string) → ip(string), for local resolution
  listen_fd         - UDP socket bound to listen_addr:listen_port
  upstream_fd       - UDP socket for upstream communication
  upstreams         - dynamic array of struct sockaddr_in (from resolv.conf)
  upstream_count    - number of upstream nameservers
  pending_map       - map: upstream_txn_id(uint16) → pending_query_t*
  next_txn_id       - monotonic counter for upstream transaction IDs
  inotify_fd        - inotify fd watching /etc/ directory
  inotify_wd        - watch descriptor

pending_query_t:
  fwd               - back-pointer to owning dns_forwarder_t (for timeout callbacks)
  client_addr       - original client sockaddr (for reply)
  client_addrlen    - sockaddr length
  original_txn_id   - client's transaction ID (to restore on reply)
  upstream_txn_id   - our assigned transaction ID
  upstream_index    - which upstream we're currently trying
  query_buf[4096]   - saved query packet (for retry with next upstream)
  query_len         - saved query length
  timeout           - tev timeout handle (for cleanup/retry)
```

## Local DNS Response Construction

For queries matching the lookup table (A record only):
- Copy transaction ID from query
- Set flags: QR=1 (response), AA=1 (authoritative), RA=1 (recursion available)
- QDCOUNT=1, ANCOUNT=1
- Copy question section verbatim
- Append answer: name pointer (0xC00C → offset 12, the QNAME), TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4, RDATA=IPv4 address

Non-A queries for local domains are forwarded upstream (to handle AAAA, etc. gracefully).
