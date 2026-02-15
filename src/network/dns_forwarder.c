#include "dns_forwarder.h"

#include <tev/map.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <unistd.h>

#define DNS_BUF_SIZE 4096       /* EDNS0 recommended UDP payload size (RFC 6891 Section 6.2.5) */
#define UPSTREAM_TIMEOUT_MS 10000
#define DNS_HDR_SIZE 12         /* RFC 1035 Section 4.1.1: fixed 12-byte header */
#define DNS_LOCAL_TTL 60
#define DNS_MAX_NAME 253        /* RFC 1035 Section 2.3.4: max domain name in dot notation */

/* DNS header flags (RFC 1035 Section 4.1.1) */
#define DNS_FLAG_QR     0x8000
#define DNS_FLAG_AA     0x0400
#define DNS_FLAG_RA     0x0080

/* DNS record types and classes (RFC 1035 Section 3.2.2 / 3.2.4) */
#define DNS_TYPE_A     1
#define DNS_CLASS_IN   1

/* -------------------------------------------------------------------------- */
/*  Data structures                                                           */
/* -------------------------------------------------------------------------- */

typedef struct dns_forwarder_s dns_forwarder_t;

typedef struct pending_query_s
{
    dns_forwarder_t *fwd;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    uint16_t original_txn_id;
    uint16_t upstream_txn_id;
    int upstream_index;
    uint8_t query_buf[DNS_BUF_SIZE];
    ssize_t query_len;
    tev_timeout_handle_t timeout;
} pending_query_t;

struct dns_forwarder_s
{
    tev_handle_t tev;
    map_handle_t lookup_map;
    int listen_fd;
    int upstream_fd;
    struct sockaddr_in *upstreams;
    int upstream_count;
    map_handle_t pending_map;
    uint16_t next_txn_id;
    int inotify_fd;
    int inotify_wd;
};

/* -------------------------------------------------------------------------- */
/*  Forward declarations                                                       */
/* -------------------------------------------------------------------------- */

static void on_client_query(void *ctx);
static void on_upstream_response(void *ctx);
static void on_query_timeout(void *ctx);
static void on_resolv_conf_changed(void *ctx);
static int parse_resolv_conf(struct sockaddr_in **out_addrs, int *out_count);
static int extract_qname(const uint8_t *buf, ssize_t len, char *name_out, int name_out_size);
static int get_qtype(const uint8_t *buf, ssize_t len, int qname_end_offset);
static ssize_t build_a_response(const uint8_t *query, ssize_t query_len,
                                uint32_t ip_net_order, uint8_t *resp, int resp_size);
static void send_to_upstream(dns_forwarder_t *fwd, pending_query_t *pq);
static void pending_query_free(pending_query_t *pq);
static void free_pending_cb(void *value, void *ctx);

/* -------------------------------------------------------------------------- */
/*  resolv.conf parsing                                                        */
/* -------------------------------------------------------------------------- */

static int parse_resolv_conf(struct sockaddr_in **out_addrs, int *out_count)
{
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f) return -1;

    struct sockaddr_in *addrs = NULL;
    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), f))
    {
        /* skip comments and empty lines */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\0') continue;

        char key[64], value[128];
        if (sscanf(p, "%63s %127s", key, value) != 2) continue;
        if (strcmp(key, "nameserver") != 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53);
        if (inet_pton(AF_INET, value, &addr.sin_addr) != 1) continue; /* skip IPv6 for now */

        struct sockaddr_in *tmp = realloc(addrs, (count + 1) * sizeof(*addrs));
        if (!tmp) { free(addrs); fclose(f); return -1; }
        addrs = tmp;
        addrs[count++] = addr;
    }

    fclose(f);

    if (count == 0)
    {
        free(addrs);
        return -1;
    }

    *out_addrs = addrs;
    *out_count = count;
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  DNS helpers                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Extract the QNAME from a DNS query as a dot-separated lowercase string.
 * Returns the byte offset past the QNAME (start of QTYPE field), or -1 on error.
 */
static int extract_qname(const uint8_t *buf, ssize_t len, char *name_out, int name_out_size)
{
    if (len < DNS_HDR_SIZE + 1) return -1;

    int pos = DNS_HDR_SIZE; /* skip header */
    int name_pos = 0;

    while (pos < len)
    {
        uint8_t label_len = buf[pos++];
        if (label_len == 0) break; /* end of QNAME */
        if (label_len > 63) return -1; /* compression not expected in queries */
        if (pos + label_len > len) return -1;
        if (name_pos + label_len + 1 >= name_out_size) return -1;

        if (name_pos > 0) name_out[name_pos++] = '.';
        memcpy(name_out + name_pos, buf + pos, label_len);
        name_pos += label_len;
        pos += label_len;
    }

    name_out[name_pos] = '\0';

    /* convert to lowercase for case-insensitive matching */
    for (int i = 0; i < name_pos; i++)
    {
        if (name_out[i] >= 'A' && name_out[i] <= 'Z')
            name_out[i] += 'a' - 'A';
    }

    return pos; /* offset past QNAME null terminator */
}

/**
 * Get the QTYPE from a DNS query, given the offset past QNAME.
 * Returns QTYPE or -1 on error.
 */
static int get_qtype(const uint8_t *buf, ssize_t len, int qname_end_offset)
{
    if (qname_end_offset + 4 > len) return -1;
    return (buf[qname_end_offset] << 8) | buf[qname_end_offset + 1];
}

/* DNS wire-format structures (packed, no alignment assumptions) */

typedef struct __attribute__((packed)) dns_header_s
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct __attribute__((packed)) dns_a_answer_s
{
    uint16_t name_ptr;  /* compression pointer (0xC00C) */
    uint16_t type;      /* DNS_TYPE_A */
    uint16_t class;     /* DNS_CLASS_IN */
    uint32_t ttl;
    uint16_t rdlength;  /* 4 for A record */
    uint32_t rdata;     /* IPv4 address in network byte order */
} dns_a_answer_t;

/**
 * Build a minimal DNS A-record response.
 * Returns response length, or -1 on error.
 */
static ssize_t build_a_response(const uint8_t *query, ssize_t query_len,
                                uint32_t ip_net_order, uint8_t *resp, int resp_size)
{
    /* Find the end of the question section */
    char discard[DNS_MAX_NAME + 1];
    int qname_end = extract_qname(query, query_len, discard, sizeof(discard));
    if (qname_end < 0) return -1;

    int question_end = qname_end + 4; /* QTYPE(2) + QCLASS(2) */
    if (question_end > query_len) return -1;

    int total = question_end + (int)sizeof(dns_a_answer_t);
    if (total > resp_size) return -1;

    /* Copy header + question from query */
    memcpy(resp, query, question_end);

    /* Patch the header in place */
    dns_header_t hdr;
    memcpy(&hdr, query, sizeof(hdr));
    hdr.flags = htons(ntohs(hdr.flags) | DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA);
    hdr.flags &= htons(~0x000F); /* clear RCODE */
    hdr.qdcount = htons(1);
    hdr.ancount = htons(1);
    hdr.nscount = htons(0);
    hdr.arcount = htons(0);
    memcpy(resp, &hdr, sizeof(hdr));

    /* Build the answer record */
    dns_a_answer_t ans = {
        .name_ptr = htons(0xC00C), /* pointer to QNAME at offset 12 */
        .type     = htons(DNS_TYPE_A),
        .class    = htons(DNS_CLASS_IN),
        .ttl      = htonl(DNS_LOCAL_TTL),
        .rdlength = htons(4),
        .rdata    = ip_net_order,
    };
    memcpy(resp + question_end, &ans, sizeof(ans));

    return total;
}

/* -------------------------------------------------------------------------- */
/*  inotify handler                                                            */
/* -------------------------------------------------------------------------- */

static void on_resolv_conf_changed(void *ctx)
{
    dns_forwarder_t *fwd = ctx;

    /* drain all inotify events */
    uint8_t buf[4096];
    ssize_t n = read(fwd->inotify_fd, buf, sizeof(buf));
    if (n <= 0) return;

    /* check if any event is about resolv.conf */
    int should_reload = 0;
    const uint8_t *p = buf;
    while (p < buf + n)
    {
        const struct inotify_event *ev = (const struct inotify_event *)p;
        if (ev->len > 0 && strcmp(ev->name, "resolv.conf") == 0)
        {
            should_reload = 1;
        }
        p += sizeof(struct inotify_event) + ev->len;
    }

    if (!should_reload) return;

    struct sockaddr_in *new_addrs = NULL;
    int new_count = 0;
    if (parse_resolv_conf(&new_addrs, &new_count) == 0)
    {
        if (fwd->upstreams) free(fwd->upstreams);
        fwd->upstreams = new_addrs;
        fwd->upstream_count = new_count;
    }
    /* on parse failure, keep existing upstream list */
}

static void free_lookup_value(void *value, void *ctx)
{
    (void)ctx;
    free(value);
}

/* -------------------------------------------------------------------------- */
/*  Pending query management                                                   */
/* -------------------------------------------------------------------------- */

static void pending_query_free(pending_query_t *pq)
{
    if (!pq) return;
    if (pq->timeout)
    {
        tev_clear_timeout(pq->fwd->tev, pq->timeout);
        pq->timeout = NULL;
    }
    free(pq);
}

static void free_pending_cb(void *value, void *ctx)
{
    (void)ctx;
    pending_query_t *pq = value;
    if (pq->timeout)
    {
        tev_clear_timeout(pq->fwd->tev, pq->timeout);
    }
    free(pq);
}

static void send_to_upstream(dns_forwarder_t *fwd, pending_query_t *pq)
{
    if (pq->upstream_index >= fwd->upstream_count)
    {
        /* all upstreams exhausted — discard query */
        uint16_t key = pq->upstream_txn_id;
        map_remove(fwd->pending_map, &key, sizeof(key));
        free(pq);
        return;
    }

    /* write our txn ID into the query buffer */
    pq->query_buf[0] = (pq->upstream_txn_id >> 8) & 0xFF;
    pq->query_buf[1] = pq->upstream_txn_id & 0xFF;

    sendto(fwd->upstream_fd, pq->query_buf, pq->query_len, 0,
           (struct sockaddr *)&fwd->upstreams[pq->upstream_index],
           sizeof(fwd->upstreams[pq->upstream_index]));

    /* set per-upstream timeout; pq has a back-pointer to fwd, so no wrapper needed */
    pq->timeout = tev_set_timeout(fwd->tev, on_query_timeout, pq, UPSTREAM_TIMEOUT_MS);
}

static void on_query_timeout(void *ctx)
{
    pending_query_t *pq = ctx;
    dns_forwarder_t *fwd = pq->fwd;
    pq->timeout = NULL; /* fired, no longer valid */

    pq->upstream_index++;
    send_to_upstream(fwd, pq);
}

/* -------------------------------------------------------------------------- */
/*  Client query handler                                                       */
/* -------------------------------------------------------------------------- */

static void on_client_query(void *ctx)
{
    dns_forwarder_t *fwd = ctx;

    uint8_t buf[DNS_BUF_SIZE];
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

    ssize_t n = recvfrom(fwd->listen_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&client_addr, &addrlen);
    if (n < DNS_HDR_SIZE) return; /* too short to be a DNS message */

    /* Extract QNAME and QTYPE */
    char qname[DNS_MAX_NAME + 1];
    int qname_end = extract_qname(buf, n, qname, sizeof(qname));
    if (qname_end < 0) return;

    int qtype = get_qtype(buf, n, qname_end);

    /* Check local lookup table for A queries */
    if (qtype == DNS_TYPE_A)
    {
        char *ip = map_get(fwd->lookup_map, qname, strlen(qname));
        if (ip)
        {
            struct in_addr addr;
            if (inet_pton(AF_INET, ip, &addr) == 1)
            {
                uint8_t resp[DNS_BUF_SIZE];
                ssize_t resp_len = build_a_response(buf, n, addr.s_addr, resp, sizeof(resp));
                if (resp_len > 0)
                {
                    sendto(fwd->listen_fd, resp, resp_len, 0,
                           (struct sockaddr *)&client_addr, addrlen);
                }
                return;
            }
        }
    }

    /* No local match — forward to upstream */
    if (fwd->upstream_count == 0) return;

    pending_query_t *pq = calloc(1, sizeof(*pq));
    if (!pq) return;

    pq->fwd = fwd;
    memcpy(&pq->client_addr, &client_addr, addrlen);
    pq->client_addrlen = addrlen;
    pq->original_txn_id = (buf[0] << 8) | buf[1];
    pq->upstream_txn_id = fwd->next_txn_id++;
    pq->upstream_index = 0;
    memcpy(pq->query_buf, buf, n);
    pq->query_len = n;

    /* store in pending map (keyed by our upstream txn ID) */
    void *replaced = map_add(fwd->pending_map, &pq->upstream_txn_id, sizeof(uint16_t), pq);
    if (replaced == NULL)
    {
        /* map_add failed */
        free(pq);
        return;
    }
    if (replaced != pq)
    {
        /* evicted old entry with same txn ID (wrap-around after 65536) */
        pending_query_free(replaced);
    }

    send_to_upstream(fwd, pq);
}

/* -------------------------------------------------------------------------- */
/*  Upstream response handler                                                  */
/* -------------------------------------------------------------------------- */

static void on_upstream_response(void *ctx)
{
    dns_forwarder_t *fwd = ctx;

    uint8_t buf[DNS_BUF_SIZE];
    ssize_t n = recvfrom(fwd->upstream_fd, buf, sizeof(buf), 0, NULL, NULL);
    if (n < DNS_HDR_SIZE) return;

    uint16_t txn_id = (buf[0] << 8) | buf[1];

    pending_query_t *pq = map_get(fwd->pending_map, &txn_id, sizeof(uint16_t));
    if (!pq) return; /* unknown txn ID — stale or duplicate response */

    /* cancel the timeout */
    if (pq->timeout)
    {
        tev_clear_timeout(fwd->tev, pq->timeout);
        pq->timeout = NULL;
    }

    /* restore original transaction ID */
    buf[0] = (pq->original_txn_id >> 8) & 0xFF;
    buf[1] = pq->original_txn_id & 0xFF;

    /* send response back to client */
    sendto(fwd->listen_fd, buf, n, 0,
           (struct sockaddr *)&pq->client_addr, pq->client_addrlen);

    /* clean up */
    map_remove(fwd->pending_map, &txn_id, sizeof(uint16_t));
    free(pq);
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                 */
/* -------------------------------------------------------------------------- */

dns_forwarder dns_forwarder_new(tev_handle_t tev, const char *listen_addr, uint16_t listen_port)
{
    dns_forwarder_t *fwd = calloc(1, sizeof(*fwd));
    if (!fwd) return NULL;

    fwd->tev = tev;
    fwd->listen_fd = -1;
    fwd->upstream_fd = -1;
    fwd->inotify_fd = -1;
    fwd->inotify_wd = -1;

    /* create maps */
    fwd->lookup_map = map_create();
    if (!fwd->lookup_map) goto fail;

    fwd->pending_map = map_create();
    if (!fwd->pending_map) goto fail;

    /* parse resolv.conf for upstream nameservers */
    if (parse_resolv_conf(&fwd->upstreams, &fwd->upstream_count) != 0)
    {
        fprintf(stderr, "dns_forwarder: warning: no upstream nameservers found\n");
        /* not fatal — local lookups still work, upstreams can arrive via inotify */
    }

    /* create listen socket */
    fwd->listen_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fwd->listen_fd < 0) goto fail;

    int opt = 1;
    setsockopt(fwd->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(listen_port);
    if (inet_pton(AF_INET, listen_addr, &bind_addr.sin_addr) != 1) goto fail;
    if (bind(fwd->listen_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) goto fail;

    /* create upstream socket */
    fwd->upstream_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fwd->upstream_fd < 0) goto fail;

    /* set up inotify on /etc/ for resolv.conf changes */
    fwd->inotify_fd = inotify_init1(IN_NONBLOCK);
    if (fwd->inotify_fd >= 0)
    {
        fwd->inotify_wd = inotify_add_watch(fwd->inotify_fd, "/etc",
                                              IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE);
        if (fwd->inotify_wd < 0)
        {
            close(fwd->inotify_fd);
            fwd->inotify_fd = -1;
        }
    }
    /* inotify failure is non-fatal — upstreams just won't auto-update */

    /* register tev read handlers */
    if (tev_set_read_handler(tev, fwd->listen_fd, on_client_query, fwd) != 0) goto fail;
    if (tev_set_read_handler(tev, fwd->upstream_fd, on_upstream_response, fwd) != 0) goto fail;
    if (fwd->inotify_fd >= 0)
    {
        tev_set_read_handler(tev, fwd->inotify_fd, on_resolv_conf_changed, fwd);
    }

    return fwd;

fail:
    dns_forwarder_free(fwd);
    return NULL;
}

void dns_forwarder_free(dns_forwarder forwarder)
{
    if (!forwarder) return;
    dns_forwarder_t *fwd = forwarder;

    /* unregister tev handlers and close fds */
    if (fwd->listen_fd >= 0)
    {
        tev_set_read_handler(fwd->tev, fwd->listen_fd, NULL, NULL);
        close(fwd->listen_fd);
    }
    if (fwd->upstream_fd >= 0)
    {
        tev_set_read_handler(fwd->tev, fwd->upstream_fd, NULL, NULL);
        close(fwd->upstream_fd);
    }
    if (fwd->inotify_fd >= 0)
    {
        tev_set_read_handler(fwd->tev, fwd->inotify_fd, NULL, NULL);
        if (fwd->inotify_wd >= 0)
            inotify_rm_watch(fwd->inotify_fd, fwd->inotify_wd);
        close(fwd->inotify_fd);
    }

    /* clean up pending queries (cancels their timeouts) */
    if (fwd->pending_map)
        map_delete(fwd->pending_map, free_pending_cb, NULL);

    /* clean up lookup map (free strdup'd ip values) */
    if (fwd->lookup_map)
        map_delete(fwd->lookup_map, free_lookup_value, NULL);

    if (fwd->upstreams)
        free(fwd->upstreams);
    free(fwd);
}

int dns_forwarder_add_lookup(dns_forwarder forwarder, const char *domain, const char *ip)
{
    dns_forwarder_t *fwd = forwarder;
    if (!fwd || !domain || !ip) return -1;

    /* normalize domain to lowercase */
    char lower[DNS_MAX_NAME + 1];
    int i = 0;
    for (; domain[i] && i < DNS_MAX_NAME; i++)
    {
        lower[i] = (domain[i] >= 'A' && domain[i] <= 'Z') ? domain[i] + ('a' - 'A') : domain[i];
    }
    lower[i] = '\0';

    char *val = strdup(ip);
    if (!val) return -1;

    void *old = map_add(fwd->lookup_map, lower, strlen(lower), val);
    if (old == NULL)
    {
        /* map_add failed */
        free(val);
        return -1;
    }
    if (old != val)
    {
        /* replaced existing entry — free old value */
        free(old);
    }

    return 0;
}

int dns_forwarder_remove_lookup(dns_forwarder forwarder, const char *domain)
{
    dns_forwarder_t *fwd = forwarder;
    if (!fwd || !domain) return -1;

    /* normalize domain to lowercase */
    char lower[DNS_MAX_NAME + 1];
    int i = 0;
    for (; domain[i] && i < DNS_MAX_NAME; i++)
    {
        lower[i] = (domain[i] >= 'A' && domain[i] <= 'Z') ? domain[i] + ('a' - 'A') : domain[i];
    }
    lower[i] = '\0';

    void *old = map_remove(fwd->lookup_map, lower, strlen(lower));
    if (!old) return -1;

    free(old); /* free the strdup'd ip value */
    return 0;
}
