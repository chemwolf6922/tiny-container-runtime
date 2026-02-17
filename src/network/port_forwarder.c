#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "port_forwarder.h"

#include <nftables/libnftables.h>

#include "nft_helper.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Constants                                                                 */
/* ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_RULE_HANDLES 4   /* at most: tcp DNAT + tcp fwd + udp DNAT + udp fwd */

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Data structures                                                           */
/* ═══════════════════════════════════════════════════════════════════════════ */

struct port_forwarder_s
{
    char *table_name;
    char *comment;          /* "tcr-<group_id>" */

    struct in_addr listen_ip;
    uint16_t listen_port;
    struct in_addr target_ip;
    uint16_t target_port;
    int protocols;

    int n_handles;
    struct {
        char chain[16];     /* "prerouting" or "forward" */
        uint64_t handle;
    } handles[MAX_RULE_HANDLES];
};

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: nftables                                                         */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Ensure the prerouting chain exists in the given table.
 * Uses "add" which is idempotent — succeeds even if the chain already exists.
 */
static int ensure_prerouting_chain(struct nft_ctx *nft, const char *table)
{
    return nft_cmd(nft,
                   "add chain inet %s prerouting "
                   "{ type nat hook prerouting priority -100 ; }",
                   table);
}

/**
 * Find the handle of a rule we just added by listing the chain with handles
 * (-a) and searching for our comment.  We look for the *last* matching line
 * because `nft -a list` outputs rules in order and we just appended one.
 *
 * Returns the handle, or 0 on failure.
 */
static uint64_t find_last_rule_handle(struct nft_ctx *nft __attribute__((unused)),
                                      const char *table,
                                      const char *chain, const char *match)
{
    /* List chain with handles */
    char *cmd;
    if (asprintf(&cmd, "list chain inet %s %s", table, chain) < 0)
        return 0;

    /* We need a fresh context to capture output cleanly */
    struct nft_ctx *qnft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!qnft) return 0;
    nft_ctx_buffer_output(qnft);
    nft_ctx_buffer_error(qnft);
    nft_ctx_output_set_flags(qnft, NFT_CTX_OUTPUT_HANDLE);

    int rc = nft_run_cmd_from_buffer(qnft, cmd);
    free(cmd);
    if (rc < 0) {
        nft_ctx_free(qnft);
        return 0;
    }

    const char *output = nft_ctx_get_output_buffer(qnft);
    if (!output) {
        nft_ctx_free(qnft);
        return 0;
    }

    /*
     * Parse line by line, looking for lines that contain `match` AND
     * "# handle <N>".  Keep the last one (the rule we just added).
     *
     * Example line:
     *   tcp dport 8080 dnat ip to 10.88.0.2:80 comment "tcr-mycontainer" # handle 42
     */
    uint64_t last_handle = 0;
    const char *line = output;
    while (line && *line) {
        const char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);

        /* Check if this line contains our match string */
        char *found = memmem(line, len, match, strlen(match));
        if (found) {
            /* Look for "# handle <N>" */
            const char *hp = memmem(line, len, "# handle ", 9);
            if (hp) {
                last_handle = strtoull(hp + 9, NULL, 10);
            }
        }

        line = eol ? eol + 1 : NULL;
    }

    nft_ctx_free(qnft);
    return last_handle;
}

/**
 * Build a match string that uniquely identifies a rule we just added.
 * Includes the protocol, port(s), and comment to avoid false matches.
 *
 * For DNAT rules:   "<proto> dport <lport> dnat ip to <tip>:<tport> comment \"<comment>\""
 * For forward rules: "ip daddr <tip> <proto> dport <tport> accept comment \"<comment>\""
 */
static char *build_dnat_match(const char *proto, uint16_t lport,
                             struct in_addr target_ip, uint16_t tport,
                             struct in_addr listen_ip, const char *comment)
{
    char tip[INET_ADDRSTRLEN], lip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target_ip, tip, sizeof(tip));
    inet_ntop(AF_INET, &listen_ip, lip, sizeof(lip));

    char *buf;
    if (listen_ip.s_addr == htonl(INADDR_ANY)) {
        if (asprintf(&buf, "%s dport %u dnat ip to %s:%u comment \"%s\"",
                     proto, lport, tip, tport, comment) < 0)
            return NULL;
    } else {
        if (asprintf(&buf, "ip daddr %s %s dport %u dnat ip to %s:%u comment \"%s\"",
                     lip, proto, lport, tip, tport, comment) < 0)
            return NULL;
    }
    return buf;
}

static char *build_forward_match(const char *proto,
                                 struct in_addr target_ip, uint16_t tport,
                                 const char *comment)
{
    char tip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target_ip, tip, sizeof(tip));
    char *buf;
    if (asprintf(&buf, "ip daddr %s %s dport %u accept comment \"%s\"",
                 tip, proto, tport, comment) < 0)
        return NULL;
    return buf;
}

/**
 * Add a DNAT + forward rule pair for one protocol and record their handles.
 * Returns 0 on success, -1 on failure.
 */
static int add_rules_for_proto(struct nft_ctx *nft,
                               port_forwarder pf,
                               const char *proto)
{
    char tip[INET_ADDRSTRLEN], lip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pf->target_ip, tip, sizeof(tip));
    inet_ntop(AF_INET, &pf->listen_ip, lip, sizeof(lip));

    /* ── DNAT rule in prerouting chain ── */
    if (pf->listen_ip.s_addr == htonl(INADDR_ANY)) {
        if (nft_cmd(nft,
                    "add rule inet %s prerouting %s dport %u "
                    "dnat ip to %s:%u comment \"%s\"",
                    pf->table_name, proto, pf->listen_port,
                    tip, pf->target_port, pf->comment) < 0)
            return -1;
    } else {
        if (nft_cmd(nft,
                    "add rule inet %s prerouting ip daddr %s %s dport %u "
                    "dnat ip to %s:%u comment \"%s\"",
                    pf->table_name, lip, proto, pf->listen_port,
                    tip, pf->target_port, pf->comment) < 0)
            return -1;
    }

    /* Record DNAT rule handle */
    char *match = build_dnat_match(proto, pf->listen_port,
                                   pf->target_ip, pf->target_port,
                                   pf->listen_ip, pf->comment);
    uint64_t h = match ? find_last_rule_handle(nft, pf->table_name, "prerouting", match) : 0;
    free(match);
    if (h && pf->n_handles < MAX_RULE_HANDLES) {
        snprintf(pf->handles[pf->n_handles].chain,
                 sizeof(pf->handles[0].chain), "prerouting");
        pf->handles[pf->n_handles].handle = h;
        pf->n_handles++;
    }

    /* ── Forward accept rule ── */
    if (nft_cmd(nft,
                "add rule inet %s forward ip daddr %s %s dport %u "
                "accept comment \"%s\"",
                pf->table_name, tip, proto, pf->target_port,
                pf->comment) < 0)
        return -1;

    /* Record forward rule handle */
    match = build_forward_match(proto, pf->target_ip, pf->target_port,
                                pf->comment);
    h = match ? find_last_rule_handle(nft, pf->table_name, "forward", match) : 0;
    free(match);
    if (h && pf->n_handles < MAX_RULE_HANDLES) {
        snprintf(pf->handles[pf->n_handles].chain,
                 sizeof(pf->handles[0].chain), "forward");
        pf->handles[pf->n_handles].handle = h;
        pf->n_handles++;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: cleanup_group — parse handles from nft listing                   */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Delete all rules in the given chain whose output line contains the
 * specified comment tag.  Scans `nft -a list chain` output for
 * 'comment "<tag>"' and extracts the handle number.
 */
static void delete_rules_by_comment(const char *table, const char *chain,
                                    const char *comment_tag)
{
    /* nft -a list chain inet <table> <chain> */
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) return;
    nft_ctx_buffer_output(nft);
    nft_ctx_buffer_error(nft);
    nft_ctx_output_set_flags(nft, NFT_CTX_OUTPUT_HANDLE);

    char *cmd;
    if (asprintf(&cmd, "list chain inet %s %s", table, chain) < 0) {
        nft_ctx_free(nft);
        return;
    }
    if (nft_run_cmd_from_buffer(nft, cmd) < 0) {
        free(cmd);
        nft_ctx_free(nft);
        return;
    }
    free(cmd);

    const char *output = nft_ctx_get_output_buffer(nft);
    if (!output) {
        nft_ctx_free(nft);
        return;
    }

    /*
     * Collect handles first, then delete.
     * (Deleting while iterating could invalidate the listing.)
     */
    int n_delete = 0;
    int cap_delete = 16;
    uint64_t *to_delete = malloc(cap_delete * sizeof(*to_delete));
    if (!to_delete) {
        nft_ctx_free(nft);
        return;
    }

    char *needle;
    if (asprintf(&needle, "comment \"%s\"", comment_tag) < 0) {
        free(to_delete);
        nft_ctx_free(nft);
        return;
    }
    size_t needle_len = strlen(needle);

    const char *line = output;
    while (line && *line) {
        const char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);

        if (memmem(line, len, needle, needle_len)) {
            const char *hp = memmem(line, len, "# handle ", 9);
            if (hp) {
                if (n_delete == cap_delete) {
                    cap_delete *= 2;
                    uint64_t *tmp = realloc(to_delete,
                                            cap_delete * sizeof(*to_delete));
                    if (!tmp) break;
                    to_delete = tmp;
                }
                to_delete[n_delete++] = strtoull(hp + 9, NULL, 10);
            }
        }

        line = eol ? eol + 1 : NULL;
    }

    nft_ctx_free(nft);
    free(needle);

    /* Now delete the collected handles */
    if (n_delete == 0) {
        free(to_delete);
        return;
    }

    struct nft_ctx *del_nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!del_nft) { free(to_delete); return; }
    nft_ctx_buffer_output(del_nft);
    nft_ctx_buffer_error(del_nft);

    for (int i = 0; i < n_delete; i++)
        nft_cmd(del_nft, "delete rule inet %s %s handle %lu",
                table, chain, (unsigned long)to_delete[i]);

    nft_ctx_free(del_nft);
    free(to_delete);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Public API                                                                */
/* ═══════════════════════════════════════════════════════════════════════════ */

port_forwarder port_forwarder_new(
    const char *table_name,
    const char *group_id,
    struct in_addr listen_ip, uint16_t listen_port,
    struct in_addr target_ip, uint16_t target_port,
    int protocols)
{
    if (!table_name || !group_id)
        return NULL;

    if (protocols == 0) {
        fprintf(stderr, "port_forwarder: no protocol specified\n");
        return NULL;
    }

    if ((protocols & ~(PORT_FORWARDER_PROTOCOL_TCP | PORT_FORWARDER_PROTOCOL_UDP)) != 0) {
        fprintf(stderr, "port_forwarder: invalid protocol bitmask\n");
        return NULL;
    }

    if (listen_port == 0 || target_port == 0) {
        fprintf(stderr, "port_forwarder: port must be 1-65535\n");
        return NULL;
    }

    /* Reject localhost — prerouting DNAT only handles external traffic */
    if ((ntohl(listen_ip.s_addr) >> 24) == 127) {
        fprintf(stderr, "port_forwarder: localhost binding is not supported "
                "(prerouting DNAT does not intercept locally generated traffic)\n");
        return NULL;
    }

    /* ── Allocate and populate ── */
    port_forwarder pf = calloc(1, sizeof(*pf));
    if (!pf) return NULL;

    pf->table_name = strdup(table_name);
    if (!pf->table_name) { free(pf); return NULL; }

    /* Build comment: "tcr-<group_id>" */
    if (asprintf(&pf->comment, "tcr-%s", group_id) < 0) {
        free(pf->table_name);
        free(pf);
        return NULL;
    }

    pf->listen_ip   = listen_ip;
    pf->listen_port  = listen_port;
    pf->target_ip    = target_ip;
    pf->target_port  = target_port;
    pf->protocols    = protocols;
    pf->n_handles    = 0;

    /* ── Set up nftables rules ── */
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) goto err;
    nft_ctx_buffer_output(nft);
    nft_ctx_buffer_error(nft);

    /* Ensure prerouting chain exists (idempotent) */
    if (ensure_prerouting_chain(nft, table_name) < 0)
        goto err_nft;

    if (protocols & PORT_FORWARDER_PROTOCOL_TCP) {
        if (add_rules_for_proto(nft, pf, "tcp") < 0)
            goto err_rollback;
    }

    if (protocols & PORT_FORWARDER_PROTOCOL_UDP) {
        if (add_rules_for_proto(nft, pf, "udp") < 0)
            goto err_rollback;
    }

    nft_ctx_free(nft);
    return pf;

err_rollback:
    /* Remove any rules we already added */
    for (int i = 0; i < pf->n_handles; i++)
        nft_cmd(nft, "delete rule inet %s %s handle %lu",
                pf->table_name, pf->handles[i].chain,
                (unsigned long)pf->handles[i].handle);
err_nft:
    nft_ctx_free(nft);
err:
    free(pf->comment);
    free(pf->table_name);
    free(pf);
    return NULL;
}

void port_forwarder_free(port_forwarder forwarder)
{
    if (!forwarder) return;

    if (forwarder->n_handles > 0) {
        struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
        if (nft) {
            nft_ctx_buffer_output(nft);
            nft_ctx_buffer_error(nft);

            for (int i = 0; i < forwarder->n_handles; i++)
                nft_cmd(nft, "delete rule inet %s %s handle %lu",
                        forwarder->table_name, forwarder->handles[i].chain,
                        (unsigned long)forwarder->handles[i].handle);

            nft_ctx_free(nft);
        }
    }

    free(forwarder->comment);
    free(forwarder->table_name);
    free(forwarder);
}

void port_forwarder_cleanup_group(const char *table_name, const char *group_id)
{
    if (!table_name || !group_id)
        return;

    char *comment_tag;
    if (asprintf(&comment_tag, "tcr-%s", group_id) < 0)
        return;

    delete_rules_by_comment(table_name, "prerouting", comment_tag);
    delete_rules_by_comment(table_name, "forward",    comment_tag);
    free(comment_tag);
}
