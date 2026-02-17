#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nat_network.h"

#include <tev/xxhash.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/route.h>
#include <nftables/libnftables.h>

#include "nft_helper.h"
#include "common/bitmap.h"

#include <tev/map.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Constants                                                                 */
/* ═══════════════════════════════════════════════════════════════════════════ */

#define NETNS_RUN_DIR   "/var/run/netns"
#define IP_RANGE_START  2

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Data structures                                                           */
/* ═══════════════════════════════════════════════════════════════════════════ */

#define DNS_PORT 53

struct nat_network_s
{
    char *name;            /* network name, also bridge name and nft table name */

    uint32_t subnet_nbo;   /* subnet base address, network byte order */
    uint32_t gateway_nbo;  /* gateway IP (.1), network byte order */
    int prefix_len;
    uint32_t host_mask;    /* (1u << host_bits) - 1, host byte order */

    bitmap_t bitmap;

    map_handle_t namespaces; /* map: ns_name -> (void*)1 sentinel */

    dns_forwarder dns;     /* DNS forwarder on gateway:53 */
};

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: sysctl                                                           */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int enable_ip_forward(void)
{
    int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "nat_network: cannot open ip_forward: %s\n",
                strerror(errno));
        return -1;
    }
    int ok = (write(fd, "1", 1) == 1) ? 0 : -1;
    close(fd);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: veth name derivation (xxhash)                                    */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Derive deterministic veth interface names from the netns name.
 * Output names are at most 11 characters ("veth" + 7 hex = 11), safely
 * within IFNAMSIZ (16).
 */
static void derive_veth_names(const char *ns_name,
                              char host_out[static 12],
                              char temp_out[static 12])
{
    XXH32_hash_t h = XXH32(ns_name, strlen(ns_name), 0);
    snprintf(host_out, 12, "veth%07x", h & 0x0FFFFFFFu);
    snprintf(temp_out, 12, "vtmp%07x", h & 0x0FFFFFFFu);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: network namespace management (direct syscalls)                   */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Create a named network namespace (equivalent to `ip netns add`).
 * Forks a child to unshare(CLONE_NEWNET) and bind-mount the ns.
 */
static int netns_create(const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, name);

    /* Ensure /var/run/netns exists */
    mkdir(NETNS_RUN_DIR, 0755); /* ignore EEXIST */

    /* Remove stale mount / file if any */
    umount2(path, MNT_DETACH);  /* ignore errors */
    unlink(path);               /* ignore errors */

    /* Create mount-point file */
    int fd = open(path, O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, "nat_network: cannot create netns mount point %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    close(fd);

    /* Fork to create the namespace and bind-mount it.
     *
     * unshare(CLONE_NEWNET) moves the calling thread into the new network
     * namespace, which would leave the daemon unable to reach the host
     * network.  By forking, the child performs unshare + bind-mount and
     * exits, while the parent stays in the host namespace untouched.
     * This is also safe when the daemon is multi-threaded (tev event
     * loop), since the parent thread is never affected.
     *
     * A pipe is used to communicate the result back to the parent instead
     * of relying on the child's exit code, because valgrind may override
     * the exit code when it detects "leaks" from inherited library
     * constructors (e.g. libnl). */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        fprintf(stderr, "nat_network: pipe failed: %s\n", strerror(errno));
        unlink(path);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "nat_network: fork failed: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        unlink(path);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        char result = 1;
        if (unshare(CLONE_NEWNET) == 0 &&
            mount("/proc/self/ns/net", path, "none", MS_BIND, NULL) == 0)
            result = 0;
        (void)write(pipefd[1], &result, 1);
        close(pipefd[1]);
        _exit(0);
    }

    close(pipefd[1]);
    char result = 1;
    (void)read(pipefd[0], &result, 1);
    close(pipefd[0]);
    waitpid(pid, NULL, 0);

    if (result != 0) {
        fprintf(stderr, "nat_network: failed to create netns '%s'\n", name);
        unlink(path);
        return -1;
    }
    return 0;
}

/**
 * Delete a named network namespace (equivalent to `ip netns del`).
 * Silently ignores errors.
 */
static void netns_delete(const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, name);
    umount2(path, MNT_DETACH);
    unlink(path);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: netlink socket                                                   */
/* ═══════════════════════════════════════════════════════════════════════════ */

static struct nl_sock *open_rtnl_socket(void)
{
    struct nl_sock *sk = nl_socket_alloc();
    if (!sk) return NULL;
    if (nl_connect(sk, NETLINK_ROUTE) < 0) {
        nl_socket_free(sk);
        return NULL;
    }
    return sk;
}

/**
 * Delete a network interface by name. Ignores errors (interface may not
 * exist).
 */
static void link_delete_by_name(struct nl_sock *sk, const char *name)
{
    struct rtnl_link *link = NULL;
    if (rtnl_link_get_kernel(sk, 0, name, &link) == 0 && link) {
        rtnl_link_delete(sk, link);
        rtnl_link_put(link);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: bridge management (libnl-route)                                  */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Create a Linux bridge, assign the gateway address, and bring it up.
 * Deletes any pre-existing bridge with the same name first.
 */
static int bridge_create(struct nl_sock *sk, const char *name,
                         struct in_addr gateway, int prefix_len)
{
    int err;

    /* Idempotent: delete existing bridge if any */
    link_delete_by_name(sk, name);

    /* Create bridge interface */
    struct rtnl_link *bridge = rtnl_link_alloc();
    if (!bridge) return -1;
    rtnl_link_set_name(bridge, name);
    if (rtnl_link_set_type(bridge, "bridge") < 0) {
        rtnl_link_put(bridge);
        return -1;
    }
    err = rtnl_link_add(sk, bridge, NLM_F_CREATE | NLM_F_EXCL);
    rtnl_link_put(bridge);
    if (err < 0) {
        fprintf(stderr, "nat_network: bridge create failed: %s\n",
                nl_geterror(err));
        return -1;
    }

    /* Look up the new bridge to get its ifindex */
    struct rtnl_link *br = NULL;
    err = rtnl_link_get_kernel(sk, 0, name, &br);
    if (err < 0 || !br) {
        fprintf(stderr, "nat_network: bridge lookup failed: %s\n",
                nl_geterror(err));
        return -1;
    }

    /* Assign gateway IP address */
    struct rtnl_addr *raddr = rtnl_addr_alloc();
    if (!raddr) { rtnl_link_put(br); return -1; }

    rtnl_addr_set_ifindex(raddr, rtnl_link_get_ifindex(br));

    struct nl_addr *local =
        nl_addr_build(AF_INET, &gateway, sizeof(gateway));
    if (!local) { rtnl_addr_put(raddr); rtnl_link_put(br); return -1; }
    nl_addr_set_prefixlen(local, prefix_len);
    rtnl_addr_set_local(raddr, local);
    nl_addr_put(local);

    err = rtnl_addr_add(sk, raddr, 0);
    rtnl_addr_put(raddr);
    if (err < 0) {
        fprintf(stderr, "nat_network: addr add failed: %s\n",
                nl_geterror(err));
        rtnl_link_put(br);
        return -1;
    }

    /* Bring the bridge up */
    struct rtnl_link *changes = rtnl_link_alloc();
    if (!changes) { rtnl_link_put(br); return -1; }
    rtnl_link_set_flags(changes, IFF_UP);
    err = rtnl_link_change(sk, br, changes, 0);
    rtnl_link_put(changes);
    rtnl_link_put(br);
    if (err < 0) {
        fprintf(stderr, "nat_network: bridge bring-up failed: %s\n",
                nl_geterror(err));
        return -1;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: nftables management (libnftables)                                */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Set up the nftables table, chains, and rules for NAT masquerade and
 * forwarding.
 *
 * Equivalent to:
 *   nft add table inet $table
 *   nft add chain inet $table postrouting { type nat hook postrouting priority 100 ; }
 *   nft add chain inet $table forward { type filter hook forward priority 0 ; }
 *   nft add rule inet $table postrouting ip saddr $subnet oifname != "$bridge" masquerade
 *   nft add rule inet $table forward iifname "$bridge" accept
 *   nft add rule inet $table forward oifname "$bridge" ct state related,established accept
 */
static int nft_setup(const char *table, const char *bridge,
                     const char *subnet_cidr)
{
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) return -1;
    nft_ctx_buffer_output(nft);
    nft_ctx_buffer_error(nft);

    int ret = -1;

    /* Delete existing table (idempotent recreation, ignore errors) */
    nft_cmd(nft, "delete table inet %s", table); /* ignore errors */

    if (nft_cmd(nft, "add table inet %s", table) < 0)
        goto out;

    if (nft_cmd(nft,
                "add chain inet %s postrouting "
                "{ type nat hook postrouting priority 100 ; }",
                table) < 0)
        goto out;

    if (nft_cmd(nft,
                "add chain inet %s forward "
                "{ type filter hook forward priority 0 ; }",
                table) < 0)
        goto out;

    /* Masquerade traffic from containers going to external interfaces */
    if (nft_cmd(nft,
                "add rule inet %s postrouting "
                "ip saddr %s oifname != \"%s\" masquerade",
                table, subnet_cidr, bridge) < 0)
        goto out;

    /* Allow forwarding from the bridge */
    if (nft_cmd(nft,
                "add rule inet %s forward iifname \"%s\" accept",
                table, bridge) < 0)
        goto out;

    /* Allow return traffic to containers */
    if (nft_cmd(nft,
                "add rule inet %s forward "
                "oifname \"%s\" ct state related,established accept",
                table, bridge) < 0)
        goto out;

    ret = 0;
out:
    nft_ctx_free(nft);
    return ret;
}

/**
 * Delete the entire nftables table (removes all chains and rules).
 * Silently ignores errors.
 */
static void nft_teardown(const char *table)
{
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) return;
    nft_ctx_buffer_output(nft);
    nft_ctx_buffer_error(nft);

    nft_cmd(nft, "delete table inet %s", table); /* ignore errors */

    nft_ctx_free(nft);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: veth pair (libnl-route)                                          */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Create a veth pair, attach the host end to the bridge, and move the peer
 * into the given network namespace.
 *
 * @param sk          Open NETLINK_ROUTE socket.
 * @param host_name   Name for the host-side veth interface.
 * @param temp_name   Temporary name for the peer (will be renamed inside the
 *                    netns later).
 * @param bridge_name Name of the bridge to attach the host end to.
 * @param ns_fd       File descriptor for the target network namespace.
 * @return 0 on success, -1 on failure (with cleanup).
 */
static int veth_create_and_attach(struct nl_sock *sk,
                                  const char *host_name,
                                  const char *temp_name,
                                  const char *bridge_name,
                                  int ns_fd)
{
    int err;

    /* Idempotent: delete lingering veth with the same name */
    link_delete_by_name(sk, host_name);

    /* Create veth pair */
    struct rtnl_link *veth = rtnl_link_veth_alloc();
    if (!veth) {
        fprintf(stderr, "nat_network: veth alloc failed\n");
        return -1;
    }
    struct rtnl_link *peer = rtnl_link_veth_get_peer(veth);
    rtnl_link_set_name(veth, host_name);
    rtnl_link_set_name(peer, temp_name);
    rtnl_link_put(peer);

    err = rtnl_link_add(sk, veth, NLM_F_CREATE);
    rtnl_link_put(veth);
    if (err < 0) {
        fprintf(stderr, "nat_network: veth create failed: %s\n",
                nl_geterror(err));
        return -1;
    }

    /* Look up bridge to get ifindex */
    struct rtnl_link *br = NULL;
    err = rtnl_link_get_kernel(sk, 0, bridge_name, &br);
    if (err < 0 || !br) {
        fprintf(stderr, "nat_network: bridge '%s' lookup failed\n",
                bridge_name);
        goto err_cleanup;
    }
    int br_ifindex = rtnl_link_get_ifindex(br);
    rtnl_link_put(br);

    /* Attach host end to bridge and bring it up */
    struct rtnl_link *host_link = NULL;
    err = rtnl_link_get_kernel(sk, 0, host_name, &host_link);
    if (err < 0 || !host_link) goto err_cleanup;

    struct rtnl_link *changes = rtnl_link_alloc();
    if (!changes) { rtnl_link_put(host_link); goto err_cleanup; }
    rtnl_link_set_master(changes, br_ifindex);
    rtnl_link_set_flags(changes, IFF_UP);
    err = rtnl_link_change(sk, host_link, changes, 0);
    rtnl_link_put(changes);
    rtnl_link_put(host_link);
    if (err < 0) {
        fprintf(stderr, "nat_network: veth bridge attach failed: %s\n",
                nl_geterror(err));
        goto err_cleanup;
    }

    /* Move peer end into the network namespace */
    struct rtnl_link *peer_link = NULL;
    err = rtnl_link_get_kernel(sk, 0, temp_name, &peer_link);
    if (err < 0 || !peer_link) goto err_cleanup;

    changes = rtnl_link_alloc();
    if (!changes) { rtnl_link_put(peer_link); goto err_cleanup; }
    rtnl_link_set_ns_fd(changes, ns_fd);
    err = rtnl_link_change(sk, peer_link, changes, 0);
    rtnl_link_put(changes);
    rtnl_link_put(peer_link);
    if (err < 0) {
        fprintf(stderr, "nat_network: veth move to netns failed: %s\n",
                nl_geterror(err));
        goto err_cleanup;
    }

    return 0;

err_cleanup:
    link_delete_by_name(sk, host_name);
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: configure network inside a netns (forked child)                  */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Fork a child process that enters the given network namespace and
 * configures the interface:
 *   1. Rename temp veth → eth0
 *   2. Assign IP address with prefix length
 *   3. Bring up eth0 and loopback
 *   4. Add default route via gateway
 *
 * Uses fork + setns so the parent's namespace is never changed.
 * setns(CLONE_NEWNET) would move the calling thread into the target
 * netns, making it unable to perform host-side netlink operations.
 * Forking isolates this side-effect in a short-lived child process.
 */
static int configure_netns_internal(const char *netns_name,
                                    const char *temp_name,
                                    struct in_addr ip,
                                    struct in_addr gateway,
                                    int prefix_len)
{
    char ns_path[PATH_MAX];
    snprintf(ns_path, sizeof(ns_path), "%s/%s", NETNS_RUN_DIR, netns_name);

    /* A pipe communicates the result back to the parent instead of
     * relying on the child's exit code (valgrind may override it). */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        fprintf(stderr, "nat_network: pipe failed: %s\n", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "nat_network: fork failed: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* ── Child process: configure inside the network namespace ── */
        close(pipefd[0]);
        char result = 1; /* assume failure */

        int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (ns_fd < 0) goto child_done;
        if (setns(ns_fd, CLONE_NEWNET) < 0) { close(ns_fd); goto child_done; }
        close(ns_fd);

        struct nl_sock *sk = nl_socket_alloc();
        if (!sk) goto child_done;
        if (nl_connect(sk, NETLINK_ROUTE) < 0) { nl_socket_free(sk); goto child_done; }

        int err;
        struct rtnl_link *changes;

        /* 1. Rename temp interface → eth0 */
        struct rtnl_link *tmp = NULL;
        err = rtnl_link_get_kernel(sk, 0, temp_name, &tmp);
        if (err < 0 || !tmp) { nl_socket_free(sk); goto child_done; }

        changes = rtnl_link_alloc();
        if (!changes) { rtnl_link_put(tmp); nl_socket_free(sk); goto child_done; }
        rtnl_link_set_name(changes, "eth0");
        err = rtnl_link_change(sk, tmp, changes, 0);
        rtnl_link_put(changes);
        rtnl_link_put(tmp);
        if (err < 0) { nl_socket_free(sk); goto child_done; }

        /* 2. Look up eth0 */
        struct rtnl_link *eth0 = NULL;
        err = rtnl_link_get_kernel(sk, 0, "eth0", &eth0);
        if (err < 0 || !eth0) { nl_socket_free(sk); goto child_done; }
        int eth0_idx = rtnl_link_get_ifindex(eth0);

        /* 3. Assign IP address */
        struct rtnl_addr *raddr = rtnl_addr_alloc();
        if (!raddr) { rtnl_link_put(eth0); nl_socket_free(sk); goto child_done; }
        rtnl_addr_set_ifindex(raddr, eth0_idx);

        struct nl_addr *local = nl_addr_build(AF_INET, &ip, sizeof(ip));
        if (!local) {
            rtnl_addr_put(raddr);
            rtnl_link_put(eth0);
            nl_socket_free(sk);
            goto child_done;
        }
        nl_addr_set_prefixlen(local, prefix_len);
        rtnl_addr_set_local(raddr, local);
        nl_addr_put(local);

        err = rtnl_addr_add(sk, raddr, 0);
        rtnl_addr_put(raddr);
        if (err < 0) { rtnl_link_put(eth0); nl_socket_free(sk); goto child_done; }

        /* 4. Bring up eth0 */
        changes = rtnl_link_alloc();
        if (!changes) { rtnl_link_put(eth0); nl_socket_free(sk); goto child_done; }
        rtnl_link_set_flags(changes, IFF_UP);
        err = rtnl_link_change(sk, eth0, changes, 0);
        rtnl_link_put(eth0);
        if (err < 0) { rtnl_link_put(changes); nl_socket_free(sk); goto child_done; }

        /* 5. Bring up loopback */
        struct rtnl_link *lo = NULL;
        if (rtnl_link_get_kernel(sk, 0, "lo", &lo) == 0 && lo) {
            rtnl_link_change(sk, lo, changes, 0);
            rtnl_link_put(lo);
        }
        rtnl_link_put(changes);

        /* 6. Add default route via gateway */
        struct rtnl_route *route = rtnl_route_alloc();
        if (!route) { nl_socket_free(sk); goto child_done; }

        rtnl_route_set_family(route, AF_INET);
        rtnl_route_set_table(route, RT_TABLE_MAIN);
        rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);

        struct in_addr any = { .s_addr = INADDR_ANY };
        struct nl_addr *dst = nl_addr_build(AF_INET, &any, sizeof(any));
        if (!dst) { rtnl_route_put(route); nl_socket_free(sk); goto child_done; }
        nl_addr_set_prefixlen(dst, 0);
        rtnl_route_set_dst(route, dst);
        nl_addr_put(dst);

        struct rtnl_nexthop *nh = rtnl_route_nh_alloc();
        if (!nh) { rtnl_route_put(route); nl_socket_free(sk); goto child_done; }

        struct nl_addr *gw = nl_addr_build(AF_INET, &gateway, sizeof(gateway));
        if (!gw) {
            rtnl_route_nh_free(nh);
            rtnl_route_put(route);
            nl_socket_free(sk);
            goto child_done;
        }
        rtnl_route_nh_set_gateway(nh, gw);
        rtnl_route_nh_set_ifindex(nh, eth0_idx);
        nl_addr_put(gw);

        rtnl_route_add_nexthop(route, nh);
        /* nh is now owned by route, do not free separately */

        err = rtnl_route_add(sk, route, 0);
        rtnl_route_put(route);
        nl_socket_free(sk);

        result = (err < 0) ? 1 : 0;

child_done:
        (void)write(pipefd[1], &result, 1);
        close(pipefd[1]);
        _exit(0);
    }

    /* ── Parent: wait for child ── */
    close(pipefd[1]);
    char result = 1;
    (void)read(pipefd[0], &result, 1);
    close(pipefd[0]);
    waitpid(pid, NULL, 0);

    if (result != 0) {
        fprintf(stderr,
                "nat_network: netns configuration failed for '%s'\n",
                netns_name);
        return -1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: namespace tracking (tev/map)                                     */
/* ═══════════════════════════════════════════════════════════════════════════ */

static bool ns_is_tracked(nat_network network, const char *name)
{
    return map_has(network->namespaces, (void *)name, strlen(name));
}

static int ns_track(nat_network network, const char *name)
{
    void *prev = map_add(network->namespaces,
                         (void *)name, strlen(name), (void *)1);
    /* map_add returns NULL on allocation failure */
    return prev == NULL ? -1 : 0;
}

static void ns_untrack(nat_network network, const char *name)
{
    map_remove(network->namespaces, (void *)name, strlen(name));
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Public API                                                                */
/* ═══════════════════════════════════════════════════════════════════════════ */

nat_network nat_network_new(tev_handle_t tev, const char *name, const char *subnet)
{
    if (!tev || !name || !subnet) return NULL;

    /* ── Parse subnet ── */
    char addr_str[INET_ADDRSTRLEN];
    int prefix;
    if (sscanf(subnet, "%15[^/]/%d", addr_str, &prefix) != 2 ||
        prefix < 2 || prefix > 30) {
        fprintf(stderr, "nat_network: invalid subnet (need /<2..30>)\n");
        return NULL;
    }

    int host_bits = 32 - prefix;
    uint32_t host_mask = (1u << host_bits) - 1u;

    struct in_addr subnet_addr;
    if (inet_pton(AF_INET, addr_str, &subnet_addr) != 1) {
        fprintf(stderr, "nat_network: invalid subnet address: %s\n", addr_str);
        return NULL;
    }

    if (ntohl(subnet_addr.s_addr) & host_mask) {
        fprintf(stderr, "nat_network: host bits must be zero in subnet address\n");
        return NULL;
    }

    struct in_addr gateway;
    gateway.s_addr = htonl(ntohl(subnet_addr.s_addr) | 1u);

    /* ── Allocate struct ── */
    struct nat_network_s *net = calloc(1, sizeof(*net));
    if (!net) return NULL;

    net->name = strdup(name);
    if (!net->name) { free(net); return NULL; }

    net->subnet_nbo = subnet_addr.s_addr;
    net->gateway_nbo = gateway.s_addr;
    net->prefix_len = prefix;
    net->host_mask = host_mask;
    net->namespaces = map_create();
    if (!net->namespaces) { free(net->name); free(net); return NULL; }

    net->bitmap = bitmap_create(1 << host_bits);
    if (!net->bitmap) goto err_free;

    /* Mark reserved addresses: .0 (network), .1 (gateway), last (broadcast) */
    bitmap_set(net->bitmap, 0);
    bitmap_set(net->bitmap, 1);
    bitmap_set(net->bitmap, (1 << host_bits) - 1);

    /* ── Create bridge ── */
    struct nl_sock *sk = open_rtnl_socket();
    if (!sk) {
        fprintf(stderr, "nat_network: cannot open netlink socket\n");
        goto err_free;
    }
    if (bridge_create(sk, name, gateway, prefix) < 0) {
        nl_socket_free(sk);
        goto err_free;
    }
    nl_socket_free(sk);

    /* ── Enable IP forwarding ── */
    if (enable_ip_forward() < 0)
        goto err_teardown;

    /* ── Set up nftables ── */
    if (nft_setup(name, name, subnet) < 0)
        goto err_teardown;

    /* ── Create DNS forwarder on gateway:53 ── */
    {
        char gw_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &gateway, gw_str, sizeof(gw_str));
        net->dns = dns_forwarder_new(tev, gw_str, DNS_PORT);
        if (!net->dns)
        {
            fprintf(stderr, "nat_network: failed to create DNS forwarder on %s:%d\n",
                    gw_str, DNS_PORT);
            goto err_teardown;
        }
    }

    return net;

err_teardown:
    {
        dns_forwarder_free(net->dns);
        struct nl_sock *cleanup_sk = open_rtnl_socket();
        if (cleanup_sk) {
            link_delete_by_name(cleanup_sk, name);
            nl_socket_free(cleanup_sk);
        }
        nft_teardown(name);
    }
err_free:
    map_delete(net->namespaces, NULL, NULL);
    bitmap_free(net->bitmap);
    free(net->name);
    free(net);
    return NULL;
}

void nat_network_free(nat_network network)
{
    if (!network) return;

    struct nl_sock *sk = open_rtnl_socket();

    /* Remove all tracked namespaces (deleting the netns auto-destroys the
       veth pair, but we also explicitly delete the host-side veth in case
       the netns was kept alive by another process). */
    {
        map_entry_t entry;
        map_forEach(network->namespaces, entry) {
            char ns_name[PATH_MAX];
            size_t len = entry.key.len < sizeof(ns_name) - 1
                       ? entry.key.len : sizeof(ns_name) - 1;
            memcpy(ns_name, entry.key.key, len);
            ns_name[len] = '\0';

            if (sk) {
                char veth_host[12], veth_temp[12];
                derive_veth_names(ns_name, veth_host, veth_temp);
                link_delete_by_name(sk, veth_host);
            }
            netns_delete(ns_name);
        }
    }

    /* Delete bridge */
    if (sk) {
        link_delete_by_name(sk, network->name);
        nl_socket_free(sk);
    }

    /* Delete nftables table */
    nft_teardown(network->name);

    dns_forwarder_free(network->dns);
    map_delete(network->namespaces, NULL, NULL);
    bitmap_free(network->bitmap);
    free(network->name);
    free(network);
}

const char *nat_network_get_name(nat_network network)
{
    if (!network) return NULL;
    return network->name;
}

dns_forwarder nat_network_get_dns_forwarder(nat_network network)
{
    if (!network) return NULL;
    return network->dns;
}

int nat_network_get_gateway(nat_network network, struct in_addr *out)
{
    if (!network || !out) return -1;
    out->s_addr = network->gateway_nbo;
    return 0;
}

int nat_network_allocate_ip(nat_network network, struct in_addr *out)
{
    if (!network || !out) return -1;

    int bit = bitmap_find_first_free(network->bitmap);
    if (bit < 0 || bit < IP_RANGE_START) {
        fprintf(stderr, "nat_network: no available IPs in subnet\n");
        return -1;
    }
    bitmap_set(network->bitmap, bit);
    out->s_addr = htonl(ntohl(network->subnet_nbo) | (uint32_t)bit);
    return 0;
}

int nat_network_reserve_ip(nat_network network, struct in_addr ip)
{
    if (!network) return -1;

    /* Verify the IP belongs to this subnet */
    uint32_t ip_hbo = ntohl(ip.s_addr);
    uint32_t subnet_hbo = ntohl(network->subnet_nbo);
    if ((ip_hbo & ~network->host_mask) != (subnet_hbo & ~network->host_mask)) {
        fprintf(stderr, "nat_network: IP not in subnet\n");
        return -1;
    }

    int host = (int)(ip_hbo & network->host_mask);
    int range_end = bitmap_total_bits(network->bitmap) - 2;
    if (host < IP_RANGE_START || host > range_end) {
        fprintf(stderr, "nat_network: IP .%d out of allocatable range\n", host);
        return -1;
    }
    if (bitmap_test(network->bitmap, host)) {
        fprintf(stderr, "nat_network: IP already allocated\n");
        return -1;
    }

    bitmap_set(network->bitmap, host);
    return 0;
}

int nat_network_release_ip(nat_network network, struct in_addr ip)
{
    if (!network) return -1;

    uint32_t ip_hbo = ntohl(ip.s_addr);
    uint32_t subnet_hbo = ntohl(network->subnet_nbo);
    if ((ip_hbo & ~network->host_mask) != (subnet_hbo & ~network->host_mask)) {
        fprintf(stderr, "nat_network: IP not in subnet\n");
        return -1;
    }

    int host = (int)(ip_hbo & network->host_mask);
    int range_end = bitmap_total_bits(network->bitmap) - 2;
    if (host < IP_RANGE_START || host > range_end) {
        fprintf(stderr, "nat_network: IP .%d out of allocatable range\n", host);
        return -1;
    }
    if (!bitmap_test(network->bitmap, host)) {
        fprintf(stderr, "nat_network: IP not currently allocated\n");
        return -1;
    }

    bitmap_clear(network->bitmap, host);
    return 0;
}

int nat_network_create_network_namespace(nat_network network,
                                         const char *namespace_name,
                                         struct in_addr ip)
{
    if (!network || !namespace_name) return -1;

    /* Validate IP is in range and allocated */
    uint32_t ip_hbo = ntohl(ip.s_addr);
    int host = (int)(ip_hbo & network->host_mask);
    int range_end = bitmap_total_bits(network->bitmap) - 2;
    if (host < IP_RANGE_START || host > range_end) {
        fprintf(stderr, "nat_network: IP not in valid range\n");
        return -1;
    }
    if (!bitmap_test(network->bitmap, host)) {
        fprintf(stderr,
                "nat_network: IP not allocated; call allocate_ip/reserve_ip first\n");
        return -1;
    }

    char veth_host[12], veth_temp[12];
    derive_veth_names(namespace_name, veth_host, veth_temp);

    /* Remove from tracking if already present (idempotent recreation) */
    ns_untrack(network, namespace_name);

    struct nl_sock *sk = open_rtnl_socket();
    if (!sk) return -1;

    /* Clean up any pre-existing veth and netns */
    link_delete_by_name(sk, veth_host);
    netns_delete(namespace_name);

    /* Create fresh network namespace */
    if (netns_create(namespace_name) < 0) {
        nl_socket_free(sk);
        return -1;
    }

    /* Open netns fd for moving the veth peer */
    char ns_path[PATH_MAX];
    snprintf(ns_path, sizeof(ns_path), "%s/%s", NETNS_RUN_DIR, namespace_name);
    int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (ns_fd < 0) {
        fprintf(stderr, "nat_network: cannot open netns '%s': %s\n",
                namespace_name, strerror(errno));
        netns_delete(namespace_name);
        nl_socket_free(sk);
        return -1;
    }

    /* Create veth pair, attach host end to bridge, move peer into netns */
    int ret = veth_create_and_attach(sk, veth_host, veth_temp,
                                     network->name, ns_fd);
    nl_socket_free(sk);
    close(ns_fd);

    if (ret < 0) {
        netns_delete(namespace_name);
        return -1;
    }

    /* Configure inside the netns: rename → eth0, IP, loopback, routes */
    struct in_addr gw;
    gw.s_addr = network->gateway_nbo;
    ret = configure_netns_internal(namespace_name, veth_temp,
                                   ip, gw, network->prefix_len);
    if (ret < 0) {
        /* Rollback: delete the veth (host side) and the netns */
        sk = open_rtnl_socket();
        if (sk) {
            link_delete_by_name(sk, veth_host);
            nl_socket_free(sk);
        }
        netns_delete(namespace_name);
        return -1;
    }

    /* Track the namespace */
    if (ns_track(network, namespace_name) < 0) {
        /* Allocation failure during tracking — still rollback */
        sk = open_rtnl_socket();
        if (sk) {
            link_delete_by_name(sk, veth_host);
            nl_socket_free(sk);
        }
        netns_delete(namespace_name);
        return -1;
    }

    return 0;
}

int nat_network_remove_network_namespace(nat_network network,
                                         const char *namespace_name)
{
    if (!network || !namespace_name) return -1;

    if (!ns_is_tracked(network, namespace_name)) {
        fprintf(stderr, "nat_network: namespace '%s' not tracked\n",
                namespace_name);
        return -1;
    }

    /* Delete host-side veth (in case the netns is held by another process) */
    char veth_host[12], veth_temp[12];
    derive_veth_names(namespace_name, veth_host, veth_temp);
    struct nl_sock *sk = open_rtnl_socket();
    if (sk) {
        link_delete_by_name(sk, veth_host);
        nl_socket_free(sk);
    }

    /* Delete the network namespace */
    netns_delete(namespace_name);

    /* Remove from tracking */
    ns_untrack(network, namespace_name);

    return 0;
}
