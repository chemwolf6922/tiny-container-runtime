/**
 * @file test_nat_network.c
 * @brief Integration tests for the NAT network module.
 *
 * Must be run as root (bridge/netns/nftables require privileges).
 *
 * Usage: sudo ./test_nat_network
 *   test dir defaults to /tmp/tcr_test_nat_XXXXXX
 */
#define _GNU_SOURCE
#include "nat_network.h"
#include "test_util.h"

#include <tev/tev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static char test_root[128];
static tev_handle_t g_tev;

static int rm_cb(const char *path, const struct stat *st, int flag,
                 struct FTW *ftw)
{
    (void)st; (void)flag; (void)ftw;
    return remove(path);
}

static void rm_rf(const char *path)
{
    nftw(path, rm_cb, 64, FTW_DEPTH | FTW_PHYS);
}

static const char *ip_str(struct in_addr addr)
{
    static _Thread_local char bufs[4][INET_ADDRSTRLEN];
    static _Thread_local int idx = 0;
    char *buf = bufs[idx++ & 3];
    inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
    return buf;
}

/* -------------------------------------------------------------------------- */
/*  Tests                                                                      */
/* -------------------------------------------------------------------------- */

static void test_new_and_free(void)
{
    printf("  test_new_and_free... ");

    nat_network net = nat_network_new(g_tev, "tcr_test1", "10.99.0.0/24");
    CHECK(net != NULL, "nat_network_new should succeed");

    nat_network_free(net);
    printf("OK\n");
}

static void test_gateway(void)
{
    printf("  test_gateway... ");

    nat_network net = nat_network_new(g_tev, "tcr_test3", "10.99.2.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr gw;
    int rc = nat_network_get_gateway(net, &gw);
    CHECK(rc == 0, "get_gateway should succeed");

    struct in_addr expected;
    inet_pton(AF_INET, "10.99.2.1", &expected);
    CHECK(gw.s_addr == expected.s_addr, "gateway should be .1");
    printf("(gw=%s) ", ip_str(gw));

    nat_network_free(net);
    printf("OK\n");
}

static void test_allocate_ip(void)
{
    printf("  test_allocate_ip... ");

    nat_network net = nat_network_new(g_tev, "tcr_test4", "10.99.3.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr ip1, ip2;
    int rc = nat_network_allocate_ip(net, &ip1);
    CHECK(rc == 0, "first allocation should succeed");

    struct in_addr expected_first;
    inet_pton(AF_INET, "10.99.3.2", &expected_first);
    CHECK(ip1.s_addr == expected_first.s_addr, "first IP should be .2");

    rc = nat_network_allocate_ip(net, &ip2);
    CHECK(rc == 0, "second allocation should succeed");

    struct in_addr expected_second;
    inet_pton(AF_INET, "10.99.3.3", &expected_second);
    CHECK(ip2.s_addr == expected_second.s_addr, "second IP should be .3");

    printf("(ip1=%s ip2=%s) ", ip_str(ip1), ip_str(ip2));

    nat_network_free(net);
    printf("OK\n");
}

static void test_reserve_ip(void)
{
    printf("  test_reserve_ip... ");

    nat_network net = nat_network_new(g_tev, "tcr_test5", "10.99.4.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr reserved;
    inet_pton(AF_INET, "10.99.4.100", &reserved);

    int rc = nat_network_reserve_ip(net, reserved);
    CHECK(rc == 0, "reserve should succeed");

    /* Double reserve should fail */
    rc = nat_network_reserve_ip(net, reserved);
    CHECK(rc < 0, "double reserve should fail");

    /* Allocations should skip the reserved IP */
    for (int i = 0; i < 98; i++) {
        struct in_addr tmp;
        rc = nat_network_allocate_ip(net, &tmp);
        CHECK(rc == 0, "allocation should succeed");
    }

    /* The next allocation should be .101 (skipping .100) */
    struct in_addr next;
    rc = nat_network_allocate_ip(net, &next);
    CHECK(rc == 0, "allocation past reserved IP should succeed");

    struct in_addr expected_skip;
    inet_pton(AF_INET, "10.99.4.101", &expected_skip);
    CHECK(next.s_addr == expected_skip.s_addr,
          "allocation should skip reserved .100");

    printf("(reserved=.100, next=%s) ", ip_str(next));

    nat_network_free(net);
    printf("OK\n");
}

static void test_release_ip(void)
{
    printf("  test_release_ip... ");

    nat_network net = nat_network_new(g_tev, "tcr_test6", "10.99.5.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr ip1;
    int rc = nat_network_allocate_ip(net, &ip1);
    CHECK(rc == 0, "allocate should succeed");

    rc = nat_network_release_ip(net, ip1);
    CHECK(rc == 0, "release should succeed");

    /* Double release should fail */
    rc = nat_network_release_ip(net, ip1);
    CHECK(rc < 0, "double release should fail");

    /* Re-allocate should return the same IP (.2) */
    struct in_addr ip_again;
    rc = nat_network_allocate_ip(net, &ip_again);
    CHECK(rc == 0, "re-allocate should succeed");
    CHECK(ip_again.s_addr == ip1.s_addr,
          "re-allocated IP should be same as released");

    nat_network_free(net);
    printf("OK\n");
}

static void test_invalid_subnet(void)
{
    printf("  test_invalid_subnet... ");

    nat_network net;

    net = nat_network_new(g_tev, "tcr_test_bad", "10.99.0.0/31");
    CHECK(net == NULL, "prefix /31 should fail");

    net = nat_network_new(g_tev, "tcr_test_bad", "10.99.0.0/1");
    CHECK(net == NULL, "prefix /1 should fail");

    net = nat_network_new(g_tev, "tcr_test_bad", "10.99.0.1/24");
    CHECK(net == NULL, "non-zero host bits should fail");

    net = nat_network_new(g_tev, "tcr_test_bad", "garbage");
    CHECK(net == NULL, "garbage subnet should fail");

    printf("OK\n");
}

static void test_reserve_out_of_range(void)
{
    printf("  test_reserve_out_of_range... ");

    nat_network net = nat_network_new(g_tev, "tcr_test7", "10.99.6.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr bad;
    int rc;

    /* .0 is network address — out of range */
    inet_pton(AF_INET, "10.99.6.0", &bad);
    rc = nat_network_reserve_ip(net, bad);
    CHECK(rc < 0, "reserve .0 should fail");

    /* .1 is gateway — out of range */
    inet_pton(AF_INET, "10.99.6.1", &bad);
    rc = nat_network_reserve_ip(net, bad);
    CHECK(rc < 0, "reserve .1 (gateway) should fail");

    /* .255 is broadcast — out of range */
    inet_pton(AF_INET, "10.99.6.255", &bad);
    rc = nat_network_reserve_ip(net, bad);
    CHECK(rc < 0, "reserve .255 should fail");

    /* wrong subnet entirely */
    inet_pton(AF_INET, "192.168.1.50", &bad);
    rc = nat_network_reserve_ip(net, bad);
    CHECK(rc < 0, "reserve IP from wrong subnet should fail");

    nat_network_free(net);
    printf("OK\n");
}

static void test_create_namespace(void)
{
    printf("  test_create_namespace... ");

    nat_network net = nat_network_new(g_tev, "tcr_test8", "10.99.7.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr ip;
    int rc = nat_network_allocate_ip(net, &ip);
    CHECK(rc == 0, "allocate IP");

    rc = nat_network_create_network_namespace(net, "tcr_test_ns1", ip);
    CHECK(rc == 0, "create namespace should succeed");

    /* Verify the netns exists */
    struct stat st;
    rc = stat("/var/run/netns/tcr_test_ns1", &st);
    CHECK(rc == 0, "netns mount point should exist");

    printf("(ns=tcr_test_ns1 ip=%s) ", ip_str(ip));

    nat_network_free(net);

    /* After free, the netns should be cleaned up */
    rc = stat("/var/run/netns/tcr_test_ns1", &st);
    CHECK(rc < 0, "netns should be removed after free");

    printf("OK\n");
}

static void test_create_namespace_idempotent(void)
{
    printf("  test_create_namespace_idempotent... ");

    nat_network net = nat_network_new(g_tev, "tcr_test9", "10.99.8.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr ip;
    int rc = nat_network_allocate_ip(net, &ip);
    CHECK(rc == 0, "allocate IP");

    rc = nat_network_create_network_namespace(net, "tcr_test_ns2", ip);
    CHECK(rc == 0, "first create should succeed");

    /* Recreating same namespace should succeed (idempotent) */
    rc = nat_network_create_network_namespace(net, "tcr_test_ns2", ip);
    CHECK(rc == 0, "second create (idempotent) should succeed");

    nat_network_free(net);
    printf("OK\n");
}

static void test_remove_namespace(void)
{
    printf("  test_remove_namespace... ");

    nat_network net = nat_network_new(g_tev, "tcr_tst10", "10.99.9.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr ip;
    int rc = nat_network_allocate_ip(net, &ip);
    CHECK(rc == 0, "allocate IP");

    rc = nat_network_create_network_namespace(net, "tcr_test_ns3", ip);
    CHECK(rc == 0, "create namespace");

    rc = nat_network_remove_network_namespace(net, "tcr_test_ns3");
    CHECK(rc == 0, "remove namespace should succeed");

    struct stat st;
    rc = stat("/var/run/netns/tcr_test_ns3", &st);
    CHECK(rc < 0, "netns should be removed");

    /* Removing again should fail (not tracked) */
    rc = nat_network_remove_network_namespace(net, "tcr_test_ns3");
    CHECK(rc < 0, "double remove should fail");

    nat_network_free(net);
    printf("OK\n");
}

static void test_multiple_namespaces(void)
{
    printf("  test_multiple_namespaces... ");

    nat_network net = nat_network_new(g_tev, "tcr_tst11", "10.99.10.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr ips[3];
    const char *names[] = { "tcr_test_ns_a", "tcr_test_ns_b", "tcr_test_ns_c" };
    int rc;

    for (int i = 0; i < 3; i++) {
        rc = nat_network_allocate_ip(net, &ips[i]);
        CHECK(rc == 0, "allocate IP");
        rc = nat_network_create_network_namespace(net, names[i], ips[i]);
        CHECK(rc == 0, "create namespace");
    }

    printf("(3 namespaces) ");

    /* Remove middle one */
    rc = nat_network_remove_network_namespace(net, names[1]);
    CHECK(rc == 0, "remove middle namespace");

    /* Free should clean up remaining two */
    nat_network_free(net);

    struct stat st;
    for (int i = 0; i < 3; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/var/run/netns/%s", names[i]);
        rc = stat(path, &st);
        CHECK(rc < 0, "all netns should be cleaned up after free");
    }

    printf("OK\n");
}

static void test_exhaust_ips(void)
{
    printf("  test_exhaust_ips... ");

    nat_network net = nat_network_new(g_tev, "tcr_tst12", "10.99.11.0/24");
    CHECK(net != NULL, "network creation");

    struct in_addr ip;
    int rc;

    /* Allocate all 253 IPs (.2 through .254) */
    for (int i = 0; i < 253; i++) {
        rc = nat_network_allocate_ip(net, &ip);
        CHECK(rc == 0, "allocation should succeed");
    }

    /* Next should fail */
    rc = nat_network_allocate_ip(net, &ip);
    CHECK(rc < 0, "allocation past exhaustion should fail");

    nat_network_free(net);
    printf("OK\n");
}

static void test_recreate_network(void)
{
    printf("  test_recreate_network... ");

    /* Create, free, re-create — should work (always-recreate semantics) */
    nat_network net1 = nat_network_new(g_tev, "tcr_tst13", "10.99.12.0/24");
    CHECK(net1 != NULL, "first creation");
    nat_network_free(net1);

    nat_network net2 = nat_network_new(g_tev, "tcr_tst13", "10.99.12.0/24");
    CHECK(net2 != NULL, "re-creation after free");

    /* Gateway should be consistent */
    struct in_addr gw;
    int rc = nat_network_get_gateway(net2, &gw);
    CHECK(rc == 0, "get_gateway on re-created network");

    struct in_addr expected;
    inet_pton(AF_INET, "10.99.12.1", &expected);
    CHECK(gw.s_addr == expected.s_addr, "gateway should be .1");

    nat_network_free(net2);
    printf("OK\n");
}

static void test_non_24_prefix(void)
{
    printf("  test_non_24_prefix... ");

    nat_network net = nat_network_new(g_tev, "tcr_tst14", "10.100.0.0/16");
    CHECK(net != NULL, "/16 subnet should succeed");

    struct in_addr gw;
    int rc = nat_network_get_gateway(net, &gw);
    CHECK(rc == 0, "get_gateway");

    struct in_addr expected_gw;
    inet_pton(AF_INET, "10.100.0.1", &expected_gw);
    CHECK(gw.s_addr == expected_gw.s_addr, "gateway should be .0.1");

    struct in_addr ip;
    rc = nat_network_allocate_ip(net, &ip);
    CHECK(rc == 0, "allocate from /16");

    struct in_addr expected_ip;
    inet_pton(AF_INET, "10.100.0.2", &expected_ip);
    CHECK(ip.s_addr == expected_ip.s_addr, "first allocated should be .0.2");

    /* Reserve a high IP */
    struct in_addr high;
    inet_pton(AF_INET, "10.100.255.100", &high);
    rc = nat_network_reserve_ip(net, high);
    CHECK(rc == 0, "reserve high IP in /16");

    printf("(gw=%s, ip=%s) ", ip_str(gw), ip_str(ip));

    nat_network_free(net);
    printf("OK\n");
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                       */
/* -------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (getuid() != 0) {
        fprintf(stderr, "error: must be run as root\n");
        return 1;
    }

    if (argc > 1) {
        snprintf(test_root, sizeof(test_root), "%s", argv[1]);
        mkdir(test_root, 0755);
    } else {
        snprintf(test_root, sizeof(test_root), "/tmp/tcr_test_nat_XXXXXX");
        CHECK(mkdtemp(test_root) != NULL, "mkdtemp failed");
    }

    printf("test_nat_network (root=%s)\n", test_root);
    printf("─────────────────────────────────────────\n");

    g_tev = tev_create_ctx();
    CHECK(g_tev != NULL, "tev_create_ctx");

    test_new_and_free();
    test_gateway();
    test_allocate_ip();
    test_reserve_ip();
    test_release_ip();
    test_invalid_subnet();
    test_reserve_out_of_range();
    test_create_namespace();
    test_create_namespace_idempotent();
    test_remove_namespace();
    test_multiple_namespaces();
    test_exhaust_ips();
    test_recreate_network();
    test_non_24_prefix();

    printf("─────────────────────────────────────────\n");
    printf("All tests passed.\n");

    tev_free_ctx(g_tev);
    rm_rf(test_root);
    return 0;
}
