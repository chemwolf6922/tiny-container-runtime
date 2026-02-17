/**
 * @file test_nat_network_manager.c
 * @brief Integration tests for the NAT network manager module.
 *
 * Must be run as root (bridge/netns/nftables require privileges).
 *
 * Usage: sudo ./test_nat_network_manager
 */
#define _GNU_SOURCE
#include "nat_network_manager.h"
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

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "nat_network_manager_new should succeed");

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_new_null_path(void)
{
    printf("  test_new_null_path... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, NULL);
    CHECK(mgr == NULL, "NULL root_path should fail");

    printf("OK\n");
}

static void test_get_default_network(void)
{
    printf("  test_get_default_network... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    /* NULL name should use default */
    nat_network net = nat_network_manager_get_network(mgr, NULL);
    CHECK(net != NULL, "get default network should succeed");

    /* verify it's a valid network with a gateway */
    struct in_addr gw;
    int rc = nat_network_get_gateway(net, &gw);
    CHECK(rc == 0, "get_gateway should succeed");
    printf("(gw=%s) ", ip_str(gw));

    /* getting again should return the same instance */
    nat_network net2 = nat_network_manager_get_network(mgr, NULL);
    CHECK(net2 == net, "same instance on second get");

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_get_named_network(void)
{
    printf("  test_get_named_network... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net = nat_network_manager_get_network(mgr, "test_net_1");
    CHECK(net != NULL, "get named network should succeed");

    const char *name = nat_network_get_name(net);
    CHECK(name != NULL, "network should have a name");
    CHECK(strcmp(name, "test_net_1") == 0, "name should match");

    struct in_addr gw;
    nat_network_get_gateway(net, &gw);
    printf("(name=%s gw=%s) ", name, ip_str(gw));

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_multiple_networks_unique_subnets(void)
{
    printf("  test_multiple_networks_unique_subnets... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net1 = nat_network_manager_get_network(mgr, "multi_a");
    nat_network net2 = nat_network_manager_get_network(mgr, "multi_b");
    nat_network net3 = nat_network_manager_get_network(mgr, "multi_c");

    CHECK(net1 != NULL && net2 != NULL && net3 != NULL,
          "all networks should be created");
    CHECK(net1 != net2, "different networks should be different instances");
    CHECK(net2 != net3, "different networks should be different instances");

    /* verify each has a different gateway */
    struct in_addr gw1, gw2, gw3;
    nat_network_get_gateway(net1, &gw1);
    nat_network_get_gateway(net2, &gw2);
    nat_network_get_gateway(net3, &gw3);

    CHECK(gw1.s_addr != gw2.s_addr, "gateways should differ (1 vs 2)");
    CHECK(gw2.s_addr != gw3.s_addr, "gateways should differ (2 vs 3)");
    CHECK(gw1.s_addr != gw3.s_addr, "gateways should differ (1 vs 3)");

    printf("(gw1=%s gw2=%s gw3=%s) ", ip_str(gw1), ip_str(gw2), ip_str(gw3));

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_get_idempotent(void)
{
    printf("  test_get_idempotent... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net1 = nat_network_manager_get_network(mgr, "idem_net");
    CHECK(net1 != NULL, "first get should succeed");

    nat_network net2 = nat_network_manager_get_network(mgr, "idem_net");
    CHECK(net2 != NULL, "second get should succeed");
    CHECK(net1 == net2, "should return same instance");

    /* gateway should be stable */
    struct in_addr gw1, gw2;
    nat_network_get_gateway(net1, &gw1);
    nat_network_get_gateway(net2, &gw2);
    CHECK(gw1.s_addr == gw2.s_addr, "gateway should not change");

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_remove_network(void)
{
    printf("  test_remove_network... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net = nat_network_manager_get_network(mgr, "remove_me");
    CHECK(net != NULL, "network creation");

    struct in_addr gw_before;
    nat_network_get_gateway(net, &gw_before);

    /* remove it */
    nat_network_remove_network(mgr, "remove_me");

    /* getting it again should create a new instance */
    nat_network net2 = nat_network_manager_get_network(mgr, "remove_me");
    CHECK(net2 != NULL, "re-creation should succeed");
    /* net2 should be a different instance (net was freed) */
    /* we can't compare pointers since net was freed, but we can verify it works */

    struct in_addr gw_after;
    nat_network_get_gateway(net2, &gw_after);
    printf("(before=%s after=%s) ", ip_str(gw_before), ip_str(gw_after));

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_remove_nonexistent(void)
{
    printf("  test_remove_nonexistent... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    /* should not crash */
    nat_network_remove_network(mgr, "does_not_exist");
    nat_network_remove_network(mgr, NULL);

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_remove_default(void)
{
    printf("  test_remove_default... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net = nat_network_manager_get_network(mgr, NULL);
    CHECK(net != NULL, "default network creation");

    /* remove using NULL (should remove default) */
    nat_network_remove_network(mgr, NULL);

    /* re-create should work */
    nat_network net2 = nat_network_manager_get_network(mgr, NULL);
    CHECK(net2 != NULL, "default re-creation should succeed");

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_allocate_ip_through_manager(void)
{
    printf("  test_allocate_ip_through_manager... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net = nat_network_manager_get_network(mgr, "ip_test");
    CHECK(net != NULL, "network creation");

    /* allocate some IPs */
    struct in_addr ip1, ip2;
    int rc = nat_network_allocate_ip(net, &ip1);
    CHECK(rc == 0, "first allocation should succeed");

    rc = nat_network_allocate_ip(net, &ip2);
    CHECK(rc == 0, "second allocation should succeed");

    CHECK(ip1.s_addr != ip2.s_addr, "IPs should be different");
    printf("(ip1=%s ip2=%s) ", ip_str(ip1), ip_str(ip2));

    /* release and verify reuse */
    rc = nat_network_release_ip(net, ip1);
    CHECK(rc == 0, "release should succeed");

    struct in_addr ip3;
    rc = nat_network_allocate_ip(net, &ip3);
    CHECK(rc == 0, "allocation after release should succeed");
    printf("(ip3=%s) ", ip_str(ip3));

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_create_namespace_through_manager(void)
{
    printf("  test_create_namespace_through_manager... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net = nat_network_manager_get_network(mgr, "ns_test");
    CHECK(net != NULL, "network creation");

    struct in_addr ip;
    int rc = nat_network_allocate_ip(net, &ip);
    CHECK(rc == 0, "IP allocation");

    rc = nat_network_create_network_namespace(net, "tcr_mgr_test", ip);
    CHECK(rc == 0, "namespace creation should succeed");

    printf("(ip=%s) ", ip_str(ip));

    /* verify netns exists */
    struct stat st;
    CHECK(stat("/var/run/netns/tcr_mgr_test", &st) == 0,
          "netns file should exist");

    /* cleanup */
    rc = nat_network_remove_network_namespace(net, "tcr_mgr_test");
    CHECK(rc == 0, "namespace removal should succeed");

    nat_network_release_ip(net, ip);
    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_subnet_slot_reuse(void)
{
    printf("  test_subnet_slot_reuse... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    /* create and remove a network, then exhaust forward slots so
     * allocator wraps around and picks the freed slot */
    nat_network net_a = nat_network_manager_get_network(mgr, "slot_a");
    CHECK(net_a != NULL, "first network created");

    struct in_addr gw_a;
    nat_network_get_gateway(net_a, &gw_a);

    /* remove it — frees its slot */
    nat_network_remove_network(mgr, "slot_a");

    /* re-create with same name — should get a new slot (round-robin) */
    nat_network net_b = nat_network_manager_get_network(mgr, "slot_reuse");
    CHECK(net_b != NULL, "second network created");

    struct in_addr gw_b;
    nat_network_get_gateway(net_b, &gw_b);

    printf("(gw_a=%s gw_b=%s) ", ip_str(gw_a), ip_str(gw_b));

    /* the freed slot 0 is available. The allocator may or may not pick it
     * depending on where next_slot points, so just verify that the
     * remove didn't leave things broken and the network works. */
    struct in_addr ip;
    int rc = nat_network_allocate_ip(net_b, &ip);
    CHECK(rc == 0, "allocation from new network works");
    printf("(ip=%s) ", ip_str(ip));
    nat_network_release_ip(net_b, ip);

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static int foreach_count;
static nat_network foreach_last_net;

static void foreach_counter(nat_network net, void *user_data)
{
    (void)user_data;
    foreach_count++;
    foreach_last_net = net;
}

static void test_foreach_safe_empty(void)
{
    printf("  test_foreach_safe_empty... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    foreach_count = 0;
    int rc = nat_network_manager_foreach_safe(mgr, foreach_counter, NULL);
    CHECK(rc == 0, "foreach on empty manager should succeed");
    CHECK(foreach_count == 0, "should visit 0 networks");

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_foreach_safe_multiple(void)
{
    printf("  test_foreach_safe_multiple... ");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");

    nat_network net1 = nat_network_manager_get_network(mgr, "foreach_a");
    nat_network net2 = nat_network_manager_get_network(mgr, "foreach_b");
    nat_network net3 = nat_network_manager_get_network(mgr, "foreach_c");
    CHECK(net1 != NULL && net2 != NULL && net3 != NULL, "network creation");

    foreach_count = 0;
    int rc = nat_network_manager_foreach_safe(mgr, foreach_counter, NULL);
    CHECK(rc == 0, "foreach should succeed");
    CHECK(foreach_count == 3, "should visit 3 networks");

    /* remove one and verify count drops */
    nat_network_remove_network(mgr, "foreach_b");
    foreach_count = 0;
    rc = nat_network_manager_foreach_safe(mgr, foreach_counter, NULL);
    CHECK(rc == 0, "foreach after remove should succeed");
    CHECK(foreach_count == 2, "should visit 2 networks after removal");

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_foreach_safe_null(void)
{
    printf("  test_foreach_safe_null... ");

    CHECK(nat_network_manager_foreach_safe(NULL, foreach_counter, NULL) == -1,
          "foreach on NULL manager should fail");

    nat_network_manager mgr = nat_network_manager_new(g_tev, test_root);
    CHECK(mgr != NULL, "manager creation");
    CHECK(nat_network_manager_foreach_safe(mgr, NULL, NULL) == -1,
          "foreach with NULL callback should fail");

    nat_network_manager_free(mgr);
    printf("OK\n");
}

static void test_null_manager_ops(void)
{
    printf("  test_null_manager_ops... ");

    /* all operations on NULL should be safe (no crash) */
    CHECK(nat_network_manager_get_network(NULL, "x") == NULL,
          "get on NULL manager should return NULL");
    nat_network_remove_network(NULL, "x");
    nat_network_manager_free(NULL);

    printf("OK\n");
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                       */
/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc > 1) {
        snprintf(test_root, sizeof(test_root), "%s", argv[1]);
        mkdir(test_root, 0755);
    } else {
        snprintf(test_root, sizeof(test_root), "/tmp/tcr_test_natmgr_XXXXXX");
        CHECK(mkdtemp(test_root) != NULL, "mkdtemp failed");
    }

    printf("test_nat_network_manager (root=%s)\n", test_root);
    printf("─────────────────────────────────────────\n");

    g_tev = tev_create_ctx();
    CHECK(g_tev != NULL, "tev_create_ctx");

    test_new_and_free();
    test_new_null_path();
    test_get_default_network();
    test_get_named_network();
    test_multiple_networks_unique_subnets();
    test_get_idempotent();
    test_remove_network();
    test_remove_nonexistent();
    test_remove_default();
    test_allocate_ip_through_manager();
    test_foreach_safe_empty();
    test_foreach_safe_multiple();
    test_foreach_safe_null();
    test_null_manager_ops();
    test_create_namespace_through_manager();
    test_subnet_slot_reuse();

    printf("─────────────────────────────────────────\n");
    printf("All tests passed.\n");

    tev_free_ctx(g_tev);
    rm_rf(test_root);
    return 0;
}
