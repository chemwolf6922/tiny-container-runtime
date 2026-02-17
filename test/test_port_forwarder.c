/**
 * @file test_port_forwarder.c
 * @brief Integration tests for the port forwarder module.
 *
 * Must be run as root (nftables requires privileges).
 * Requires an existing nftables table — we create a temporary one for testing.
 *
 * Usage: sudo ./test_port_forwarder
 */
#define _GNU_SOURCE
#include "port_forwarder.h"
#include "test_util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nftables/libnftables.h>

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

#define TEST_TABLE "tcr_pf_test"

static struct in_addr ip(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return a;
}

static const struct in_addr INADDR_ANY_V = { .s_addr = 0 };

/**
 * Create the test nftables table with a forward chain.
 * (port_forwarder lazily creates the prerouting chain.)
 */
static void nft_test_setup(void)
{
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    CHECK(nft != NULL, "nft_ctx_new");
    nft_ctx_buffer_output(nft);
    nft_ctx_buffer_error(nft);

    /* Clean slate */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "delete table inet %s", TEST_TABLE);
    nft_run_cmd_from_buffer(nft, cmd); /* ignore errors */

    snprintf(cmd, sizeof(cmd), "add table inet %s", TEST_TABLE);
    CHECK(nft_run_cmd_from_buffer(nft, cmd) >= 0, "create test table");

    snprintf(cmd, sizeof(cmd),
             "add chain inet %s forward "
             "{ type filter hook forward priority 0 ; }",
             TEST_TABLE);
    CHECK(nft_run_cmd_from_buffer(nft, cmd) >= 0, "create forward chain");

    nft_ctx_free(nft);
}

/**
 * Tear down the test nftables table.
 */
static void nft_test_teardown(void)
{
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) return;
    nft_ctx_buffer_output(nft);
    nft_ctx_buffer_error(nft);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "delete table inet %s", TEST_TABLE);
    nft_run_cmd_from_buffer(nft, cmd); /* ignore errors */

    nft_ctx_free(nft);
}

/**
 * Count rules containing the given substring in the specified chain.
 */
static int count_rules(const char *chain, const char *needle)
{
    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) return -1;
    nft_ctx_buffer_output(nft);
    nft_ctx_buffer_error(nft);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "list chain inet %s %s", TEST_TABLE, chain);
    if (nft_run_cmd_from_buffer(nft, cmd) < 0) {
        nft_ctx_free(nft);
        return -1;
    }

    const char *output = nft_ctx_get_output_buffer(nft);
    int count = 0;
    if (output) {
        const char *p = output;
        size_t nlen = strlen(needle);
        while ((p = strstr(p, needle)) != NULL) {
            count++;
            p += nlen;
        }
    }

    nft_ctx_free(nft);
    return count;
}

/* -------------------------------------------------------------------------- */
/*  Tests                                                                      */
/* -------------------------------------------------------------------------- */

static void test_new_tcp(void)
{
    printf("  test_new_tcp... ");

    port_forwarder pf = port_forwarder_new(
        TEST_TABLE, "test1",
        INADDR_ANY_V, 8080,
        ip("10.88.0.2"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf != NULL, "port_forwarder_new should succeed");

    /* Verify DNAT rule exists in prerouting */
    CHECK(count_rules("prerouting", "\"tcr-test1\"") == 1,
          "should have 1 DNAT rule in prerouting");

    /* Verify forward rule exists */
    CHECK(count_rules("forward", "\"tcr-test1\"") == 1,
          "should have 1 forward rule");

    port_forwarder_free(pf);

    /* After free, rules should be gone */
    CHECK(count_rules("prerouting", "\"tcr-test1\"") == 0,
          "DNAT rule should be removed after free");
    CHECK(count_rules("forward", "\"tcr-test1\"") == 0,
          "forward rule should be removed after free");

    printf("OK\n");
}

static void test_new_udp(void)
{
    printf("  test_new_udp... ");

    port_forwarder pf = port_forwarder_new(
        TEST_TABLE, "test2",
        INADDR_ANY_V, 5353,
        ip("10.88.0.3"), 53,
        PORT_FORWARDER_PROTOCOL_UDP);
    CHECK(pf != NULL, "port_forwarder_new should succeed for UDP");

    CHECK(count_rules("prerouting", "\"tcr-test2\"") == 1,
          "should have 1 DNAT rule");
    CHECK(count_rules("forward", "\"tcr-test2\"") == 1,
          "should have 1 forward rule");

    port_forwarder_free(pf);
    printf("OK\n");
}

static void test_new_both_protocols(void)
{
    printf("  test_new_both_protocols... ");

    port_forwarder pf = port_forwarder_new(
        TEST_TABLE, "test3",
        INADDR_ANY_V, 9000,
        ip("10.88.0.4"), 9000,
        PORT_FORWARDER_PROTOCOL_TCP | PORT_FORWARDER_PROTOCOL_UDP);
    CHECK(pf != NULL, "port_forwarder_new should succeed for TCP+UDP");

    CHECK(count_rules("prerouting", "\"tcr-test3\"") == 2,
          "should have 2 DNAT rules (tcp + udp)");
    CHECK(count_rules("forward", "\"tcr-test3\"") == 2,
          "should have 2 forward rules (tcp + udp)");

    port_forwarder_free(pf);

    CHECK(count_rules("prerouting", "\"tcr-test3\"") == 0,
          "all rules should be removed after free");
    CHECK(count_rules("forward", "\"tcr-test3\"") == 0,
          "all forward rules should be removed after free");

    printf("OK\n");
}

static void test_specific_listen_ip(void)
{
    printf("  test_specific_listen_ip... ");

    port_forwarder pf = port_forwarder_new(
        TEST_TABLE, "test4",
        ip("192.168.1.10"), 443,
        ip("10.88.0.5"), 443,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf != NULL, "port_forwarder_new with specific listen IP");

    /* Verify the rule contains ip daddr */
    CHECK(count_rules("prerouting", "ip daddr 192.168.1.10") == 1,
          "DNAT rule should match specific listen IP");

    port_forwarder_free(pf);
    printf("OK\n");
}

static void test_reject_localhost(void)
{
    printf("  test_reject_localhost... ");

    port_forwarder pf = port_forwarder_new(
        TEST_TABLE, "test5",
        ip("127.0.0.1"), 8080,
        ip("10.88.0.6"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf == NULL, "localhost binding should be rejected");

    pf = port_forwarder_new(
        TEST_TABLE, "test5b",
        ip("127.1.2.3"), 8080,
        ip("10.88.0.6"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf == NULL, "127.x.x.x should be rejected");

    printf("OK\n");
}

static void test_reject_invalid_args(void)
{
    printf("  test_reject_invalid_args... ");

    /* Zero port */
    port_forwarder pf = port_forwarder_new(
        TEST_TABLE, "test6",
        INADDR_ANY_V, 0,
        ip("10.88.0.7"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf == NULL, "zero listen port should be rejected");

    pf = port_forwarder_new(
        TEST_TABLE, "test6",
        INADDR_ANY_V, 8080,
        ip("10.88.0.7"), 0,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf == NULL, "zero target port should be rejected");

    /* No protocol */
    pf = port_forwarder_new(
        TEST_TABLE, "test6",
        INADDR_ANY_V, 8080,
        ip("10.88.0.7"), 80,
        0);
    CHECK(pf == NULL, "zero protocol should be rejected");

    /* Invalid protocol bits */
    pf = port_forwarder_new(
        TEST_TABLE, "test6",
        INADDR_ANY_V, 8080,
        ip("10.88.0.7"), 80,
        0x04);
    CHECK(pf == NULL, "invalid protocol bits should be rejected");

    /* NULL table/group */
    pf = port_forwarder_new(
        NULL, "test6",
        INADDR_ANY_V, 8080,
        ip("10.88.0.7"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf == NULL, "NULL table should be rejected");

    pf = port_forwarder_new(
        TEST_TABLE, NULL,
        INADDR_ANY_V, 8080,
        ip("10.88.0.7"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf == NULL, "NULL group_id should be rejected");

    printf("OK\n");
}

static void test_cleanup_group(void)
{
    printf("  test_cleanup_group... ");

    /* Create multiple forwarders with the same group_id */
    port_forwarder pf1 = port_forwarder_new(
        TEST_TABLE, "groupA",
        INADDR_ANY_V, 8081,
        ip("10.88.0.10"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf1 != NULL, "first forwarder");

    port_forwarder pf2 = port_forwarder_new(
        TEST_TABLE, "groupA",
        INADDR_ANY_V, 8082,
        ip("10.88.0.10"), 8080,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf2 != NULL, "second forwarder");

    port_forwarder pf3 = port_forwarder_new(
        TEST_TABLE, "groupA",
        INADDR_ANY_V, 5353,
        ip("10.88.0.10"), 53,
        PORT_FORWARDER_PROTOCOL_UDP);
    CHECK(pf3 != NULL, "third forwarder");

    CHECK(count_rules("prerouting", "\"tcr-groupA\"") == 3,
          "should have 3 DNAT rules total");
    CHECK(count_rules("forward", "\"tcr-groupA\"") == 3,
          "should have 3 forward rules total");

    /* Cleanup group — removes ALL rules for groupA */
    port_forwarder_cleanup_group(TEST_TABLE, "groupA");

    CHECK(count_rules("prerouting", "\"tcr-groupA\"") == 0,
          "cleanup should remove all DNAT rules");
    CHECK(count_rules("forward", "\"tcr-groupA\"") == 0,
          "cleanup should remove all forward rules");

    /*
     * Note: after cleanup_group, the port_forwarder objects are invalidated.
     * But free should still be safe (handles will just fail silently).
     */
    port_forwarder_free(pf1);
    port_forwarder_free(pf2);
    port_forwarder_free(pf3);

    printf("OK\n");
}

static void test_cleanup_group_isolation(void)
{
    printf("  test_cleanup_group_isolation... ");

    /* Two different groups */
    port_forwarder pf_a = port_forwarder_new(
        TEST_TABLE, "grpX",
        INADDR_ANY_V, 9001,
        ip("10.88.0.20"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf_a != NULL, "group X forwarder");

    port_forwarder pf_b = port_forwarder_new(
        TEST_TABLE, "grpY",
        INADDR_ANY_V, 9002,
        ip("10.88.0.21"), 80,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf_b != NULL, "group Y forwarder");

    /* Cleanup only group X */
    port_forwarder_cleanup_group(TEST_TABLE, "grpX");

    CHECK(count_rules("prerouting", "\"tcr-grpX\"") == 0,
          "group X rules should be gone");
    CHECK(count_rules("prerouting", "\"tcr-grpY\"") == 1,
          "group Y rules should remain");

    port_forwarder_free(pf_a);
    port_forwarder_free(pf_b);

    CHECK(count_rules("prerouting", "\"tcr-grpY\"") == 0,
          "group Y rules should be gone after free");

    printf("OK\n");
}

static void test_free_null(void)
{
    printf("  test_free_null... ");
    port_forwarder_free(NULL); /* should not crash */
    printf("OK\n");
}

static void test_multiple_forwarders_same_group(void)
{
    printf("  test_multiple_forwarders_same_group... ");

    port_forwarder pf1 = port_forwarder_new(
        TEST_TABLE, "multi",
        INADDR_ANY_V, 3000,
        ip("10.88.0.30"), 3000,
        PORT_FORWARDER_PROTOCOL_TCP);
    CHECK(pf1 != NULL, "first");

    port_forwarder pf2 = port_forwarder_new(
        TEST_TABLE, "multi",
        INADDR_ANY_V, 3001,
        ip("10.88.0.30"), 3001,
        PORT_FORWARDER_PROTOCOL_TCP | PORT_FORWARDER_PROTOCOL_UDP);
    CHECK(pf2 != NULL, "second (tcp+udp)");

    /* pf1: 1 DNAT + 1 fwd = 2 rules
     * pf2: 2 DNAT + 2 fwd = 4 rules
     * total tagged "tcr-multi": 3 in prerouting, 3 in forward */
    CHECK(count_rules("prerouting", "\"tcr-multi\"") == 3,
          "3 DNAT rules");
    CHECK(count_rules("forward", "\"tcr-multi\"") == 3,
          "3 forward rules");

    /* Free one */
    port_forwarder_free(pf1);
    CHECK(count_rules("prerouting", "\"tcr-multi\"") == 2,
          "after freeing pf1, 2 DNAT rules remain");
    CHECK(count_rules("forward", "\"tcr-multi\"") == 2,
          "after freeing pf1, 2 forward rules remain");

    port_forwarder_free(pf2);
    CHECK(count_rules("prerouting", "\"tcr-multi\"") == 0,
          "all gone");
    CHECK(count_rules("forward", "\"tcr-multi\"") == 0,
          "all gone");

    printf("OK\n");
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                       */
/* -------------------------------------------------------------------------- */

int main(void)
{
    if (getuid() != 0) {
        fprintf(stderr, "error: must be run as root (nftables requires privileges)\n");
        return 1;
    }

    printf("test_port_forwarder\n");
    printf("─────────────────────────────────────────\n");

    nft_test_setup();

    test_new_tcp();
    test_new_udp();
    test_new_both_protocols();
    test_specific_listen_ip();
    test_reject_localhost();
    test_reject_invalid_args();
    test_cleanup_group();
    test_cleanup_group_isolation();
    test_free_null();
    test_multiple_forwarders_same_group();

    nft_test_teardown();

    printf("─────────────────────────────────────────\n");
    printf("All tests passed.\n");

    return 0;
}
