#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nat_network_manager.h"

#include "common/bitmap.h"

#include <tev/map.h>

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* -------------------------------------------------------------------------- */
/*  Constants                                                                  */
/* -------------------------------------------------------------------------- */

/*
 * Subnet allocation scheme:
 *   Each network gets a /24 from the 10.88.x.0 range where x is the
 *   network's slot index (0–255). The first network ("tcr_default")
 *   gets 10.88.0.0/24, the next gets 10.88.1.0/24, etc.
 *
 *   This is a simple allocation strategy that supports up to 256 networks.
 */
#define SUBNET_PREFIX  "10.88."
#define SUBNET_SUFFIX  ".0/24"
#define MAX_NETWORKS   256

/* -------------------------------------------------------------------------- */
/*  Data structures                                                            */
/* -------------------------------------------------------------------------- */

struct nat_network_manager_s
{
    tev_handle_t tev;
    char *root_path;
    map_handle_t networks;      /* name (char*) -> nat_network */
    bitmap_t slot_bitmap;       /* tracks used subnet slots    */
};

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static int mkdir_p(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/**
 * Find the next available subnet slot and build the subnet string.
 * Returns the slot index, or -1 if none available.
 * Writes the subnet string (e.g. "10.88.3.0/24") to out_subnet.
 */
static int allocate_subnet_slot(struct nat_network_manager_s *mgr,
                                char *out_subnet, size_t out_len)
{
    int slot = bitmap_find_first_free(mgr->slot_bitmap);
    if (slot < 0) return -1;

    bitmap_set(mgr->slot_bitmap, slot);
    snprintf(out_subnet, out_len, "%s%d%s", SUBNET_PREFIX, slot, SUBNET_SUFFIX);
    return slot;
}

static void release_subnet_slot(struct nat_network_manager_s *mgr, int slot)
{
    if (slot >= 0 && slot < MAX_NETWORKS)
        bitmap_clear(mgr->slot_bitmap, slot);
}

/**
 * Derive the subnet slot index from a nat_network's gateway IP.
 * Gateway is always x.x.SLOT.1, so extract the third octet.
 * Returns -1 if unable to determine.
 */
static int slot_from_network(nat_network net)
{
    struct in_addr gw;
    if (nat_network_get_gateway(net, &gw) != 0) return -1;

    /* gateway is in network byte order, convert to host */
    uint32_t ip = ntohl(gw.s_addr);
    int slot = (int)((ip >> 8) & 0xFF);
    return (slot >= 0 && slot < MAX_NETWORKS) ? slot : -1;
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                 */
/* -------------------------------------------------------------------------- */

nat_network_manager nat_network_manager_new(tev_handle_t tev, const char *root_path)
{
    if (!tev || !root_path) return NULL;

    struct nat_network_manager_s *mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    mgr->tev = tev;

    /* resolve to absolute path */
    char resolved[PATH_MAX];
    if (realpath(root_path, resolved))
        mgr->root_path = strdup(resolved);
    else
        mgr->root_path = strdup(root_path);
    if (!mgr->root_path) goto fail;

    if (mkdir_p(mgr->root_path) != 0) goto fail;

    mgr->networks = map_create();
    if (!mgr->networks) goto fail;

    mgr->slot_bitmap = bitmap_create(MAX_NETWORKS);
    if (!mgr->slot_bitmap) goto fail;

    return mgr;

fail:
    bitmap_free(mgr->slot_bitmap);
    free(mgr->root_path);
    free(mgr);
    return NULL;
}

static void free_network_cb(void *value, void *ctx)
{
    (void)ctx;
    nat_network net = value;
    nat_network_free(net);
}

void nat_network_manager_free(nat_network_manager manager)
{
    if (!manager) return;
    struct nat_network_manager_s *mgr = manager;

    map_delete(mgr->networks, free_network_cb, NULL);
    bitmap_free(mgr->slot_bitmap);
    free(mgr->root_path);
    free(mgr);
}

nat_network nat_network_manager_find_network(
    nat_network_manager manager,
    const char *name)
{
    if (!manager) return NULL;
    struct nat_network_manager_s *mgr = manager;

    const char *key = name ? name : NAT_NETWORK_MANAGER_DEFAULT_NAME;
    size_t key_len = strlen(key);

    return map_get(mgr->networks, (void *)key, key_len);
}

nat_network nat_network_manager_get_network(
    nat_network_manager manager,
    const char *name)
{
    if (!manager) return NULL;
    struct nat_network_manager_s *mgr = manager;

    const char *key = name ? name : NAT_NETWORK_MANAGER_DEFAULT_NAME;
    size_t key_len = strlen(key);

    /* check if already exists */
    nat_network net = map_get(mgr->networks, (void *)key, key_len);
    if (net) return net;

    /* allocate a subnet slot */
    char subnet[64];
    int slot = allocate_subnet_slot(mgr, subnet, sizeof(subnet));
    if (slot < 0)
    {
        fprintf(stderr, "nat_network_manager: no available subnet slots\n");
        return NULL;
    }

    /* create the network */
    net = nat_network_new(mgr->tev, key, subnet);
    if (!net)
    {
        fprintf(stderr, "nat_network_manager: failed to create network '%s' with subnet %s\n",
                key, subnet);
        release_subnet_slot(mgr, slot);
        return NULL;
    }

    /* store in map — map_add returns the old value (NULL for new entry) */
    void *prev = map_add(mgr->networks, (void *)key, key_len, net);
    if (prev && prev != net)
    {
        /* should not happen since we checked map_get above */
        fprintf(stderr, "nat_network_manager: unexpected duplicate for '%s'\n", key);
        nat_network_free(net);
        release_subnet_slot(mgr, slot);
        return prev;
    }

    fprintf(stderr, "nat_network_manager: created network '%s' (%s)\n", key, subnet);
    return net;
}

void nat_network_remove_network(nat_network_manager manager, const char *name)
{
    if (!manager) return;
    struct nat_network_manager_s *mgr = manager;

    const char *key = name ? name : NAT_NETWORK_MANAGER_DEFAULT_NAME;
    size_t key_len = strlen(key);

    nat_network net = map_remove(mgr->networks, (void *)key, key_len);
    if (!net) return;

    int slot = slot_from_network(net);
    nat_network_free(net);
    release_subnet_slot(mgr, slot);

    fprintf(stderr, "nat_network_manager: removed network '%s'\n", key);
}

int nat_network_manager_foreach_safe(nat_network_manager manager,
                                     nat_network_manager_foreach_fn fn,
                                     void *user_data)
{
    if (!manager || !fn) return -1;
    struct nat_network_manager_s *mgr = manager;

    size_t len = 0;
    void **values = map_values(mgr->networks, &len);
    if (!values) return (len == 0) ? 0 : -1;

    for (size_t i = 0; i < len; i++)
    {
        fn((nat_network)values[i], user_data);
    }

    free(values);
    return 0;
}
