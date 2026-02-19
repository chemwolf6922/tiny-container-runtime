#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "run_config.h"
#include "common/utils.h"
#include "network/port_forwarder.h"

#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers                                                                   */
/* ═══════════════════════════════════════════════════════════════════════════ */

/** Set *err_msg via asprintf.  Always returns -1 for convenience. */
__attribute__((format(printf, 2, 3)))
static int fail(char **err_msg, const char *fmt, ...)
{
    if (err_msg) {
        va_list ap;
        va_start(ap, fmt);
        if (vasprintf(err_msg, fmt, ap) < 0)
            *err_msg = NULL;
        va_end(ap);
    }
    return -1;
}

/** Get a string field.  Returns NULL if missing.  Sets err on type mismatch. */
static const char *json_get_string(const cJSON *root, const char *key,
                                   char **err_msg)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item || cJSON_IsNull(item))
        return NULL;
    if (!cJSON_IsString(item)) {
        fail(err_msg, "'%s' must be a string", key);
        return NULL;
    }
    return item->valuestring;
}

/** Get a bool field.  Returns @a def if missing.  Sets err on type mismatch.
 *  Returns -1 on error so the caller can distinguish missing (def) from error. */
static int json_get_bool(const cJSON *root, const char *key, bool def,
                         bool *out, char **err_msg)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item || cJSON_IsNull(item)) {
        *out = def;
        return 0;
    }
    if (!cJSON_IsBool(item))
        return fail(err_msg, "'%s' must be a boolean", key);
    *out = cJSON_IsTrue(item);
    return 0;
}

/** Get an integer field.  Returns @a def if missing. */
static int json_get_int(const cJSON *root, const char *key, int def,
                        int *out, char **err_msg)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!item || cJSON_IsNull(item)) {
        *out = def;
        return 0;
    }
    if (!cJSON_IsNumber(item))
        return fail(err_msg, "'%s' must be an integer", key);
    *out = item->valueint;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Section parsers                                                           */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int parse_env(const cJSON *root, container_args args, char **err_msg)
{
    const cJSON *env = cJSON_GetObjectItemCaseSensitive(root, "env");
    if (!env || cJSON_IsNull(env))
        return 0;
    if (!cJSON_IsObject(env))
        return fail(err_msg, "'env' must be an object");

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, env) {
        if (!cJSON_IsString(item))
            return fail(err_msg, "env value for '%s' must be a string", item->string);
        if (container_args_add_env(args, item->string, item->valuestring) != 0)
            return fail(err_msg, "failed to add env '%s'", item->string);
    }
    return 0;
}

static int parse_command(const cJSON *root, container_args args, char **err_msg)
{
    const cJSON *cmd = cJSON_GetObjectItemCaseSensitive(root, "command");
    if (!cmd || cJSON_IsNull(cmd))
        return 0;
    if (!cJSON_IsArray(cmd))
        return fail(err_msg, "'command' must be an array of strings");

    int n = cJSON_GetArraySize(cmd);
    if (n == 0)
        return fail(err_msg, "'command' must not be empty");

    const char **argv = calloc((size_t)n, sizeof(char *));
    if (!argv)
        return fail(err_msg, "OOM");

    for (int i = 0; i < n; i++) {
        const cJSON *item = cJSON_GetArrayItem(cmd, i);
        if (!cJSON_IsString(item)) {
            free(argv);
            return fail(err_msg, "command[%d] must be a string", i);
        }
        argv[i] = item->valuestring;
    }

    int rc = container_args_set_command(args, (size_t)n, argv);
    free(argv);
    if (rc != 0)
        return fail(err_msg, "failed to set command");
    return 0;
}

static int parse_mounts(const cJSON *root, container_args args,
                        const char *config_dir, char **err_msg)
{
    const cJSON *mounts = cJSON_GetObjectItemCaseSensitive(root, "mounts");
    if (!mounts || cJSON_IsNull(mounts))
        return 0;
    if (!cJSON_IsArray(mounts))
        return fail(err_msg, "'mounts' must be an array");

    int idx = 0;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, mounts) {
        if (!cJSON_IsObject(item))
            return fail(err_msg, "mounts[%d] must be an object", idx);

        const char *src = json_get_string(item, "source", err_msg);
        if (!src) {
            if (*err_msg) return -1;
            return fail(err_msg, "mounts[%d].source is required", idx);
        }
        const char *dst = json_get_string(item, "destination", err_msg);
        if (!dst) {
            if (*err_msg) return -1;
            return fail(err_msg, "mounts[%d].destination is required", idx);
        }

        bool ro = false;
        if (json_get_bool(item, "readonly", false, &ro, err_msg) != 0)
            return -1;

        /* Resolve relative source paths against config file directory */
        char *abs_src = NULL;
        if (src[0] != '/') {
            abs_src = path_join(config_dir, src);
            if (!abs_src)
                return fail(err_msg, "OOM resolving mounts[%d].source", idx);
            src = abs_src;
        }

        int rc = container_args_add_bind_mount(args, src, dst, ro);
        free(abs_src);
        if (rc != 0)
            return fail(err_msg, "failed to add mount[%d]", idx);
        idx++;
    }
    return 0;
}

static int parse_tmpfs(const cJSON *root, container_args args, char **err_msg)
{
    const cJSON *tmpfs = cJSON_GetObjectItemCaseSensitive(root, "tmpfs");
    if (!tmpfs || cJSON_IsNull(tmpfs))
        return 0;
    if (!cJSON_IsArray(tmpfs))
        return fail(err_msg, "'tmpfs' must be an array");

    int idx = 0;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, tmpfs) {
        if (!cJSON_IsObject(item))
            return fail(err_msg, "tmpfs[%d] must be an object", idx);

        const char *dst = json_get_string(item, "destination", err_msg);
        if (!dst) {
            if (*err_msg) return -1;
            return fail(err_msg, "tmpfs[%d].destination is required", idx);
        }

        int size = 0;
        if (json_get_int(item, "size", 0, &size, err_msg) != 0)
            return -1;
        size_t size_bytes = (size > 0) ? (size_t)size : 64 * 1024 * 1024; /* 64 MiB default */

        if (container_args_add_tmpfs_mount(args, dst, size_bytes) != 0)
            return fail(err_msg, "failed to add tmpfs[%d]", idx);
        idx++;
    }
    return 0;
}

static int parse_ports(const cJSON *root, container_args args, char **err_msg)
{
    const cJSON *ports = cJSON_GetObjectItemCaseSensitive(root, "ports");
    if (!ports || cJSON_IsNull(ports))
        return 0;
    if (!cJSON_IsArray(ports))
        return fail(err_msg, "'ports' must be an array");

    int idx = 0;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, ports) {
        if (!cJSON_IsObject(item))
            return fail(err_msg, "ports[%d] must be an object", idx);

        /* hostPort (required) */
        int hp = 0;
        if (json_get_int(item, "hostPort", 0, &hp, err_msg) != 0) return -1;
        if (hp <= 0 || hp > 65535)
            return fail(err_msg, "ports[%d].hostPort must be 1-65535", idx);

        /* containerPort (required) */
        int cp = 0;
        if (json_get_int(item, "containerPort", 0, &cp, err_msg) != 0) return -1;
        if (cp <= 0 || cp > 65535)
            return fail(err_msg, "ports[%d].containerPort must be 1-65535", idx);

        /* hostIp (optional, default 0.0.0.0) */
        struct in_addr host_ip;
        host_ip.s_addr = INADDR_ANY;
        const char *ip_str = json_get_string(item, "hostIp", err_msg);
        if (!ip_str && *err_msg) return -1;
        if (ip_str) {
            if (inet_pton(AF_INET, ip_str, &host_ip) != 1)
                return fail(err_msg, "ports[%d].hostIp '%s' is not a valid IPv4 address",
                            idx, ip_str);
        }

        /* protocol (optional, default "tcp") */
        int protocol = PORT_FORWARDER_PROTOCOL_TCP;
        const char *proto_str = json_get_string(item, "protocol", err_msg);
        if (!proto_str && *err_msg) return -1;
        if (proto_str) {
            if (strcmp(proto_str, "tcp") == 0)
                protocol = PORT_FORWARDER_PROTOCOL_TCP;
            else if (strcmp(proto_str, "udp") == 0)
                protocol = PORT_FORWARDER_PROTOCOL_UDP;
            else
                return fail(err_msg, "ports[%d].protocol must be 'tcp' or 'udp'", idx);
        }

        if (container_args_add_port_forwarding(
                args, host_ip, (uint16_t)hp, (uint16_t)cp, protocol) != 0)
            return fail(err_msg, "failed to add port[%d]", idx);
        idx++;
    }
    return 0;
}

static container_restart_policy parse_restart_policy_str(const char *s)
{
    if (strcmp(s, "unless-stopped") == 0)
        return CONTAINER_RESTART_POLICY_UNLESS_STOPPED;
    if (strcmp(s, "always") == 0)
        return CONTAINER_RESTART_POLICY_ALWAYS;
    return CONTAINER_RESTART_POLICY_NEVER;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Public API                                                                */
/* ═══════════════════════════════════════════════════════════════════════════ */

int run_config_parse(const char *config_path, container_args args, char **err_msg)
{
    if (err_msg) *err_msg = NULL;

    /* ── Load and parse JSON ─────────────────────────────────────────────── */
    cJSON *root = load_json_file(config_path);
    if (!root)
        return fail(err_msg, "failed to load config file: %s", config_path);

    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return fail(err_msg, "config must be a JSON object");
    }

    /* ── Derive config directory for relative path resolution ────────────── */
    char *path_copy = strdup(config_path);
    if (!path_copy) {
        cJSON_Delete(root);
        return fail(err_msg, "OOM");
    }
    const char *config_dir = dirname(path_copy);

    int rc = -1;

    /* ── image (required) ────────────────────────────────────────────────── */
    const char *image = json_get_string(root, "image", err_msg);
    if (!image) {
        if (!*err_msg) fail(err_msg, "'image' is required");
        goto out;
    }
    if (container_args_set_image(args, image) != 0) {
        fail(err_msg, "failed to set image");
        goto out;
    }

    /* ── name (optional) ─────────────────────────────────────────────────── */
    const char *name = json_get_string(root, "name", err_msg);
    if (!name && *err_msg) goto out;
    if (name && container_args_set_name(args, name) != 0) {
        fail(err_msg, "failed to set name");
        goto out;
    }

    /* ── boolean flags ───────────────────────────────────────────────────── */
    bool bval = false;

    if (json_get_bool(root, "detached", false, &bval, err_msg) != 0) goto out;
    container_args_set_detached(args, bval);

    if (json_get_bool(root, "terminal", false, &bval, err_msg) != 0) goto out;
    container_args_set_terminal_mode(args, bval);

    if (json_get_bool(root, "readonly", false, &bval, err_msg) != 0) goto out;
    container_args_set_readonly(args, bval);

    if (json_get_bool(root, "autoRemove", false, &bval, err_msg) != 0) goto out;
    container_args_set_auto_remove(args, bval);

    /* ── command ─────────────────────────────────────────────────────────── */
    if (parse_command(root, args, err_msg) != 0) goto out;

    /* ── env ─────────────────────────────────────────────────────────────── */
    if (parse_env(root, args, err_msg) != 0) goto out;

    /* ── mounts ──────────────────────────────────────────────────────────── */
    if (parse_mounts(root, args, config_dir, err_msg) != 0) goto out;

    /* ── tmpfs ───────────────────────────────────────────────────────────── */
    if (parse_tmpfs(root, args, err_msg) != 0) goto out;

    /* ── ports ───────────────────────────────────────────────────────────── */
    if (parse_ports(root, args, err_msg) != 0) goto out;

    /* ── network / noNetwork ─────────────────────────────────────────────── */
    bool no_network = false;
    if (json_get_bool(root, "noNetwork", false, &no_network, err_msg) != 0) goto out;

    const char *network = json_get_string(root, "network", err_msg);
    if (!network && *err_msg) goto out;

    if (no_network && network) {
        fail(err_msg, "'network' and 'noNetwork' are mutually exclusive");
        goto out;
    }

    if (!no_network) {
        /* NULL = default network (tcr_default) */
        container_args_set_nat_network(args, network);
    }

    /* ── restartPolicy ───────────────────────────────────────────────────── */
    const char *restart = json_get_string(root, "restartPolicy", err_msg);
    if (!restart && *err_msg) goto out;
    if (restart) {
        if (strcmp(restart, "no") != 0 &&
            strcmp(restart, "unless-stopped") != 0 &&
            strcmp(restart, "always") != 0) {
            fail(err_msg, "restartPolicy must be 'no', 'unless-stopped', or 'always'");
            goto out;
        }
        container_args_set_restart_policy(args, parse_restart_policy_str(restart));
    }

    /* ── stopTimeout ─────────────────────────────────────────────────────── */
    int stop_timeout = 10;
    if (json_get_int(root, "stopTimeout", 10, &stop_timeout, err_msg) != 0) goto out;
    container_args_set_stop_timeout(args, stop_timeout * 1000);

    rc = 0;

out:
    free(path_copy);
    cJSON_Delete(root);
    return rc;
}
