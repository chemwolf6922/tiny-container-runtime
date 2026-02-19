
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "rpc/rpc_server.h"
#include "app/common.h"
#include "app/daemon-constants.h"

#include "image/image_manager.h"
#include "container/container_manager.h"
#include "container/run_config.h"
#include "network/nat_network_manager.h"
#include "network/nat_network.h"
#include "common/utils.h"

#include <cjson/cJSON.h>
#include <tev/tev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <unistd.h>

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Daemon state                                                              */
/* ═══════════════════════════════════════════════════════════════════════════ */

typedef struct
{
    tev_handle_t tev;
    rpc_server server;
    image_manager img_manager;
    nat_network_manager nat_manager;
    container_manager ctr_manager;
    char *root_path;
} daemon_ctx;

static daemon_ctx g_ctx;

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: cJSON args → C argv                                              */
/* ═══════════════════════════════════════════════════════════════════════════ */

/** Extract the params.args JSON array as (argc, argv). argv[i] are borrowed. */
static int params_get_args(const cJSON *params, int *out_argc, const char ***out_argv)
{
    const cJSON *args = cJSON_GetObjectItemCaseSensitive(params, "args");
    if (!cJSON_IsArray(args)) {
        *out_argc = 0;
        *out_argv = NULL;
        return 0;
    }
    int n = cJSON_GetArraySize(args);
    const char **argv = calloc((size_t)n, sizeof(char *));
    if (!argv) return -1;
    for (int i = 0; i < n; i++) {
        const cJSON *item = cJSON_GetArrayItem(args, i);
        argv[i] = cJSON_IsString(item) ? item->valuestring : "";
    }
    *out_argc = n;
    *out_argv = argv;
    return 0;
}

/** Get params.pwd (borrowed string). */
static const char *params_get_pwd(const cJSON *params)
{
    const cJSON *pwd = cJSON_GetObjectItemCaseSensitive(params, "pwd");
    return cJSON_IsString(pwd) ? pwd->valuestring : "/";
}

/** Get params.pid. */
static pid_t params_get_pid(const cJSON *params)
{
    const cJSON *pid = cJSON_GetObjectItemCaseSensitive(params, "pid");
    return cJSON_IsNumber(pid) ? (pid_t)pid->valueint : -1;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: reply builders                                                   */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int reply_output(rpc_server server, rpc_request_handle h,
                        int exit_code, const char *out, const char *err)
{
    cJSON *result = cJSON_CreateObject();
    if (!result) return -1;
    cJSON_AddNumberToObject(result, "exitCode", exit_code);
    cJSON_AddStringToObject(result, "stdOut", out ? out : "");
    cJSON_AddStringToObject(result, "stdErr", err ? err : "");
    int rc = rpc_server_reply_result(server, h, result);
    cJSON_Delete(result);
    return rc;
}

static int reply_exec(rpc_server server, rpc_request_handle h,
                      char **argv, size_t argc)
{
    cJSON *result = cJSON_CreateObject();
    if (!result) return -1;
    cJSON *arr = cJSON_AddArrayToObject(result, "execArgs");
    for (size_t i = 0; i < argc; i++)
        cJSON_AddItemToArray(arr, cJSON_CreateString(argv[i]));
    int rc = rpc_server_reply_result(server, h, result);
    cJSON_Delete(result);
    return rc;
}

static int reply_error(rpc_server server, rpc_request_handle h,
                       int code, const char *msg)
{
    return rpc_server_reply_error(server, h, code, msg);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: resolve path relative to client pwd                              */
/* ═══════════════════════════════════════════════════════════════════════════ */

/** Resolve a potentially relative path against the client's pwd.
 *  Returns a newly allocated absolute path. Caller must free(). */
static char *resolve_path(const char *path, const char *pwd)
{
    if (!path) return NULL;
    if (path[0] == '/') return strdup(path);
    return path_join(pwd, path);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Helpers: parse run options                                                */
/* ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Parse a -v bind mount spec: src:dst[:ro]
 * Returns 0 on success, -1 on parse error.
 */
static int parse_bind_mount(const char *spec, const char *pwd,
                            container_args args)
{
    /* Make a mutable copy. */
    char *buf = strdup(spec);
    if (!buf) return -1;

    char *src = buf;
    char *dst = strchr(src, ':');
    if (!dst) { free(buf); return -1; }
    *dst++ = '\0';

    bool ro = false;
    char *opts = strchr(dst, ':');
    if (opts) {
        *opts++ = '\0';
        if (strcmp(opts, "ro") == 0)
            ro = true;
    }

    char *abs_src = resolve_path(src, pwd);
    if (!abs_src) { free(buf); return -1; }

    int rc = container_args_add_bind_mount(args, abs_src, dst, ro);
    free(abs_src);
    free(buf);
    return rc;
}

/**
 * Parse a --tmpfs spec: dst[:size]
 * Returns 0 on success, -1 on parse error.
 */
static int parse_tmpfs_mount(const char *spec, container_args args)
{
    char *buf = strdup(spec);
    if (!buf) return -1;

    char *dst = buf;
    size_t size = 64 * 1024 * 1024; /* 64 MiB default */

    char *colon = strchr(dst, ':');
    if (colon) {
        *colon++ = '\0';
        char *end;
        unsigned long val = strtoul(colon, &end, 10);
        if (end != colon) size = val;
    }

    int rc = container_args_add_tmpfs_mount(args, dst, size);
    free(buf);
    return rc;
}

/**
 * Parse -p port spec: [hostIP:]hostPort:containerPort[/protocol]
 * Returns 0 on success, -1 on parse error.
 */
static int parse_port_forward(const char *spec, container_args args)
{
    char *buf = strdup(spec);
    if (!buf) return -1;

    /* Separate protocol suffix: /tcp, /udp, /tcp+udp */
    int protocol = PORT_FORWARDER_PROTOCOL_TCP; /* default */
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash++ = '\0';
        if (strcmp(slash, "tcp") == 0)
            protocol = PORT_FORWARDER_PROTOCOL_TCP;
        else if (strcmp(slash, "udp") == 0)
            protocol = PORT_FORWARDER_PROTOCOL_UDP;
        else if (strcmp(slash, "tcp+udp") == 0 || strcmp(slash, "udp+tcp") == 0)
            protocol = PORT_FORWARDER_PROTOCOL_TCP | PORT_FORWARDER_PROTOCOL_UDP;
        else { free(buf); return -1; }
    }

    /*
     * Possible formats after protocol stripping:
     *   hostPort:containerPort
     *   hostIP:hostPort:containerPort
     *
     * Count colons to disambiguate.
     */
    int colons = 0;
    for (char *p = buf; *p; p++)
        if (*p == ':') colons++;

    struct in_addr host_ip;
    host_ip.s_addr = INADDR_ANY;
    uint16_t host_port, container_port;

    if (colons == 1) {
        /* hostPort:containerPort */
        char *sep = strchr(buf, ':');
        *sep++ = '\0';
        host_port = (uint16_t)atoi(buf);
        container_port = (uint16_t)atoi(sep);
    } else if (colons == 2) {
        /* hostIP:hostPort:containerPort */
        char *sep1 = strchr(buf, ':');
        *sep1++ = '\0';
        char *sep2 = strchr(sep1, ':');
        *sep2++ = '\0';
        if (inet_pton(AF_INET, buf, &host_ip) != 1) { free(buf); return -1; }
        host_port = (uint16_t)atoi(sep1);
        container_port = (uint16_t)atoi(sep2);
    } else {
        free(buf);
        return -1;
    }

    int rc = container_args_add_port_forwarding(
        args, host_ip, host_port, container_port, protocol);
    free(buf);
    return rc;
}

/**
 * Parse a -e env spec: KEY=VALUE
 * Returns 0 on success, -1 on parse error.
 */
static int parse_env(const char *spec, container_args args)
{
    char *buf = strdup(spec);
    if (!buf) return -1;

    char *eq = strchr(buf, '=');
    if (!eq) { free(buf); return -1; }
    *eq++ = '\0';

    int rc = container_args_add_env(args, buf, eq);
    free(buf);
    return rc;
}

static container_restart_policy parse_restart_policy(const char *s)
{
    if (strcmp(s, "unless-stopped") == 0)
        return CONTAINER_RESTART_POLICY_UNLESS_STOPPED;
    if (strcmp(s, "always") == 0)
        return CONTAINER_RESTART_POLICY_ALWAYS;
    /* "no" or anything else */
    return CONTAINER_RESTART_POLICY_NEVER;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: run                                                              */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_run(rpc_request_handle h, const cJSON *params)
{
    int argc;
    const char **argv;
    if (params_get_args(params, &argc, &argv) != 0)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to parse args");

    const char *pwd = params_get_pwd(params);
    pid_t client_pid = params_get_pid(params);

    container_args args = container_args_new();
    if (!args) { free(argv); return reply_error(g_ctx.server, h, ERR_INTERNAL, "OOM"); }

    /* ── --config mode: parse JSON config file ────────────────────────── */
    if (argc >= 2 && strcmp(argv[0], "--config") == 0) {
        char *config_path = resolve_path(argv[1], pwd);
        if (!config_path) {
            container_args_free(args);
            free(argv);
            return reply_error(g_ctx.server, h, ERR_INTERNAL, "OOM");
        }

        if (argc > 2) {
            free(config_path);
            container_args_free(args);
            free(argv);
            return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                               "--config cannot be combined with other arguments");
        }

        char *err_msg = NULL;
        if (run_config_parse(config_path, args, &err_msg) != 0) {
            free(config_path);
            container_args_free(args);
            free(argv);
            int rc = reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                                 err_msg ? err_msg : "failed to parse config");
            free(err_msg);
            return rc;
        }
        free(config_path);

        /* image_ref comes from the config */
        const char *image_ref = container_args_get_image(args);
        image img_check = image_manager_find_by_id_or_name(g_ctx.img_manager, image_ref);
        if (!img_check) {
            container_args_free(args);
            free(argv);
            return reply_error(g_ctx.server, h, ERR_IMAGE_NOT_FOUND, "image not found");
        }

        bool detached = container_args_get_detached(args);

        container c = container_manager_create_container(g_ctx.ctr_manager, args);
        container_args_free(args);
        if (!c) {
            free(argv);
            return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to create container");
        }

        int rc;
        if (detached) {
            if (container_start(c) != 0) {
                container_remove(c);
                free(argv);
                return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to start container");
            }
            char out[64];
            snprintf(out, sizeof(out), "%s\n", container_get_id(c));
            rc = reply_output(g_ctx.server, h, 0, out, NULL);
        } else {
            char **crun_argv;
            size_t crun_argc;
            if (container_get_crun_args(c, &crun_argv, &crun_argc) != 0) {
                container_remove(c);
                free(argv);
                return reply_error(g_ctx.server, h, ERR_INTERNAL,
                                   "failed to build crun args");
            }
            if (client_pid > 0)
                container_monitor_process(c, client_pid);
            rc = reply_exec(g_ctx.server, h, crun_argv, crun_argc);
            container_free_crun_args(crun_argv, crun_argc);
        }
        free(argv);
        return rc;
    }

    /* ── CLI argument mode ────────────────────────────────────────────── */

    /* Flags */
    bool detached = false;
    bool no_network = false;
    bool network_set = false;
    const char *image_ref = NULL;

    int i = 0;
    while (i < argc) {
        const char *a = argv[i];

        if (strcmp(a, "-d") == 0) {
            detached = true;
            i++;
        } else if (strcmp(a, "--name") == 0 && i + 1 < argc) {
            container_args_set_name(args, argv[++i]);
            i++;
        } else if (strcmp(a, "--rm") == 0) {
            container_args_set_auto_remove(args, true);
            i++;
        } else if (strcmp(a, "--read-only") == 0) {
            container_args_set_readonly(args, true);
            i++;
        } else if (strcmp(a, "-t") == 0) {
            container_args_set_terminal_mode(args, true);
            i++;
        } else if (strcmp(a, "-e") == 0 && i + 1 < argc) {
            if (parse_env(argv[++i], args) != 0) {
                container_args_free(args);
                free(argv);
                return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                                   "bad -e format, expected KEY=VALUE");
            }
            i++;
        } else if (strcmp(a, "-v") == 0 && i + 1 < argc) {
            if (parse_bind_mount(argv[++i], pwd, args) != 0) {
                container_args_free(args);
                free(argv);
                return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                                   "bad -v format, expected src:dst[:ro]");
            }
            i++;
        } else if (strcmp(a, "--tmpfs") == 0 && i + 1 < argc) {
            if (parse_tmpfs_mount(argv[++i], args) != 0) {
                container_args_free(args);
                free(argv);
                return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                                   "bad --tmpfs format, expected dst[:size]");
            }
            i++;
        } else if (strcmp(a, "-p") == 0 && i + 1 < argc) {
            if (parse_port_forward(argv[++i], args) != 0) {
                container_args_free(args);
                free(argv);
                return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                                   "bad -p format, expected [hostIP:]hostPort:containerPort[/proto]");
            }
            i++;
        } else if (strcmp(a, "--network") == 0 && i + 1 < argc) {
            container_args_set_nat_network(args, argv[++i]);
            network_set = true;
            i++;
        } else if (strcmp(a, "--no-network") == 0) {
            no_network = true;
            i++;
        } else if (strcmp(a, "--restart") == 0 && i + 1 < argc) {
            container_args_set_restart_policy(args, parse_restart_policy(argv[++i]));
            i++;
        } else if (strcmp(a, "--stop-timeout") == 0 && i + 1 < argc) {
            container_args_set_stop_timeout(args, atoi(argv[++i]) * 1000);
            i++;
        } else if (a[0] == '-') {
            /* Unknown flag */
            char msg[256];
            snprintf(msg, sizeof(msg), "unknown option: %s", a);
            container_args_free(args);
            free(argv);
            return reply_error(g_ctx.server, h, ERR_INVALID_ARG, msg);
        } else {
            /* First non-flag = image ref */
            image_ref = a;
            i++;
            break;
        }
    }

    /* Remaining args after image = command override */
    if (i < argc) {
        container_args_set_command(args, (size_t)(argc - i), &argv[i]);
    }

    /* Validate image */
    if (!image_ref) {
        container_args_free(args);
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG, "no image specified");
    }

    /* Resolve image: try by id first, then by name:tag */
    image img_check = image_manager_find_by_id_or_name(g_ctx.img_manager, image_ref);
    if (!img_check) {
        container_args_free(args);
        free(argv);
        return reply_error(g_ctx.server, h, ERR_IMAGE_NOT_FOUND, "image not found");
    }
    container_args_set_image(args, image_ref);

    container_args_set_detached(args, detached);

    /* Networking: default is NAT (tcr_default), unless --no-network */
    if (!no_network && !network_set) {
        container_args_set_nat_network(args, NULL); /* NULL = default network */
    }

    /* Create the container */
    container c = container_manager_create_container(g_ctx.ctr_manager, args);
    container_args_free(args);

    if (!c) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to create container");
    }

    int rc;
    if (detached) {
        /* Start in background */
        if (container_start(c) != 0) {
            container_remove(c);
            free(argv);
            return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to start container");
        }

        char out[64];
        snprintf(out, sizeof(out), "%s\n", container_get_id(c));
        rc = reply_output(g_ctx.server, h, 0, out, NULL);
    } else {
        /* Interactive: return crun args for client-side exec */
        char **crun_argv;
        size_t crun_argc;
        if (container_get_crun_args(c, &crun_argv, &crun_argc) != 0) {
            container_remove(c);
            free(argv);
            return reply_error(g_ctx.server, h, ERR_INTERNAL,
                               "failed to build crun args");
        }

        /* Monitor the client process */
        if (client_pid > 0) {
            container_monitor_process(c, client_pid);
        }

        rc = reply_exec(g_ctx.server, h, crun_argv, crun_argc);
        container_free_crun_args(crun_argv, crun_argc);
    }

    free(argv);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: exec                                                             */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_exec(rpc_request_handle h, const cJSON *params)
{
    int argc;
    const char **argv;
    if (params_get_args(params, &argc, &argv) != 0)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to parse args");

    /* Flags */
    bool detach = false;
    bool tty = false;
    const char *env_arr[256]; /* stack buffer — bounded by arg count */
    size_t env_count = 0;
    const char *container_ref = NULL;

    int i = 0;
    while (i < argc) {
        const char *a = argv[i];

        if (strcmp(a, "-d") == 0) {
            detach = true;
            i++;
        } else if (strcmp(a, "-t") == 0) {
            tty = true;
            i++;
        } else if (strcmp(a, "-e") == 0 && i + 1 < argc) {
            const char *env_val = argv[++i];
            if (!strchr(env_val, '=')) {
                free(argv);
                return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                                   "bad -e format, expected KEY=VALUE");
            }
            if (env_count < sizeof(env_arr) / sizeof(env_arr[0]))
                env_arr[env_count++] = env_val;
            i++;
        } else if (a[0] == '-') {
            char msg[256];
            snprintf(msg, sizeof(msg), "unknown option: %s", a);
            free(argv);
            return reply_error(g_ctx.server, h, ERR_INVALID_ARG, msg);
        } else {
            /* First non-flag = container ref */
            container_ref = a;
            i++;
            break;
        }
    }

    /* Validate container ref */
    if (!container_ref) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG, "no container specified");
    }

    /* Remaining args = command */
    const char **cmd = &argv[i];
    size_t cmd_count = (size_t)(argc - i);

    if (cmd_count == 0) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG, "no command specified");
    }

    /* Find container */
    container c = container_manager_find_container(g_ctx.ctr_manager, container_ref);
    if (!c) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_CONTAINER_NOT_FOUND, "container not found");
    }

    if (!container_is_running(c)) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG, "container is not running");
    }

    /* Build crun exec args */
    char **exec_argv;
    size_t exec_argc;
    if (container_get_exec_args(c, detach, tty,
                                env_arr, env_count,
                                cmd, cmd_count,
                                &exec_argv, &exec_argc) != 0) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to build exec args");
    }

    int rc = reply_exec(g_ctx.server, h, exec_argv, exec_argc);
    container_free_crun_args(exec_argv, exec_argc);
    free(argv);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: ps                                                               */
/* ═══════════════════════════════════════════════════════════════════════════ */

struct ps_ctx
{
    char *buf;
    size_t len;
    size_t cap;
};

static void ps_append(struct ps_ctx *ctx, const char *line)
{
    size_t line_len = strlen(line);
    if (ctx->len + line_len + 1 > ctx->cap) {
        size_t new_cap = (ctx->cap == 0) ? 1024 : ctx->cap * 2;
        while (new_cap < ctx->len + line_len + 1) new_cap *= 2;
        char *new_buf = realloc(ctx->buf, new_cap);
        if (!new_buf) return;
        ctx->buf = new_buf;
        ctx->cap = new_cap;
    }
    memcpy(ctx->buf + ctx->len, line, line_len);
    ctx->len += line_len;
    ctx->buf[ctx->len] = '\0';
}

static void ps_visitor(container c, void *user_data)
{
    struct ps_ctx *ctx = user_data;

    const char *id = container_get_id(c);
    const char *name = container_get_name(c);
    const char *status = container_is_running(c) ? "running" : "stopped";

    /* Get image info */
    const char *img_name = "";
    const char *img_tag = "";
    image img = container_get_image(c);
    if (img) {
        img_name = image_get_name(img) ? image_get_name(img) : "";
        img_tag = image_get_tag(img) ? image_get_tag(img) : "";
    }

    char *line = NULL;
    if (img_tag[0]) {
        if (asprintf(&line, "%-16s %-20s %s:%-10s %s\n", id, name, img_name, img_tag, status) < 0)
            line = NULL;
    } else {
        if (asprintf(&line, "%-16s %-20s %-24s %s\n", id, name, img_name, status) < 0)
            line = NULL;
    }

    if (line) {
        ps_append(ctx, line);
        free(line);
    }
}

static int handle_ps(rpc_request_handle h, const cJSON *params)
{
    (void)params;

    struct ps_ctx ctx = {0};
    ps_append(&ctx, "ID               NAME                 IMAGE                    STATUS\n");

    container_manager_foreach_container_safe(g_ctx.ctr_manager, ps_visitor, &ctx);

    int rc = reply_output(g_ctx.server, h, 0, ctx.buf ? ctx.buf : "", NULL);
    free(ctx.buf);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: stop                                                             */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_stop(rpc_request_handle h, const cJSON *params)
{
    int argc;
    const char **argv;
    if (params_get_args(params, &argc, &argv) != 0 || argc < 1) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG, "usage: stop <name_or_id>");
    }

    container c = container_manager_find_container(g_ctx.ctr_manager, argv[0]);
    free(argv);
    if (!c)
        return reply_error(g_ctx.server, h, ERR_CONTAINER_NOT_FOUND, "container not found");

    if (container_stop(c, false) != 0)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to stop container");

    char out[64];
    snprintf(out, sizeof(out), "%s\n", container_get_id(c));
    return reply_output(g_ctx.server, h, 0, out, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: kill                                                             */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_kill(rpc_request_handle h, const cJSON *params)
{
    int argc;
    const char **argv;
    if (params_get_args(params, &argc, &argv) != 0 || argc < 1) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG, "usage: kill <name_or_id>");
    }

    container c = container_manager_find_container(g_ctx.ctr_manager, argv[0]);
    free(argv);
    if (!c)
        return reply_error(g_ctx.server, h, ERR_CONTAINER_NOT_FOUND, "container not found");

    if (container_stop(c, true) != 0)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to kill container");

    char out[64];
    snprintf(out, sizeof(out), "%s\n", container_get_id(c));
    return reply_output(g_ctx.server, h, 0, out, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: rm                                                               */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_rm(rpc_request_handle h, const cJSON *params)
{
    int argc;
    const char **argv;
    if (params_get_args(params, &argc, &argv) != 0 || argc < 1) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG, "usage: rm <name_or_id>");
    }

    container c = container_manager_find_container(g_ctx.ctr_manager, argv[0]);
    if (!c) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_CONTAINER_NOT_FOUND, "container not found");
    }

    /* Save id before removal invalidates the pointer */
    char id[32];
    snprintf(id, sizeof(id), "%s", container_get_id(c));

    free(argv);

    if (container_remove(c) != 0)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to remove container");

    char out[64];
    snprintf(out, sizeof(out), "%s\n", id);
    return reply_output(g_ctx.server, h, 0, out, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: image load                                                       */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_image_load(rpc_request_handle h, int argc, const char **argv,
                             const char *pwd)
{
    if (argc < 1)
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                           "usage: image load <path>");

    char *abs_path = resolve_path(argv[0], pwd);
    if (!abs_path)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to resolve path");

    image img = image_manager_load(g_ctx.img_manager, abs_path);
    free(abs_path);

    if (!img)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to load image");

    char *out = NULL;
    if (asprintf(&out, "%s\n", image_get_id(img)) < 0)
        out = NULL;
    int rc = reply_output(g_ctx.server, h, 0, out ? out : "", NULL);
    free(out);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: image ls                                                         */
/* ═══════════════════════════════════════════════════════════════════════════ */

struct image_ls_ctx
{
    char *buf;
    size_t len;
    size_t cap;
};

static void image_ls_append(struct image_ls_ctx *ctx, const char *line)
{
    size_t line_len = strlen(line);
    if (ctx->len + line_len + 1 > ctx->cap) {
        size_t new_cap = (ctx->cap == 0) ? 1024 : ctx->cap * 2;
        while (new_cap < ctx->len + line_len + 1) new_cap *= 2;
        char *new_buf = realloc(ctx->buf, new_cap);
        if (!new_buf) return;
        ctx->buf = new_buf;
        ctx->cap = new_cap;
    }
    memcpy(ctx->buf + ctx->len, line, line_len);
    ctx->len += line_len;
    ctx->buf[ctx->len] = '\0';
}

static void image_ls_visitor(image img, void *user_data)
{
    struct image_ls_ctx *ctx = user_data;

    const char *id = image_get_id(img);
    const char *name = image_get_name(img);
    const char *tag = image_get_tag(img);
    bool mounted = image_get_mounted(img);

    char *line = NULL;
    if (asprintf(&line, "%-16s %-30s %-10s %s\n",
             id ? id : "",
             name ? name : "",
             tag ? tag : "<none>",
             mounted ? "yes" : "no") < 0)
        line = NULL;
    if (line) {
        image_ls_append(ctx, line);
        free(line);
    }
}

static int handle_image_ls(rpc_request_handle h)
{
    struct image_ls_ctx ctx = {0};
    image_ls_append(&ctx, "IMAGE ID         NAME                           TAG        MOUNTED\n");

    image_manager_foreach_safe(g_ctx.img_manager, image_ls_visitor, &ctx);

    int rc = reply_output(g_ctx.server, h, 0, ctx.buf ? ctx.buf : "", NULL);
    free(ctx.buf);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: image rm                                                         */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_image_rm(rpc_request_handle h, int argc, const char **argv)
{
    if (argc < 1)
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                           "usage: image rm <id_or_name:tag>");

    const char *ref = argv[0];
    image img = NULL;

    /* Try by id first, then by name:tag */
    img = image_manager_find_by_id_or_name(g_ctx.img_manager, ref);

    if (!img)
        return reply_error(g_ctx.server, h, ERR_IMAGE_NOT_FOUND, "image not found");

    /* Check ref count */
    int refs = container_manager_get_image_ref_count(g_ctx.ctr_manager, img);
    if (refs > 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "image in use by %d container(s)", refs);
        return reply_error(g_ctx.server, h, ERR_RESOURCE_IN_USE, msg);
    }

    const char *id = image_get_id(img);
    char *out = NULL;
    if (asprintf(&out, "%s\n", id ? id : "") < 0)
        out = NULL;

    image_manager_remove(g_ctx.img_manager, img);

    int rc = reply_output(g_ctx.server, h, 0, out ? out : "", NULL);
    free(out);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: image (dispatcher)                                               */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_image(rpc_request_handle h, const cJSON *params)
{
    int argc;
    const char **argv;
    if (params_get_args(params, &argc, &argv) != 0)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to parse args");

    if (argc < 1) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                           "usage: image <load|ls|rm> [args...]");
    }

    const char *subcmd = argv[0];
    int rc;

    if (strcmp(subcmd, "load") == 0) {
        const char *pwd = params_get_pwd(params);
        rc = handle_image_load(h, argc - 1, argv + 1, pwd);
    } else if (strcmp(subcmd, "ls") == 0) {
        rc = handle_image_ls(h);
    } else if (strcmp(subcmd, "rm") == 0) {
        rc = handle_image_rm(h, argc - 1, argv + 1);
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "unknown image subcommand: %s", subcmd);
        rc = reply_error(g_ctx.server, h, ERR_UNKNOWN_CMD, msg);
    }

    free(argv);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: network ls                                                       */
/* ═══════════════════════════════════════════════════════════════════════════ */

struct network_ls_ctx
{
    char *buf;
    size_t len;
    size_t cap;
};

static void network_ls_append(struct network_ls_ctx *ctx, const char *line)
{
    size_t line_len = strlen(line);
    if (ctx->len + line_len + 1 > ctx->cap) {
        size_t new_cap = (ctx->cap == 0) ? 512 : ctx->cap * 2;
        while (new_cap < ctx->len + line_len + 1) new_cap *= 2;
        char *new_buf = realloc(ctx->buf, new_cap);
        if (!new_buf) return;
        ctx->buf = new_buf;
        ctx->cap = new_cap;
    }
    memcpy(ctx->buf + ctx->len, line, line_len);
    ctx->len += line_len;
    ctx->buf[ctx->len] = '\0';
}

static void network_ls_visitor(nat_network net, void *user_data)
{
    struct network_ls_ctx *ctx = user_data;

    const char *name = nat_network_get_name(net);

    char subnet[32];
    if (nat_network_get_subnet_str(net, subnet, sizeof(subnet)) != 0)
        snprintf(subnet, sizeof(subnet), "?");

    struct in_addr gw;
    char gw_str[INET_ADDRSTRLEN] = "?";
    if (nat_network_get_gateway(net, &gw) == 0)
        inet_ntop(AF_INET, &gw, gw_str, sizeof(gw_str));

    char *line = NULL;
    if (asprintf(&line, "%-20s %-18s %s\n", name, subnet, gw_str) < 0)
        line = NULL;
    if (line) {
        network_ls_append(ctx, line);
        free(line);
    }
}

static int handle_network_ls(rpc_request_handle h)
{
    struct network_ls_ctx ctx = {0};
    network_ls_append(&ctx, "NAME                 SUBNET             GATEWAY\n");

    nat_network_manager_foreach_safe(g_ctx.nat_manager, network_ls_visitor, &ctx);

    int rc = reply_output(g_ctx.server, h, 0, ctx.buf ? ctx.buf : "", NULL);
    free(ctx.buf);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: network rm                                                       */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_network_rm(rpc_request_handle h, int argc, const char **argv)
{
    if (argc < 1)
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                           "usage: network rm <name>");

    const char *name = argv[0];

    /* Check if network exists (lookup only, do not create) */
    nat_network net = nat_network_manager_find_network(g_ctx.nat_manager, name);
    if (!net)
        return reply_error(g_ctx.server, h, ERR_NETWORK_NOT_FOUND, "network not found");

    /* Check ref count */
    int refs = container_manager_get_network_ref_count(g_ctx.ctr_manager, net);
    if (refs > 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "network in use by %d container(s)", refs);
        return reply_error(g_ctx.server, h, ERR_RESOURCE_IN_USE, msg);
    }

    nat_network_remove_network(g_ctx.nat_manager, name);

    char *out = NULL;
    if (asprintf(&out, "%s\n", name) < 0)
        out = NULL;
    int rc = reply_output(g_ctx.server, h, 0, out ? out : "", NULL);
    free(out);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: network (dispatcher)                                             */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_network(rpc_request_handle h, const cJSON *params)
{
    int argc;
    const char **argv;
    if (params_get_args(params, &argc, &argv) != 0)
        return reply_error(g_ctx.server, h, ERR_INTERNAL, "failed to parse args");

    if (argc < 1) {
        free(argv);
        return reply_error(g_ctx.server, h, ERR_INVALID_ARG,
                           "usage: network <ls|rm> [args...]");
    }

    const char *subcmd = argv[0];
    int rc;

    if (strcmp(subcmd, "ls") == 0) {
        rc = handle_network_ls(h);
    } else if (strcmp(subcmd, "rm") == 0) {
        rc = handle_network_rm(h, argc - 1, argv + 1);
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "unknown network subcommand: %s", subcmd);
        rc = reply_error(g_ctx.server, h, ERR_UNKNOWN_CMD, msg);
    }

    free(argv);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Handler: help                                                             */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int handle_help(rpc_request_handle h)
{
    static const char help_text[] =
        "Usage: tcr <command> [args...]\n"
        "\n"
        "Container commands:\n"
        "  run [options] <image> [cmd...]  Create and run a container\n"
        "  exec [options] <container> <cmd...>  Execute a command in a running container\n"
        "  ps                              List containers\n"
        "  stop <container>                Graceful stop (SIGTERM + timeout)\n"
        "  kill <container>                Immediate stop (SIGKILL)\n"
        "  rm <container>                  Remove a container\n"
        "\n"
        "Image commands:\n"
        "  image load <path>               Load a squashfs image\n"
        "  image ls                        List loaded images\n"
        "  image rm <ref>                  Remove an image\n"
        "\n"
        "Network commands:\n"
        "  network ls                      List NAT networks\n"
        "  network rm <name>               Remove a NAT network\n"
        "\n"
        "Run options:\n"
        "  --config <file>      Load all options from a JSON config file\n"
        "  -d                   Detached mode (background)\n"
        "  --name <name>        Container name\n"
        "  --rm                 Auto-remove on exit\n"
        "  --read-only          Read-only rootfs\n"
        "  -t                   Allocate pseudo-TTY\n"
        "  -e KEY=VALUE         Environment variable (repeatable)\n"
        "  -v src:dst[:ro]      Bind mount (repeatable)\n"
        "  --tmpfs dst[:size]   tmpfs mount (repeatable)\n"
        "  -p [ip:]hP:cP[/pr]  Port forward (repeatable)\n"
        "  --network <name>     NAT network (default: tcr_default)\n"
        "  --no-network         Disable networking\n"
        "  --restart <policy>   no | unless-stopped | always\n"
        "  --stop-timeout <s>   Graceful stop timeout (default: 10s)\n"
        "\n"
        "Exec options:\n"
        "  -d                   Detach (run command in background)\n"
        "  -t                   Allocate pseudo-TTY\n"
        "  -e KEY=VALUE         Environment variable (repeatable)\n";

    return reply_output(g_ctx.server, h, 0, help_text, NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  RPC dispatch                                                              */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int on_rpc_request(rpc_request_handle handle, const char *method,
                          const cJSON *params, void *user_data)
{
    (void)user_data;

    if (strcmp(method, "run") == 0)
        return handle_run(handle, params);
    if (strcmp(method, "exec") == 0)
        return handle_exec(handle, params);
    if (strcmp(method, "ps") == 0)
        return handle_ps(handle, params);
    if (strcmp(method, "stop") == 0)
        return handle_stop(handle, params);
    if (strcmp(method, "kill") == 0)
        return handle_kill(handle, params);
    if (strcmp(method, "rm") == 0)
        return handle_rm(handle, params);
    if (strcmp(method, "image") == 0)
        return handle_image(handle, params);
    if (strcmp(method, "network") == 0)
        return handle_network(handle, params);
    if (strcmp(method, "help") == 0)
        return handle_help(handle);

    char msg[128];
    snprintf(msg, sizeof(msg), "unknown command: %s", method);
    return reply_error(g_ctx.server, handle, ERR_UNKNOWN_CMD, msg);
}

static void on_rpc_critical_error(const char *error_message, void *user_data)
{
    (void)user_data;
    fprintf(stderr, "tcrd: critical RPC error: %s\n", error_message);
    /* TODO: could initiate shutdown here */
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Signal handling (signalfd + tev)                                          */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int g_signal_fd = -1;

static void on_signal_readable(void *ctx)
{
    (void)ctx;
    /* Read and discard the signalfd info — we just need to know we got it. */
    struct signalfd_siginfo info;
    ssize_t n = read(g_signal_fd, &info, sizeof(info));
    if (n < (ssize_t)sizeof(info)) return;

    fprintf(stderr, "tcrd: received signal %u, shutting down\n", info.ssi_signo);

    /* Remove the signal handler to break the event loop after cleanup. */
    tev_set_read_handler(g_ctx.tev, g_signal_fd, NULL, NULL);

    /* Tear down the RPC server so no new requests come in.
     * The event loop will exit once all remaining handlers drain. */
    if (g_ctx.server) {
        rpc_server_free(g_ctx.server);
        g_ctx.server = NULL;
    }
}

static int setup_signal_handling(tev_handle_t tev)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    /* Block them for the process so signalfd receives them. */
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return -1;

    g_signal_fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (g_signal_fd < 0) return -1;

    if (tev_set_read_handler(tev, g_signal_fd, on_signal_readable, NULL) != 0) {
        close(g_signal_fd);
        g_signal_fd = -1;
        return -1;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Lock file — ensures a single tcrd instance                                */
/* ═══════════════════════════════════════════════════════════════════════════ */

static int g_lock_fd = -1;

/**
 * Acquire an exclusive lock on the lock file.
 * Writes our PID into it for diagnostic purposes.
 * Returns 0 on success, -1 if another instance is running.
 */
static int acquire_lock(void)
{
    g_lock_fd = open(TCR_LOCK_FILE, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (g_lock_fd < 0) {
        fprintf(stderr, "tcrd: cannot open lock file %s: %s\n",
                TCR_LOCK_FILE, strerror(errno));
        return -1;
    }

    if (flock(g_lock_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            fprintf(stderr, "tcrd: another instance is already running (lock: %s)\n",
                    TCR_LOCK_FILE);
        } else {
            fprintf(stderr, "tcrd: cannot lock %s: %s\n",
                    TCR_LOCK_FILE, strerror(errno));
        }
        close(g_lock_fd);
        g_lock_fd = -1;
        return -1;
    }

    /* Write PID into lock file */
    if (ftruncate(g_lock_fd, 0) == 0) {
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        if (write(g_lock_fd, buf, (size_t)len) != len) { /* best effort */ }
    }

    return 0;
}

static void release_lock(void)
{
    if (g_lock_fd >= 0) {
        unlink(TCR_LOCK_FILE);
        close(g_lock_fd);
        g_lock_fd = -1;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  main                                                                      */
/* ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    const char *root_path = TCR_DEFAULT_ROOT;

    /* Simple argument parsing for daemon itself */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--root") == 0 || strcmp(argv[i], "-r") == 0)
            && i + 1 < argc) {
            root_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: tcrd [--root <path>]\n");
            printf("  --root, -r <path>  Data root (default: %s)\n", TCR_DEFAULT_ROOT);
            return 0;
        } else {
            fprintf(stderr, "tcrd: unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    fprintf(stderr, "tcrd: starting (root=%s)\n", root_path);

    /* ── Lock file (single-instance guard) ─────────────────────────────── */

    if (acquire_lock() != 0)
        return 1;

    /* ── Event loop ────────────────────────────────────────────────────── */

    g_ctx.tev = tev_create_ctx();
    if (!g_ctx.tev) {
        fprintf(stderr, "tcrd: failed to create event loop\n");
        return 1;
    }

    /* ── Signal handling (signalfd via tev) ────────────────────────────── */

    if (setup_signal_handling(g_ctx.tev) != 0) {
        fprintf(stderr, "tcrd: failed to setup signal handling\n");
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    /* Ignore SIGPIPE (can happen on socket writes). */
    signal(SIGPIPE, SIG_IGN);

    /* ── Ensure root directory exists ──────────────────────────────────── */

    if (mkdir(root_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "tcrd: failed to create root dir %s: %s\n",
                root_path, strerror(errno));
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    /* ── Image manager ─────────────────────────────────────────────────── */

    char *img_root = path_join(root_path, "images_root");
    if (!img_root) {
        fprintf(stderr, "tcrd: OOM\n");
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    g_ctx.img_manager = image_manager_new(img_root);
    free(img_root);
    if (!g_ctx.img_manager) {
        fprintf(stderr, "tcrd: failed to create image manager\n");
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    /* ── NAT network manager ───────────────────────────────────────────── */

    char *net_root = path_join(root_path, "networks");
    if (!net_root) {
        fprintf(stderr, "tcrd: OOM\n");
        image_manager_free(g_ctx.img_manager, false);
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    g_ctx.nat_manager = nat_network_manager_new(g_ctx.tev, net_root);
    free(net_root);
    if (!g_ctx.nat_manager) {
        fprintf(stderr, "tcrd: failed to create NAT network manager\n");
        image_manager_free(g_ctx.img_manager, false);
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    /* ── Container manager ─────────────────────────────────────────────── */

    g_ctx.ctr_manager = container_manager_new(
        g_ctx.tev, g_ctx.img_manager, g_ctx.nat_manager, root_path);
    if (!g_ctx.ctr_manager) {
        fprintf(stderr, "tcrd: failed to create container manager\n");
        nat_network_manager_free(g_ctx.nat_manager);
        image_manager_free(g_ctx.img_manager, false);
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    /* ── RPC server ────────────────────────────────────────────────────── */

    g_ctx.server = rpc_server_new(
        g_ctx.tev, TCR_SOCKET_PATH,
        on_rpc_request, on_rpc_critical_error, NULL);
    if (!g_ctx.server) {
        fprintf(stderr, "tcrd: failed to start RPC server on %s\n", TCR_SOCKET_PATH);
        container_manager_free(g_ctx.ctr_manager);
        nat_network_manager_free(g_ctx.nat_manager);
        image_manager_free(g_ctx.img_manager, false);
        tev_free_ctx(g_ctx.tev);
        return 1;
    }

    fprintf(stderr, "tcrd: listening on %s\n", TCR_SOCKET_PATH);

    /* ── Main loop ─────────────────────────────────────────────────────── */

    tev_main_loop(g_ctx.tev);

    /* ── Cleanup ───────────────────────────────────────────────────────── */

    fprintf(stderr, "tcrd: shutting down\n");

    if (g_ctx.server)
        rpc_server_free(g_ctx.server);
    container_manager_free(g_ctx.ctr_manager);
    nat_network_manager_free(g_ctx.nat_manager);
    image_manager_free(g_ctx.img_manager, false);
    if (g_signal_fd >= 0)
        close(g_signal_fd);
    tev_free_ctx(g_ctx.tev);
    release_lock();

    return 0;
}
