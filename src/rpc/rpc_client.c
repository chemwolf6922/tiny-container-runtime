#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "rpc_client.h"

#include <tev/map.h>

#include <cjson/cJSON.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Data structures                                                           */
/* -------------------------------------------------------------------------- */

typedef struct {
    double wire_id;
    void (*on_result)(const cJSON *result, void *user_data);
    void (*on_error)(int error_code, const char *error_message, void *user_data);
    void (*on_cancel)(void *user_data);
    void *user_data;
    tev_timeout_handle_t timeout_handle;
    rpc_client client;      /* back-pointer for timeout context */
} pending_request_t;

struct rpc_client_s {
    tev_handle_t tev;
    int fd;
    bool connected;

    void (*on_connect_result)(bool success, void *user_data);
    void (*on_disconnect)(void *user_data);
    void *user_data;

    map_handle_t pending;   /* wire_id (double, 8 bytes) → pending_request_t* */
    double next_id;
};

/* -------------------------------------------------------------------------- */
/*  Forward declarations                                                      */
/* -------------------------------------------------------------------------- */

static void on_connect_writable(void *ctx);
static void on_readable(void *ctx);
static void on_request_timeout(void *ctx);
static int recv_message(int fd, uint8_t **out_buf, size_t *out_len);
static void cancel_all_pending(rpc_client client);
static void cleanup_connection(rpc_client client);

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Receive a single SEQPACKET message.  The caller must free *out_buf.
 * Returns 0 on success, -1 on error, 1 on peer shutdown.
 */
static int recv_message(int fd, uint8_t **out_buf, size_t *out_len)
{
    char peek;
    ssize_t total = recv(fd, &peek, 1, MSG_PEEK | MSG_TRUNC);
    if (total == 0) return 1;
    if (total < 0) return -1;

    uint8_t *buf = malloc((size_t)total);
    if (!buf) return -1;

    ssize_t n = recv(fd, buf, (size_t)total, 0);
    if (n <= 0) {
        free(buf);
        return n == 0 ? 1 : -1;
    }
    *out_buf = buf;
    *out_len = (size_t)n;
    return 0;
}

/**
 * Cancel all pending requests (calling on_cancel for each) and clear the map.
 */
static void cancel_all_pending(rpc_client client)
{
    size_t nkeys = 0;
    map_key_t *keys = map_keys(client->pending, &nkeys);
    if (!keys)
        return;

    for (size_t i = 0; i < nkeys; i++) {
        pending_request_t *pr = map_remove(client->pending,
                                           keys[i].key, keys[i].len);
        if (!pr) continue;

        if (pr->timeout_handle)
            tev_clear_timeout(client->tev, pr->timeout_handle);

        if (pr->on_cancel)
            pr->on_cancel(pr->user_data);

        free(pr);
    }
    free(keys);
}

/**
 * Tear down the fd: unregister handlers and close.
 */
static void cleanup_connection(rpc_client client)
{
    if (client->fd >= 0) {
        tev_set_read_handler(client->tev, client->fd, NULL, NULL);
        tev_set_write_handler(client->tev, client->fd, NULL, NULL);
        close(client->fd);
        client->fd = -1;
    }
    client->connected = false;
}

/* -------------------------------------------------------------------------- */
/*  Event handlers                                                            */
/* -------------------------------------------------------------------------- */

static void on_connect_writable(void *ctx)
{
    rpc_client client = ctx;

    /* Check connect result via SO_ERROR. */
    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) < 0 ||
        so_err != 0) {
        /* Connection failed. Release fully before callback. */
        void (*cb)(bool, void *) = client->on_connect_result;
        void *ud = client->user_data;
        rpc_client_close(client);
        if (cb)
            cb(false, ud);
        return;
    }

    /* Connection succeeded. */
    tev_set_write_handler(client->tev, client->fd, NULL, NULL);
    client->connected = true;

    if (tev_set_read_handler(client->tev, client->fd, on_readable, client) != 0) {
        void (*cb)(bool, void *) = client->on_connect_result;
        void *ud = client->user_data;
        rpc_client_close(client);
        if (cb)
            cb(false, ud);
        return;
    }

    if (client->on_connect_result)
        client->on_connect_result(true, client->user_data);
}

static void on_readable(void *ctx)
{
    rpc_client client = ctx;

    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = recv_message(client->fd, &buf, &len);
    if (rc != 0) {
        /* Connection lost. Cancel all pending requests, then notify. */
        cancel_all_pending(client);
        cleanup_connection(client);
        if (client->on_disconnect)
            client->on_disconnect(client->user_data);
        return;
    }

    /* Parse response: {"id": <double>, "result": ...} or {"id": ..., "error": {...}} */
    cJSON *root = cJSON_ParseWithLength((const char *)buf, len);
    free(buf);
    if (!root)
        return;     /* malformed message — ignore */

    cJSON *j_id = cJSON_GetObjectItemCaseSensitive(root, "id");
    if (!cJSON_IsNumber(j_id)) {
        cJSON_Delete(root);
        return;
    }

    double wire_id = cJSON_GetNumberValue(j_id);

    /* Look up pending request. */
    pending_request_t *pr = map_remove(client->pending, &wire_id, sizeof(wire_id));
    if (!pr) {
        /* Stale or unknown response — discard. */
        cJSON_Delete(root);
        return;
    }

    if (pr->timeout_handle)
        tev_clear_timeout(client->tev, pr->timeout_handle);

    cJSON *j_result = cJSON_GetObjectItemCaseSensitive(root, "result");
    cJSON *j_error  = cJSON_GetObjectItemCaseSensitive(root, "error");

    if (j_error && cJSON_IsObject(j_error)) {
        cJSON *j_code = cJSON_GetObjectItemCaseSensitive(j_error, "code");
        cJSON *j_msg  = cJSON_GetObjectItemCaseSensitive(j_error, "message");
        int code = cJSON_IsNumber(j_code) ? (int)cJSON_GetNumberValue(j_code) : -1;
        const char *msg = cJSON_IsString(j_msg) ? cJSON_GetStringValue(j_msg) : "unknown error";
        if (pr->on_error)
            pr->on_error(code, msg, pr->user_data);
    } else {
        /* Pass result as const — callback does not take ownership. */
        if (pr->on_result)
            pr->on_result(j_result, pr->user_data);
    }

    free(pr);
    cJSON_Delete(root);
}

static void on_request_timeout(void *ctx)
{
    pending_request_t *pr = ctx;
    rpc_client client = pr->client;

    pr->timeout_handle = NULL;  /* already fired */

    /* Remove from pending map. */
    map_remove(client->pending, &pr->wire_id, sizeof(pr->wire_id));

    if (pr->on_error)
        pr->on_error(-1, "request timed out", pr->user_data);

    free(pr);
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

rpc_client rpc_client_open_async(
    tev_handle_t tev, const char *socket_path,
    void (*on_connect_result)(bool success, void *user_data),
    void (*on_disconnect)(void *user_data),
    void *user_data)
{
    if (!tev || !socket_path)
        return NULL;

    bool is_abstract = (socket_path[0] == '@');

    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return NULL;

    /* Build sockaddr_un. */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    size_t path_len;
    if (is_abstract) {
        path_len = strlen(socket_path + 1);
        if (path_len + 1 > sizeof(addr.sun_path)) {
            close(fd);
            return NULL;
        }
        addr.sun_path[0] = '\0';
        memcpy(addr.sun_path + 1, socket_path + 1, path_len);
        path_len += 1;
    } else {
        path_len = strlen(socket_path);
        if (path_len >= sizeof(addr.sun_path)) {
            close(fd);
            return NULL;
        }
        memcpy(addr.sun_path, socket_path, path_len + 1);
    }

    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len);

    int rc = connect(fd, (struct sockaddr *)&addr, addr_len);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return NULL;
    }

    rpc_client client = calloc(1, sizeof(*client));
    if (!client) {
        close(fd);
        return NULL;
    }

    client->tev = tev;
    client->fd = fd;
    client->connected = false;
    client->on_connect_result = on_connect_result;
    client->on_disconnect = on_disconnect;
    client->user_data = user_data;
    client->pending = map_create();
    client->next_id = 1.0;

    if (!client->pending) {
        close(fd);
        free(client);
        return NULL;
    }

    /* For both EINPROGRESS and immediate connect, use write-handler to
       deliver the result uniformly.  When connect succeeds immediately the
       fd becomes writable on the next event-loop iteration. */
    if (tev_set_write_handler(tev, fd, on_connect_writable, client) != 0) {
        close(fd);
        map_delete(client->pending, NULL, NULL);
        free(client);
        return NULL;
    }

    return client;
}

void rpc_client_close(rpc_client client)
{
    if (!client)
        return;

    cancel_all_pending(client);
    cleanup_connection(client);
    map_delete(client->pending, NULL, NULL);
    free(client);
}

int rpc_client_make_request_async(
    rpc_client client,
    const char *method, const cJSON *params, uint64_t timeout_ms,
    void (*on_result)(const cJSON *result, void *user_data),
    void (*on_error)(int error_code, const char *error_message, void *user_data),
    void (*on_cancel)(void *user_data),
    void *user_data)
{
    if (!client || !client->connected || !method)
        return -1;

    double wire_id = client->next_id;
    client->next_id += 1.0;

    /* Build request JSON: {"id": <double>, "method": "...", "params": ...} */
    cJSON *req = cJSON_CreateObject();
    if (!req)
        return -1;

    cJSON_AddNumberToObject(req, "id", wire_id);
    cJSON_AddStringToObject(req, "method", method);
    if (params)
        cJSON_AddItemToObject(req, "params", cJSON_Duplicate(params, true));
    else
        cJSON_AddNullToObject(req, "params");

    char *msg = cJSON_PrintUnformatted(req);
    cJSON_Delete(req);
    if (!msg)
        return -1;

    /* Send with MSG_DONTWAIT. If it would block, treat as error. */
    size_t len = strlen(msg);
    ssize_t n = send(client->fd, msg, len, MSG_DONTWAIT | MSG_NOSIGNAL);
    free(msg);

    if (n < 0 || (size_t)n != len) {
        /* Send failed / would block — close connection. */
        cancel_all_pending(client);
        cleanup_connection(client);
        if (client->on_disconnect)
            client->on_disconnect(client->user_data);
        return -1;
    }

    /* Register pending request. */
    pending_request_t *pr = malloc(sizeof(*pr));
    if (!pr)
        return -1;

    pr->wire_id = wire_id;
    pr->on_result = on_result;
    pr->on_error = on_error;
    pr->on_cancel = on_cancel;
    pr->user_data = user_data;
    pr->timeout_handle = NULL;
    pr->client = client;

    map_add(client->pending, &wire_id, sizeof(wire_id), pr);

    /* Set timeout if requested. */
    if (timeout_ms > 0) {
        pr->timeout_handle = tev_set_timeout(client->tev, on_request_timeout,
                                             pr, (int64_t)timeout_ms);
    }

    return 0;
}
