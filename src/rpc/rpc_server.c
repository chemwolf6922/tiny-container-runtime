#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "rpc_server.h"

#include <tev/map.h>

#include <cjson/cJSON.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Data structures                                                           */
/* -------------------------------------------------------------------------- */

typedef struct {
    int client_fd;
    double wire_id;
} pending_request_t;

struct rpc_server_s {
    tev_handle_t tev;
    int listen_fd;
    char *socket_path;      /* strdup'd filesystem path; NULL for abstract */
    bool is_abstract;
    uid_t owner_uid;

    int (*on_request)(rpc_request_handle handle, const char *method,
                      const cJSON *params, void *user_data);
    void (*on_critical_error)(const char *error_message, void *user_data);
    void *user_data;

    map_handle_t clients;   /* fd (int, 4 bytes) → NULL (presence tracking) */
    map_handle_t pending;   /* handle (uint64_t, 8 bytes) → pending_request_t* */
    uint64_t next_handle;

    /* Set by on_client_readable before calling on_request so that
       rpc_server_free can signal back if the server was destroyed
       inside the callback. */
    bool *destroyed_flag;
};

/* -------------------------------------------------------------------------- */
/*  Forward declarations                                                      */
/* -------------------------------------------------------------------------- */

static void on_accept(void *ctx);
static void on_client_readable(void *ctx);
static void close_client(rpc_server server, int fd);
static int send_reply(rpc_server server, int fd, const char *msg);
static int recv_message(int fd, uint8_t **out_buf, size_t *out_len);

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Receive a single SEQPACKET message.  The caller must free *out_buf.
 * Returns 0 on success, -1 on error, 1 on peer shutdown.
 */
static int recv_message(int fd, uint8_t **out_buf, size_t *out_len)
{
    /* Peek to learn the true message size (MSG_TRUNC returns full length). */
    char peek;
    ssize_t total = recv(fd, &peek, 1, MSG_PEEK | MSG_TRUNC);
    if (total == 0) return 1;           /* peer closed */
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
 * Send a message with MSG_DONTWAIT.  If the send would block, close the
 * connection and return -1.
 */
static int send_reply(rpc_server server, int fd, const char *msg)
{
    size_t len = strlen(msg);
    ssize_t n = send(fd, msg, len, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n < 0 || (size_t)n != len) {
        close_client(server, fd);
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  Client lifecycle                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Context block passed to tev read-handler for a client fd.
 * Allocated on accept, freed on client close.
 */
typedef struct {
    rpc_server server;
    int fd;
} client_ctx_t;

static void close_client(rpc_server server, int fd)
{
    /* Unregister from tev and close fd. */
    tev_set_read_handler(server->tev, fd, NULL, NULL);

    /* Remove from clients map; the value is the client_ctx_t* we allocated. */
    client_ctx_t *cctx = map_remove(server->clients, &fd, sizeof(fd));
    free(cctx);

    close(fd);

    /* Remove all pending requests that belonged to this client. */
    size_t nkeys = 0;
    map_key_t *keys = map_keys(server->pending, &nkeys);
    if (keys) {
        for (size_t i = 0; i < nkeys; i++) {
            pending_request_t *pr = map_get(server->pending,
                                            keys[i].key, keys[i].len);
            if (pr && pr->client_fd == fd) {
                map_remove(server->pending, keys[i].key, keys[i].len);
                free(pr);
            }
        }
        free(keys);
    }
}

/* -------------------------------------------------------------------------- */
/*  Event handlers                                                            */
/* -------------------------------------------------------------------------- */

static void on_client_readable(void *ctx)
{
    client_ctx_t *cctx = ctx;
    rpc_server server = cctx->server;
    int fd = cctx->fd;

    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = recv_message(fd, &buf, &len);
    if (rc != 0) {
        close_client(server, fd);
        return;
    }

    /* Parse JSON request: {"id": <double>, "method": "<string>", "params": ...} */
    cJSON *root = cJSON_ParseWithLength((const char *)buf, len);
    free(buf);
    if (!root)
        return;     /* malformed message — discard silently */

    cJSON *j_id     = cJSON_GetObjectItemCaseSensitive(root, "id");
    cJSON *j_method = cJSON_GetObjectItemCaseSensitive(root, "method");
    cJSON *j_params = cJSON_GetObjectItemCaseSensitive(root, "params");

    if (!cJSON_IsNumber(j_id) || !cJSON_IsString(j_method)) {
        cJSON_Delete(root);
        return;     /* missing required fields — discard silently */
    }

    double wire_id = cJSON_GetNumberValue(j_id);
    char *method = strdup(cJSON_GetStringValue(j_method));
    if (!method) {
        cJSON_Delete(root);
        close_client(server, fd);
        return;
    }

    /* Register pending request. */
    uint64_t handle = server->next_handle++;
    pending_request_t *pr = malloc(sizeof(*pr));
    if (!pr) {
        free(method);
        cJSON_Delete(root);
        close_client(server, fd);
        return;
    }
    pr->client_fd = fd;
    pr->wire_id = wire_id;
    map_add(server->pending, &handle, sizeof(handle), pr);

    /* Invoke user callback.  params points into root — delete root after.
       The callback may call rpc_server_free, so we use a stack-local flag
       to detect destruction and avoid touching `server` afterwards. */
    bool destroyed = false;
    server->destroyed_flag = &destroyed;
    int handler_rc = server->on_request(handle, method, j_params,
                                        server->user_data);
    free(method);
    cJSON_Delete(root);
    if (destroyed)
        return;     /* server was freed inside on_request — don't touch it */
    server->destroyed_flag = NULL;
    if (handler_rc != 0) {
        /* Auto-reply with internal error. */
        rpc_server_reply_error(server, handle, -1, "internal error");
    }
}

static void on_accept(void *ctx)
{
    rpc_server server = ctx;

    int client_fd = accept4(server->listen_fd, NULL, NULL,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (client_fd < 0)
        return;

    /* For abstract sockets, verify peer uid matches the server owner. */
    if (server->is_abstract) {
        struct ucred cred;
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                       &cred, &cred_len) < 0 ||
            cred.uid != server->owner_uid) {
            close(client_fd);
            return;
        }
    }

    client_ctx_t *cctx = malloc(sizeof(*cctx));
    if (!cctx) {
        close(client_fd);
        return;
    }
    cctx->server = server;
    cctx->fd = client_fd;

    map_add(server->clients, &client_fd, sizeof(client_fd), cctx);

    if (tev_set_read_handler(server->tev, client_fd,
                             on_client_readable, cctx) != 0) {
        map_remove(server->clients, &client_fd, sizeof(client_fd));
        free(cctx);
        close(client_fd);
    }
}

static void free_pending_cb(void *value, void *ctx)
{
    (void)ctx;
    free(value);
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

rpc_server rpc_server_new(
    tev_handle_t tev, const char *socket_path,
    int (*on_request)(rpc_request_handle handle, const char *method,
                      const cJSON *params, void *user_data),
    void (*on_critical_error)(const char *error_message, void *user_data),
    void *user_data)
{
    if (!tev || !socket_path || !on_request || !on_critical_error)
        return NULL;

    bool is_abstract = (socket_path[0] == '@');

    /* Create SEQPACKET socket. */
    int listen_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd < 0)
        return NULL;

    /* Build sockaddr_un. */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    size_t path_len;
    if (is_abstract) {
        /* Abstract namespace: first byte is '\0', rest is the name (skip '@'). */
        path_len = strlen(socket_path + 1);
        if (path_len + 1 > sizeof(addr.sun_path)) {
            close(listen_fd);
            return NULL;
        }
        addr.sun_path[0] = '\0';
        memcpy(addr.sun_path + 1, socket_path + 1, path_len);
        path_len += 1;  /* include leading '\0' */
    } else {
        path_len = strlen(socket_path);
        if (path_len >= sizeof(addr.sun_path)) {
            close(listen_fd);
            return NULL;
        }
        /* Remove stale socket file. */
        unlink(socket_path);
        memcpy(addr.sun_path, socket_path, path_len + 1);
    }

    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len);

    if (bind(listen_fd, (struct sockaddr *)&addr, addr_len) < 0) {
        close(listen_fd);
        return NULL;
    }

    /* Filesystem socket: restrict to owner. */
    if (!is_abstract) {
        if (chmod(socket_path, 0600) < 0) {
            close(listen_fd);
            unlink(socket_path);
            return NULL;
        }
    }

    if (listen(listen_fd, 8) < 0) {
        close(listen_fd);
        if (!is_abstract) unlink(socket_path);
        return NULL;
    }

    /* Allocate server struct. */
    rpc_server server = calloc(1, sizeof(*server));
    if (!server) {
        close(listen_fd);
        if (!is_abstract) unlink(socket_path);
        return NULL;
    }

    server->tev = tev;
    server->listen_fd = listen_fd;
    server->socket_path = is_abstract ? NULL : strdup(socket_path);
    server->is_abstract = is_abstract;
    server->owner_uid = geteuid();
    server->on_request = on_request;
    server->on_critical_error = on_critical_error;
    server->user_data = user_data;
    server->clients = map_create();
    server->pending = map_create();
    server->next_handle = 1;

    if (!server->clients || !server->pending) {
        map_delete(server->clients, NULL, NULL);
        map_delete(server->pending, NULL, NULL);
        free(server->socket_path);
        close(listen_fd);
        if (!is_abstract) unlink(socket_path);
        free(server);
        return NULL;
    }

    if (!is_abstract && !server->socket_path) {
        /* strdup failed */
        map_delete(server->clients, NULL, NULL);
        map_delete(server->pending, NULL, NULL);
        close(listen_fd);
        unlink(socket_path);
        free(server);
        return NULL;
    }

    if (tev_set_read_handler(tev, listen_fd, on_accept, server) != 0) {
        map_delete(server->clients, NULL, NULL);
        map_delete(server->pending, NULL, NULL);
        free(server->socket_path);
        close(listen_fd);
        if (!is_abstract) unlink(socket_path);
        free(server);
        return NULL;
    }

    return server;
}

void rpc_server_free(rpc_server server)
{
    if (!server)
        return;

    /* Signal any in-progress on_request callback that the server is gone. */
    if (server->destroyed_flag)
        *server->destroyed_flag = true;

    /* Unregister listen fd. */
    tev_set_read_handler(server->tev, server->listen_fd, NULL, NULL);
    close(server->listen_fd);

    /* Close all client connections (unregister + close fd). */
    size_t nkeys = 0;
    map_key_t *keys = map_keys(server->clients, &nkeys);
    if (keys) {
        for (size_t i = 0; i < nkeys; i++) {
            int fd;
            memcpy(&fd, keys[i].key, sizeof(fd));
            tev_set_read_handler(server->tev, fd, NULL, NULL);
            client_ctx_t *cctx = map_get(server->clients,
                                         keys[i].key, keys[i].len);
            free(cctx);
            close(fd);
        }
        free(keys);
    }
    map_delete(server->clients, NULL, NULL);

    /* Free all pending requests. */
    map_delete(server->pending, free_pending_cb, NULL);

    /* Remove filesystem socket. */
    if (server->socket_path) {
        unlink(server->socket_path);
        free(server->socket_path);
    }

    free(server);
}

int rpc_server_reply_result(rpc_server server, rpc_request_handle handle, const cJSON *result)
{
    if (!server)
        return -1;

    pending_request_t *pr = map_remove(server->pending, &handle, sizeof(handle));
    if (!pr)
        return -1;

    int client_fd = pr->client_fd;
    double wire_id = pr->wire_id;
    free(pr);

    /* Check the client is still connected. */
    if (!map_has(server->clients, &client_fd, sizeof(client_fd)))
        return -1;

    /* Build response JSON. */
    cJSON *resp = cJSON_CreateObject();
    if (!resp)
        return -1;

    cJSON_AddNumberToObject(resp, "id", wire_id);
    if (result)
        cJSON_AddItemReferenceToObject(resp, "result", (cJSON *)result);
    else
        cJSON_AddNullToObject(resp, "result");

    char *msg = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    if (!msg)
        return -1;

    int rc = send_reply(server, client_fd, msg);
    free(msg);
    return rc;
}

int rpc_server_reply_error(rpc_server server, rpc_request_handle handle,
                           int error_code, const char *error_message)
{
    if (!server)
        return -1;

    pending_request_t *pr = map_remove(server->pending, &handle, sizeof(handle));
    if (!pr)
        return -1;

    int client_fd = pr->client_fd;
    double wire_id = pr->wire_id;
    free(pr);

    /* Check the client is still connected. */
    if (!map_has(server->clients, &client_fd, sizeof(client_fd)))
        return -1;

    /* Build error response JSON. */
    cJSON *resp = cJSON_CreateObject();
    if (!resp)
        return -1;

    cJSON_AddNumberToObject(resp, "id", wire_id);

    cJSON *err_obj = cJSON_AddObjectToObject(resp, "error");
    if (!err_obj) {
        cJSON_Delete(resp);
        return -1;
    }
    cJSON_AddNumberToObject(err_obj, "code", error_code);
    cJSON_AddStringToObject(err_obj, "message",
                            error_message ? error_message : "unknown error");

    char *msg = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);
    if (!msg)
        return -1;

    int rc = send_reply(server, client_fd, msg);
    free(msg);
    return rc;
}
