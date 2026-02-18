#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "test_util.h"

#include "rpc/rpc_server.h"
#include "rpc/rpc_client.h"

#include <cjson/cJSON.h>
#include <tev/tev.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Test infrastructure                                                       */
/* -------------------------------------------------------------------------- */

#define TEST_SOCKET_PATH "@tcr_rpc_test"
#define WATCHDOG_MS      5000

static int test_pass_count = 0;
static int test_fail_count = 0;

#define TEST_ASSERT(expr, msg) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "  FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
            test_fail_count++; \
        } else { \
            test_pass_count++; \
        } \
    } while (0)

/* -------------------------------------------------------------------------- */
/*  Server thread                                                             */
/* -------------------------------------------------------------------------- */

typedef struct {
    tev_handle_t tev;
    rpc_server server;
    int ready_fd;       /* eventfd: signal client that server is listening */
    int stop_fd;        /* eventfd: client tells server to stop */
    const char *socket_path;
} server_ctx_t;

/*
 * Echo handler: replies with {"echo": method, "params": params}.
 * Special methods:
 *   "fail"      -> return -1 (triggers auto internal-error reply)
 *   "error"     -> reply with explicit error {code:42, message:"custom error"}
 *   "delay_ms"  -> reply after params.ms milliseconds
 */

typedef struct {
    server_ctx_t *sctx;     /* use sctx->server so we see NULL after free */
    rpc_request_handle handle;
} delayed_reply_ctx_t;

static void delayed_reply_cb(void *ctx)
{
    delayed_reply_ctx_t *dctx = ctx;
    if (dctx->sctx->server) {
        cJSON *result = cJSON_CreateObject();
        cJSON_AddStringToObject(result, "echo", "delay_ms");
        rpc_server_reply_result(dctx->sctx->server, dctx->handle, result);
        cJSON_Delete(result);
    }
    free(dctx);
}

static int server_on_request(rpc_request_handle handle, const char *method,
                             const cJSON *params, void *user_data)
{
    server_ctx_t *sctx = user_data;

    if (strcmp(method, "fail") == 0) {
        return -1;
    }

    if (strcmp(method, "error") == 0) {
        rpc_server_reply_error(sctx->server, handle, 42, "custom error");
        return 0;
    }

    if (strcmp(method, "self_destruct") == 0) {
        /* Free the server from inside the request callback.
           Must not cause UAF in on_client_readable after callback returns. */
        rpc_server_free(sctx->server);
        sctx->server = NULL;
        return 0;
    }

    if (strcmp(method, "delay_ms") == 0) {
        int ms = 100;
        if (params) {
            const cJSON *j_ms = cJSON_GetObjectItemCaseSensitive(params, "ms");
            if (cJSON_IsNumber(j_ms))
                ms = (int)cJSON_GetNumberValue(j_ms);
        }

        delayed_reply_ctx_t *dctx = malloc(sizeof(*dctx));
        if (!dctx) return -1;
        dctx->sctx = sctx;
        dctx->handle = handle;
        tev_set_timeout(sctx->tev, delayed_reply_cb, dctx, ms);
        return 0;
    }

    /* Default: echo back. */
    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "echo", method);
    if (params)
        cJSON_AddItemToObject(result, "params", cJSON_Duplicate(params, true));
    rpc_server_reply_result(sctx->server, handle, result);
    cJSON_Delete(result);
    return 0;
}

static void server_on_critical_error(const char *error_message, void *user_data)
{
    (void)user_data;
    fprintf(stderr, "Server critical error: %s\n", error_message);
}

static void server_stop_handler(void *ctx)
{
    server_ctx_t *sctx = ctx;
    uint64_t val;
    (void)read(sctx->stop_fd, &val, sizeof(val));
    rpc_server_free(sctx->server);
    sctx->server = NULL;
    tev_set_read_handler(sctx->tev, sctx->stop_fd, NULL, NULL);
    close(sctx->stop_fd);
    sctx->stop_fd = -1;
}

static void *server_thread_fn(void *arg)
{
    server_ctx_t *sctx = arg;

    sctx->tev = tev_create_ctx();
    CHECK(sctx->tev != NULL, "server: tev_create_ctx");

    sctx->server = rpc_server_new(sctx->tev, sctx->socket_path,
                                  server_on_request, server_on_critical_error,
                                  sctx);
    CHECK(sctx->server != NULL, "server: rpc_server_new");

    int rc = tev_set_read_handler(sctx->tev, sctx->stop_fd,
                                  server_stop_handler, sctx);
    CHECK(rc == 0, "server: tev_set_read_handler stop_fd");

    /* Signal the client thread that the server is ready. */
    uint64_t val = 1;
    (void)write(sctx->ready_fd, &val, sizeof(val));
    close(sctx->ready_fd);
    sctx->ready_fd = -1;

    tev_main_loop(sctx->tev);
    tev_free_ctx(sctx->tev);
    return NULL;
}

static void start_server(server_ctx_t *sctx, pthread_t *tid)
{
    sctx->ready_fd = eventfd(0, 0);
    CHECK(sctx->ready_fd >= 0, "eventfd ready_fd");
    sctx->stop_fd = eventfd(0, EFD_NONBLOCK);
    CHECK(sctx->stop_fd >= 0, "eventfd stop_fd");
    if (!sctx->socket_path)
        sctx->socket_path = TEST_SOCKET_PATH;

    int rc = pthread_create(tid, NULL, server_thread_fn, sctx);
    CHECK(rc == 0, "pthread_create server");

    /* Block until server is ready. */
    uint64_t val;
    (void)read(sctx->ready_fd, &val, sizeof(val));
}

static void stop_server(server_ctx_t *sctx, pthread_t tid)
{
    if (sctx->stop_fd >= 0) {
        uint64_t val = 1;
        (void)write(sctx->stop_fd, &val, sizeof(val));
    }
    pthread_join(tid, NULL);
}

/* -------------------------------------------------------------------------- */
/*  Client-side test state + event-loop helpers                               */
/* -------------------------------------------------------------------------- */

/*
 * tev_main_loop exits when all fd handlers and timeouts are gone.
 * To exit reliably we:
 *   1) keep a dummy eventfd ("stop_fd") registered to prevent premature exit
 *   2) writing to stop_fd triggers stop_read_handler which:
 *      - unregisters & closes stop_fd
 *      - cancels the watchdog timeout
 *      - calls rpc_client_close (unregisters client fd handlers)
 *   3) with nothing left, tev_main_loop returns
 */

typedef struct test_state_s test_state_t;
struct test_state_s {
    tev_handle_t tev;
    rpc_client client;
    int stop_fd;
    tev_timeout_handle_t watchdog;

    /* Connect */
    bool connect_success;
    bool disconnected;

    /* Result accumulators */
    int result_count;
    int error_count;
    int cancel_count;

    cJSON *last_result;
    int last_error_code;
    char last_error_message[256];

    /* Test-specific data (e.g., pointer to server_ctx for shutdown test) */
    void *extra;
};

static void test_stop(test_state_t *ts)
{
    if (ts->stop_fd < 0) return;
    uint64_t val = 1;
    (void)write(ts->stop_fd, &val, sizeof(val));
}

static void stop_read_handler(void *ctx)
{
    test_state_t *ts = ctx;
    uint64_t val;
    (void)read(ts->stop_fd, &val, sizeof(val));

    tev_set_read_handler(ts->tev, ts->stop_fd, NULL, NULL);
    close(ts->stop_fd);
    ts->stop_fd = -1;

    if (ts->watchdog) {
        tev_clear_timeout(ts->tev, ts->watchdog);
        ts->watchdog = NULL;
    }

    if (ts->client) {
        rpc_client_close(ts->client);
        ts->client = NULL;
    }
}

static void watchdog_handler(void *ctx)
{
    test_state_t *ts = ctx;
    ts->watchdog = NULL;
    fprintf(stderr, "  WATCHDOG fired - test hung!\n");
    test_stop(ts);
}

static void test_state_init(test_state_t *ts, tev_handle_t tev)
{
    memset(ts, 0, sizeof(*ts));
    ts->tev = tev;
    ts->stop_fd = eventfd(0, EFD_NONBLOCK);
    CHECK(ts->stop_fd >= 0, "eventfd for test stop");
    tev_set_read_handler(tev, ts->stop_fd, stop_read_handler, ts);
    ts->watchdog = tev_set_timeout(tev, watchdog_handler, ts, WATCHDOG_MS);
}

static void test_state_cleanup(test_state_t *ts)
{
    if (ts->stop_fd >= 0) {
        tev_set_read_handler(ts->tev, ts->stop_fd, NULL, NULL);
        close(ts->stop_fd);
    }
    if (ts->watchdog)
        tev_clear_timeout(ts->tev, ts->watchdog);
    if (ts->client)
        rpc_client_close(ts->client);
    if (ts->last_result)
        cJSON_Delete(ts->last_result);
}

/* -------------------------------------------------------------------------- */
/*  Common callbacks                                                          */
/* -------------------------------------------------------------------------- */

/* Saves result and stops the loop (for single-request tests). */
static void on_result_then_stop(const cJSON *result, void *user_data)
{
    test_state_t *ts = user_data;
    ts->result_count++;
    if (ts->last_result) cJSON_Delete(ts->last_result);
    ts->last_result = cJSON_Duplicate(result, true);
    test_stop(ts);
}

/* Saves error and stops the loop (for single-request tests). */
static void on_error_then_stop(int code, const char *msg, void *user_data)
{
    test_state_t *ts = user_data;
    ts->error_count++;
    ts->last_error_code = code;
    snprintf(ts->last_error_message, sizeof(ts->last_error_message),
             "%s", msg ? msg : "");
    test_stop(ts);
}

/* Increments cancel count (does NOT stop - disconnect handler will). */
static void on_cancel_count(void *user_data)
{
    test_state_t *ts = user_data;
    ts->cancel_count++;
}

/* Sets disconnect flag and stops. */
static void on_disconnect_then_stop(void *user_data)
{
    test_state_t *ts = user_data;
    ts->disconnected = true;
    test_stop(ts);
}

/* -------------------------------------------------------------------------- */
/*  Test 1: Basic echo request/response                                       */
/* -------------------------------------------------------------------------- */

static void echo_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "hello", "world");
    int rc = rpc_client_make_request_async(ts->client, "echo", params, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    cJSON_Delete(params);
    if (rc != 0) test_stop(ts);
}

static void test_basic_echo(void)
{
    printf("test_basic_echo...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      echo_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect successfully");
    TEST_ASSERT(ts.result_count == 1, "should receive 1 result");
    TEST_ASSERT(ts.last_result != NULL, "result should not be NULL");
    if (ts.last_result) {
        cJSON *echo = cJSON_GetObjectItemCaseSensitive(ts.last_result, "echo");
        TEST_ASSERT(cJSON_IsString(echo) &&
                    strcmp(cJSON_GetStringValue(echo), "echo") == 0,
                    "echo field should be 'echo'");
        cJSON *p = cJSON_GetObjectItemCaseSensitive(ts.last_result, "params");
        TEST_ASSERT(p != NULL, "params should be echoed back");
        if (p) {
            cJSON *h = cJSON_GetObjectItemCaseSensitive(p, "hello");
            TEST_ASSERT(cJSON_IsString(h) &&
                        strcmp(cJSON_GetStringValue(h), "world") == 0,
                        "params.hello should be 'world'");
        }
    }

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 2: Server returns explicit error                                     */
/* -------------------------------------------------------------------------- */

static void error_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    int rc = rpc_client_make_request_async(ts->client, "error", NULL, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void test_error_response(void)
{
    printf("test_error_response...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      error_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.error_count == 1, "should receive 1 error");
    TEST_ASSERT(ts.last_error_code == 42, "error code should be 42");
    TEST_ASSERT(strcmp(ts.last_error_message, "custom error") == 0,
                "error message should be 'custom error'");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 3: Handler returns -1 -> auto internal error reply                   */
/* -------------------------------------------------------------------------- */

static void fail_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    int rc = rpc_client_make_request_async(ts->client, "fail", NULL, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void test_handler_failure(void)
{
    printf("test_handler_failure...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      fail_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.error_count == 1, "should receive 1 error");
    TEST_ASSERT(ts.last_error_code == -1, "error code should be -1");
    TEST_ASSERT(strcmp(ts.last_error_message, "internal error") == 0,
                "error message should be 'internal error'");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 4: Request timeout (connection stays alive, stale reply discarded)   */
/* -------------------------------------------------------------------------- */

/*
 * Flow:
 *  on_connect -> send delay_ms(500ms) with 100ms timeout
 *  on_error (timeout) -> record error, set 600ms timer to wait for stale reply
 *  timer fires -> check no result arrived, send a normal "ping" request
 *  on_result (ping) -> verify, stop
 */

static void timeout_verify_on_result(const cJSON *result, void *user_data);
static void timeout_check_stale(void *ctx);

static void timeout_request_on_error(int code, const char *msg, void *user_data)
{
    test_state_t *ts = user_data;
    ts->error_count++;
    ts->last_error_code = code;
    snprintf(ts->last_error_message, sizeof(ts->last_error_message),
             "%s", msg ? msg : "");
    /* Don't stop -- wait for the stale reply period, then send another request. */
    tev_set_timeout(ts->tev, timeout_check_stale, ts, 600);
}

static void timeout_check_stale(void *ctx)
{
    test_state_t *ts = ctx;
    /* By now the server's delayed reply (500ms) should have arrived and been
       discarded (id doesn't match any pending request). result_count should
       still be 0. Send a normal request to verify the connection is alive. */
    int rc = rpc_client_make_request_async(ts->client, "ping", NULL, 0,
                                           timeout_verify_on_result,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void timeout_verify_on_result(const cJSON *result, void *user_data)
{
    test_state_t *ts = user_data;
    ts->result_count++;
    if (ts->last_result) cJSON_Delete(ts->last_result);
    ts->last_result = cJSON_Duplicate(result, true);
    test_stop(ts);
}

static void timeout_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "ms", 500);
    int rc = rpc_client_make_request_async(ts->client, "delay_ms", params, 100,
                                           on_result_then_stop,
                                           timeout_request_on_error,
                                           on_cancel_count, ts);
    cJSON_Delete(params);
    if (rc != 0) test_stop(ts);
}

static void test_request_timeout(void)
{
    printf("test_request_timeout...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      timeout_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.error_count == 1, "should receive 1 timeout error");
    TEST_ASSERT(ts.last_error_code == -1, "timeout error code should be -1");
    TEST_ASSERT(strcmp(ts.last_error_message, "request timed out") == 0,
                "should be 'request timed out'");
    TEST_ASSERT(ts.result_count == 1,
                "should receive result from follow-up ping (connection alive)");
    TEST_ASSERT(!ts.disconnected, "should not be disconnected after timeout");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 5: Multiple concurrent requests                                      */
/* -------------------------------------------------------------------------- */

#define CONCURRENT_N 5

static void concurrent_on_result(const cJSON *result, void *user_data)
{
    (void)result;
    test_state_t *ts = user_data;
    ts->result_count++;
    if (ts->result_count >= CONCURRENT_N)
        test_stop(ts);
}

static void concurrent_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    for (int i = 0; i < CONCURRENT_N; i++) {
        char method[32];
        snprintf(method, sizeof(method), "req_%d", i);
        int rc = rpc_client_make_request_async(ts->client, method, NULL, 0,
                                               concurrent_on_result,
                                               on_error_then_stop,
                                               on_cancel_count, ts);
        if (rc != 0) { test_stop(ts); return; }
    }
}

static void test_concurrent_requests(void)
{
    printf("test_concurrent_requests...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      concurrent_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.result_count == CONCURRENT_N,
                "should receive all 5 results");
    TEST_ASSERT(ts.error_count == 0, "should have no errors");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 6: Server shutdown cancels pending requests                          */
/* -------------------------------------------------------------------------- */

static void shutdown_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    /* Send a request with a long delay so it won't complete before shutdown. */
    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "ms", 5000);
    int rc = rpc_client_make_request_async(ts->client, "delay_ms", params, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    cJSON_Delete(params);
    if (rc != 0) { test_stop(ts); return; }

    /* Trigger server shutdown from the client thread (eventfd write is safe). */
    server_ctx_t *sctx = ts->extra;
    uint64_t val = 1;
    (void)write(sctx->stop_fd, &val, sizeof(val));
}

static void test_server_shutdown_cancels(void)
{
    printf("test_server_shutdown_cancels...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);
    ts.extra = &sctx;

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      shutdown_on_connect,
                                      on_disconnect_then_stop, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.cancel_count >= 1, "pending request should be cancelled");
    TEST_ASSERT(ts.disconnected, "should receive disconnect callback");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    /* Server already stopped, just join. */
    pthread_join(tid, NULL);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 7: rpc_client_close cancels pending requests                         */
/* -------------------------------------------------------------------------- */

static void close_cancel_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    /* Send a request with long delay. */
    cJSON *params = cJSON_CreateObject();
    cJSON_AddNumberToObject(params, "ms", 5000);
    int rc = rpc_client_make_request_async(ts->client, "delay_ms", params, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    cJSON_Delete(params);
    if (rc != 0) { test_stop(ts); return; }

    /* Immediately close the client. This should cancel the pending request. */
    rpc_client_close(ts->client);
    ts->client = NULL;  /* prevent stop_read_handler from double-closing */

    /* Now stop the loop (client is gone, just clean up stop_fd/watchdog). */
    test_stop(ts);
}

static void test_client_close_cancels(void)
{
    printf("test_client_close_cancels...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      close_cancel_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.cancel_count == 1,
                "pending request should be cancelled on close");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 8: Connect to non-existent server fails                              */
/* -------------------------------------------------------------------------- */

static void test_connect_failure(void)
{
    printf("test_connect_failure...\n");

    /* No server started. Connect should fail. */
    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    rpc_client client = rpc_client_open_async(
        tev, "@tcr_rpc_test_nonexistent",
        NULL, NULL, &ts);

    if (client != NULL) {
        /* Async failure path -- should get on_connect(false). Not expected for
           SEQPACKET (connect fails synchronously), but handle it. */
        ts.client = client;
        tev_main_loop(tev);
        TEST_ASSERT(!ts.connect_success, "connect should fail");
    } else {
        /* Synchronous failure -- expected for SEQPACKET. */
        test_pass_count++;
    }

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 9: Multiple clients concurrently                                     */
/* -------------------------------------------------------------------------- */

typedef struct {
    test_state_t *ts1;
    test_state_t *ts2;
} multi_client_extra_t;

static void multi_check_done(test_state_t *ts)
{
    multi_client_extra_t *extra = ts->extra;
    if (extra->ts1->result_count >= 1 && extra->ts2->result_count >= 1) {
        /* Close ts2's client before stopping, since stop_read_handler
           only closes ts1's client. Without this, ts2's read handler
           keeps the event loop alive. */
        if (extra->ts2->client) {
            rpc_client_close(extra->ts2->client);
            extra->ts2->client = NULL;
        }
        test_stop(extra->ts1);  /* ts1 owns the stop_fd */
    }
}

static void multi_on_result(const cJSON *result, void *user_data)
{
    test_state_t *ts = user_data;
    ts->result_count++;
    if (ts->last_result) cJSON_Delete(ts->last_result);
    ts->last_result = cJSON_Duplicate(result, true);
    multi_check_done(ts);
}

static void multi_on_connect_1(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    int rc = rpc_client_make_request_async(ts->client, "from_client_1", NULL, 0,
                                           multi_on_result, on_error_then_stop,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void multi_on_connect_2(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    int rc = rpc_client_make_request_async(ts->client, "from_client_2", NULL, 0,
                                           multi_on_result, on_error_then_stop,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void test_multiple_clients(void)
{
    printf("test_multiple_clients...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();

    /* Two test states share the same tev and stop mechanism.
       Only ts1 owns the stop_fd; ts2 relies on ts1 to stop the loop. */
    test_state_t ts1, ts2;
    test_state_init(&ts1, tev);
    memset(&ts2, 0, sizeof(ts2));
    ts2.tev = tev;

    multi_client_extra_t extra = {&ts1, &ts2};
    ts1.extra = &extra;
    ts2.extra = &extra;

    ts1.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                       multi_on_connect_1, NULL, &ts1);
    ts2.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                       multi_on_connect_2, NULL, &ts2);
    CHECK(ts1.client != NULL, "client1 open");
    CHECK(ts2.client != NULL, "client2 open");

    tev_main_loop(tev);

    TEST_ASSERT(ts1.connect_success, "client1 should connect");
    TEST_ASSERT(ts2.connect_success, "client2 should connect");
    TEST_ASSERT(ts1.result_count == 1, "client1 should get 1 result");
    TEST_ASSERT(ts2.result_count == 1, "client2 should get 1 result");

    if (ts1.last_result) {
        cJSON *echo = cJSON_GetObjectItemCaseSensitive(ts1.last_result, "echo");
        TEST_ASSERT(cJSON_IsString(echo) &&
                    strcmp(cJSON_GetStringValue(echo), "from_client_1") == 0,
                    "client1 should get its own echo");
    }
    if (ts2.last_result) {
        cJSON *echo = cJSON_GetObjectItemCaseSensitive(ts2.last_result, "echo");
        TEST_ASSERT(cJSON_IsString(echo) &&
                    strcmp(cJSON_GetStringValue(echo), "from_client_2") == 0,
                    "client2 should get its own echo");
    }

    /* Clean up ts2's client manually (ts1's is handled by test_state_cleanup). */
    if (ts2.client) { rpc_client_close(ts2.client); ts2.client = NULL; }
    if (ts2.last_result) { cJSON_Delete(ts2.last_result); ts2.last_result = NULL; }
    test_state_cleanup(&ts1);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 10: Filesystem socket with permissions                               */
/* -------------------------------------------------------------------------- */

static void fs_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    int rc = rpc_client_make_request_async(ts->client, "fs_test", NULL, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void test_filesystem_socket(void)
{
    printf("test_filesystem_socket...\n");

    char sock_path[] = "/tmp/tcr_rpc_test_XXXXXX";
    int tmp_fd = mkstemp(sock_path);
    CHECK(tmp_fd >= 0, "mkstemp");
    close(tmp_fd);
    unlink(sock_path);

    server_ctx_t sctx = {.socket_path = sock_path};
    pthread_t tid;
    start_server(&sctx, &tid);

    /* Verify socket permissions. */
    struct stat st;
    int rc = stat(sock_path, &st);
    TEST_ASSERT(rc == 0, "socket file should exist");
    if (rc == 0)
        TEST_ASSERT((st.st_mode & 0777) == 0600, "socket should be mode 0600");

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, sock_path,
                                      fs_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open fs");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect via filesystem socket");
    TEST_ASSERT(ts.result_count == 1, "should get result");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);

    /* Socket file should be cleaned up by rpc_server_free. */
    TEST_ASSERT(stat(sock_path, &st) != 0,
                "socket file should be removed after server free");

    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 11: Client closes connection inside result callback                  */
/* -------------------------------------------------------------------------- */

static void close_in_result_cb(const cJSON *result, void *user_data)
{
    test_state_t *ts = user_data;
    ts->result_count++;
    if (ts->last_result) cJSON_Delete(ts->last_result);
    ts->last_result = cJSON_Duplicate(result, true);

    /* Close the client from inside the callback — must not cause UAF. */
    rpc_client_close(ts->client);
    ts->client = NULL;

    test_stop(ts);
}

static void close_in_result_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "tag", "close_in_result");
    int rc = rpc_client_make_request_async(ts->client, "echo", params, 0,
                                           close_in_result_cb,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    cJSON_Delete(params);
    if (rc != 0) test_stop(ts);
}

static void test_close_in_result_callback(void)
{
    printf("test_close_in_result_callback...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      close_in_result_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.result_count == 1, "should receive result before close");
    TEST_ASSERT(ts.last_result != NULL, "result should be saved");
    if (ts.last_result) {
        cJSON *echo = cJSON_GetObjectItemCaseSensitive(ts.last_result, "echo");
        TEST_ASSERT(cJSON_IsString(echo) &&
                    strcmp(cJSON_GetStringValue(echo), "echo") == 0,
                    "echo field should be 'echo'");
    }

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 12: Client closes connection inside error callback                   */
/* -------------------------------------------------------------------------- */

static void close_in_error_cb(int code, const char *msg, void *user_data)
{
    test_state_t *ts = user_data;
    ts->error_count++;
    ts->last_error_code = code;
    snprintf(ts->last_error_message, sizeof(ts->last_error_message),
             "%s", msg ? msg : "");

    /* Close the client from inside the error callback — must not cause UAF. */
    rpc_client_close(ts->client);
    ts->client = NULL;

    test_stop(ts);
}

static void close_in_error_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    int rc = rpc_client_make_request_async(ts->client, "error", NULL, 0,
                                           on_result_then_stop,
                                           close_in_error_cb,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void test_close_in_error_callback(void)
{
    printf("test_close_in_error_callback...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      close_in_error_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.error_count == 1, "should receive error before close");
    TEST_ASSERT(ts.last_error_code == 42, "error code should be 42");
    TEST_ASSERT(strcmp(ts.last_error_message, "custom error") == 0,
                "error message should be 'custom error'");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 13: Server frees itself inside on_request callback (sync)            */
/* -------------------------------------------------------------------------- */

static void self_destruct_on_disconnect(void *user_data)
{
    test_state_t *ts = user_data;
    ts->disconnected = true;
    test_stop(ts);
}

static void self_destruct_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    /* This method makes the server call rpc_server_free inside on_request. */
    int rc = rpc_client_make_request_async(ts->client, "self_destruct", NULL, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    if (rc != 0) test_stop(ts);
}

static void test_server_self_close_in_callback(void)
{
    printf("test_server_self_close_in_callback...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      self_destruct_on_connect,
                                      self_destruct_on_disconnect, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    /* Server destroyed the connection, so the client sees disconnect
       and pending request gets cancelled. */
    TEST_ASSERT(ts.cancel_count == 1 || ts.disconnected,
                "should get cancel or disconnect after server self-destruct");

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Test 14: Server replies synchronously inside on_request                   */
/* -------------------------------------------------------------------------- */

static void sync_reply_on_connect(bool success, void *user_data)
{
    test_state_t *ts = user_data;
    ts->connect_success = success;
    if (!success) { test_stop(ts); return; }

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "greeting", "hi");
    int rc = rpc_client_make_request_async(ts->client, "echo", params, 0,
                                           on_result_then_stop,
                                           on_error_then_stop,
                                           on_cancel_count, ts);
    cJSON_Delete(params);
    if (rc != 0) test_stop(ts);
}

static void test_sync_reply_in_on_request(void)
{
    printf("test_sync_reply_in_on_request...\n");

    server_ctx_t sctx = {0};
    pthread_t tid;
    start_server(&sctx, &tid);

    tev_handle_t tev = tev_create_ctx();
    test_state_t ts;
    test_state_init(&ts, tev);

    ts.client = rpc_client_open_async(tev, TEST_SOCKET_PATH,
                                      sync_reply_on_connect, NULL, &ts);
    CHECK(ts.client != NULL, "client open");

    tev_main_loop(tev);

    TEST_ASSERT(ts.connect_success, "should connect");
    TEST_ASSERT(ts.result_count == 1, "should receive 1 result");
    TEST_ASSERT(ts.error_count == 0, "should receive 0 errors");
    TEST_ASSERT(ts.last_result != NULL, "result should not be NULL");
    if (ts.last_result) {
        cJSON *echo = cJSON_GetObjectItemCaseSensitive(ts.last_result, "echo");
        TEST_ASSERT(cJSON_IsString(echo) &&
                    strcmp(cJSON_GetStringValue(echo), "echo") == 0,
                    "echo field should be 'echo'");
        cJSON *p = cJSON_GetObjectItemCaseSensitive(ts.last_result, "params");
        TEST_ASSERT(p != NULL, "params should be echoed back");
        if (p) {
            cJSON *g = cJSON_GetObjectItemCaseSensitive(p, "greeting");
            TEST_ASSERT(cJSON_IsString(g) &&
                        strcmp(cJSON_GetStringValue(g), "hi") == 0,
                        "params.greeting should be 'hi'");
        }
    }

    test_state_cleanup(&ts);
    tev_free_ctx(tev);
    stop_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                      */
/* -------------------------------------------------------------------------- */

int main(void)
{
    printf("=== RPC Client/Server Tests ===\n\n");

    test_basic_echo();
    test_error_response();
    test_handler_failure();
    test_request_timeout();
    test_concurrent_requests();
    test_server_shutdown_cancels();
    test_client_close_cancels();
    test_connect_failure();
    test_multiple_clients();
    test_filesystem_socket();
    test_close_in_result_callback();
    test_close_in_error_callback();
    test_server_self_close_in_callback();
    test_sync_reply_in_on_request();

    printf("\n=== Results: %d passed, %d failed ===\n",
           test_pass_count, test_fail_count);

    return test_fail_count > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
