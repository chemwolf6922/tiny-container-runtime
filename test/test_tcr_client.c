#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "test_util.h"

#include "rpc/rpc_server.h"

#include <cjson/cJSON.h>
#include <tev/tev.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Test infrastructure                                                       */
/* -------------------------------------------------------------------------- */

#define TEST_SOCKET_PATH "@tcr_client_test"
#define TCR_CLIENT_BIN   "./test_tcr_client_helper"
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
/*  Mock server                                                               */
/* -------------------------------------------------------------------------- */

typedef struct {
    tev_handle_t tev;
    rpc_server server;
    int ready_fd;
    int stop_fd;
} mock_server_ctx_t;

/**
 * Mock request handler. Behavior is determined by method name:
 *   "echo_exit"   -> reply with { exitCode: 0, stdOut: "hello\n", stdErr: "" }
 *   "exit_error"  -> reply with { exitCode: 42, stdOut: "", stdErr: "fail\n" }
 *   "exec_true"   -> reply with { execArgs: ["/bin/true"] }
 *   "exec_echo"   -> reply with { execArgs: ["/bin/echo", "exec_output"] }
 *   "exec_empty"  -> reply with { execArgs: [] }
 *   "rpc_error"   -> reply with error { code: 99, message: "mock error" }
 *   "echo_params" -> reply with { exitCode: 0, stdOut: <JSON of params>, stdErr: "" }
 *   anything else -> reply with { exitCode: 0, stdOut: "ok\n", stdErr: "" }
 */
static int mock_on_request(rpc_request_handle handle, const char *method,
                           const cJSON *params, void *user_data)
{
    mock_server_ctx_t *ctx = user_data;

    if (strcmp(method, "echo_exit") == 0) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddNumberToObject(r, "exitCode", 0);
        cJSON_AddStringToObject(r, "stdOut", "hello\n");
        cJSON_AddStringToObject(r, "stdErr", "");
        rpc_server_reply_result(ctx->server, handle, r);
        cJSON_Delete(r);
        return 0;
    }

    if (strcmp(method, "exit_error") == 0) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddNumberToObject(r, "exitCode", 42);
        cJSON_AddStringToObject(r, "stdOut", "");
        cJSON_AddStringToObject(r, "stdErr", "fail\n");
        rpc_server_reply_result(ctx->server, handle, r);
        cJSON_Delete(r);
        return 0;
    }

    if (strcmp(method, "exec_true") == 0) {
        cJSON *r = cJSON_CreateObject();
        cJSON *args = cJSON_AddArrayToObject(r, "execArgs");
        cJSON_AddItemToArray(args, cJSON_CreateString("/bin/true"));
        rpc_server_reply_result(ctx->server, handle, r);
        cJSON_Delete(r);
        return 0;
    }

    if (strcmp(method, "exec_echo") == 0) {
        cJSON *r = cJSON_CreateObject();
        cJSON *args = cJSON_AddArrayToObject(r, "execArgs");
        cJSON_AddItemToArray(args, cJSON_CreateString("/bin/echo"));
        cJSON_AddItemToArray(args, cJSON_CreateString("exec_output"));
        rpc_server_reply_result(ctx->server, handle, r);
        cJSON_Delete(r);
        return 0;
    }

    if (strcmp(method, "exec_empty") == 0) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddArrayToObject(r, "execArgs");
        rpc_server_reply_result(ctx->server, handle, r);
        cJSON_Delete(r);
        return 0;
    }

    if (strcmp(method, "rpc_error") == 0) {
        rpc_server_reply_error(ctx->server, handle, 99, "mock error");
        return 0;
    }

    if (strcmp(method, "echo_params") == 0) {
        char *params_str = params ? cJSON_PrintUnformatted(params) : strdup("null");
        cJSON *r = cJSON_CreateObject();
        cJSON_AddNumberToObject(r, "exitCode", 0);
        cJSON_AddStringToObject(r, "stdOut", params_str);
        cJSON_AddStringToObject(r, "stdErr", "");
        rpc_server_reply_result(ctx->server, handle, r);
        cJSON_Delete(r);
        free(params_str);
        return 0;
    }

    /* Default */
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "exitCode", 0);
    cJSON_AddStringToObject(r, "stdOut", "ok\n");
    cJSON_AddStringToObject(r, "stdErr", "");
    rpc_server_reply_result(ctx->server, handle, r);
    cJSON_Delete(r);
    return 0;
}

static void mock_on_critical_error(const char *error_message, void *user_data)
{
    (void)user_data;
    fprintf(stderr, "Mock server critical error: %s\n", error_message);
}

static void mock_stop_handler(void *vctx)
{
    mock_server_ctx_t *ctx = vctx;
    uint64_t val;
    (void)read(ctx->stop_fd, &val, sizeof(val));
    rpc_server_free(ctx->server);
    ctx->server = NULL;
    tev_set_read_handler(ctx->tev, ctx->stop_fd, NULL, NULL);
    close(ctx->stop_fd);
    ctx->stop_fd = -1;
}

static void *mock_server_thread(void *arg)
{
    mock_server_ctx_t *ctx = arg;

    ctx->tev = tev_create_ctx();
    CHECK(ctx->tev != NULL, "mock: tev_create_ctx");

    ctx->server = rpc_server_new(ctx->tev, TEST_SOCKET_PATH,
                                 mock_on_request, mock_on_critical_error, ctx);
    CHECK(ctx->server != NULL, "mock: rpc_server_new");

    int rc = tev_set_read_handler(ctx->tev, ctx->stop_fd,
                                  mock_stop_handler, ctx);
    CHECK(rc == 0, "mock: tev_set_read_handler stop_fd");

    /* Signal ready. */
    uint64_t val = 1;
    (void)write(ctx->ready_fd, &val, sizeof(val));
    close(ctx->ready_fd);
    ctx->ready_fd = -1;

    tev_main_loop(ctx->tev);
    tev_free_ctx(ctx->tev);
    return NULL;
}

static void start_mock_server(mock_server_ctx_t *ctx, pthread_t *tid)
{
    ctx->ready_fd = eventfd(0, 0);
    CHECK(ctx->ready_fd >= 0, "eventfd ready");
    ctx->stop_fd = eventfd(0, EFD_NONBLOCK);
    CHECK(ctx->stop_fd >= 0, "eventfd stop");

    int rc = pthread_create(tid, NULL, mock_server_thread, ctx);
    CHECK(rc == 0, "pthread_create mock server");

    uint64_t val;
    (void)read(ctx->ready_fd, &val, sizeof(val));
}

static void stop_mock_server(mock_server_ctx_t *ctx, pthread_t tid)
{
    if (ctx->stop_fd >= 0) {
        uint64_t val = 1;
        (void)write(ctx->stop_fd, &val, sizeof(val));
    }
    pthread_join(tid, NULL);
}

/* -------------------------------------------------------------------------- */
/*  Subprocess helper: run the tcr client and capture output/exit code        */
/* -------------------------------------------------------------------------- */

typedef struct {
    int exit_code;
    char stdout_buf[4096];
    char stderr_buf[4096];
} client_result_t;

static void run_client(const char *const argv[], client_result_t *result)
{
    memset(result, 0, sizeof(*result));

    int stdout_pipe[2], stderr_pipe[2];
    CHECK(pipe(stdout_pipe) == 0, "pipe stdout");
    CHECK(pipe(stderr_pipe) == 0, "pipe stderr");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork");

    if (pid == 0) {
        /* Child: redirect stdout/stderr, exec the helper binary. */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        execv(argv[0], (char *const *)argv);
        _exit(127);
    }

    /* Parent: read output. */
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    ssize_t n;
    size_t total_out = 0, total_err = 0;

    while ((n = read(stdout_pipe[0], result->stdout_buf + total_out,
                     sizeof(result->stdout_buf) - total_out - 1)) > 0)
        total_out += (size_t)n;
    result->stdout_buf[total_out] = '\0';

    while ((n = read(stderr_pipe[0], result->stderr_buf + total_err,
                     sizeof(result->stderr_buf) - total_err - 1)) > 0)
        total_err += (size_t)n;
    result->stderr_buf[total_err] = '\0';

    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    int status;
    waitpid(pid, &status, 0);
    result->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* -------------------------------------------------------------------------- */
/*  Tests                                                                     */
/* -------------------------------------------------------------------------- */

static void test_no_args(void)
{
    printf("test_no_args...\n");

    const char *argv[] = { TCR_CLIENT_BIN, NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 1, "exit code should be 1");
    TEST_ASSERT(strstr(r.stderr_buf, "tcr help") != NULL,
                "stderr should mention 'tcr help'");

    printf("  done.\n");
}

static void test_exitcode_stdout(void)
{
    printf("test_exitcode_stdout...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "echo_exit", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 0, "exit code should be 0");
    TEST_ASSERT(strcmp(r.stdout_buf, "hello\n") == 0, "stdout should be 'hello\\n'");
    TEST_ASSERT(r.stderr_buf[0] == '\0', "stderr should be empty");

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

static void test_exitcode_stderr(void)
{
    printf("test_exitcode_stderr...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "exit_error", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 42, "exit code should be 42");
    TEST_ASSERT(strcmp(r.stderr_buf, "fail\n") == 0, "stderr should be 'fail\\n'");
    TEST_ASSERT(r.stdout_buf[0] == '\0', "stdout should be empty");

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

static void test_exec_args(void)
{
    printf("test_exec_args...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "exec_echo", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 0, "exit code should be 0 (from /bin/echo)");
    TEST_ASSERT(strcmp(r.stdout_buf, "exec_output\n") == 0,
                "stdout should be 'exec_output\\n' from exec'd echo");

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

static void test_exec_true(void)
{
    printf("test_exec_true...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "exec_true", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 0, "exit code should be 0 (from /bin/true)");
    TEST_ASSERT(r.stdout_buf[0] == '\0', "stdout should be empty");

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

static void test_exec_empty_args(void)
{
    printf("test_exec_empty_args...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "exec_empty", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 1, "exit code should be 1 (empty execArgs)");
    TEST_ASSERT(strstr(r.stderr_buf, "execArgs is empty") != NULL,
                "stderr should mention empty execArgs");

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

static void test_rpc_error(void)
{
    printf("test_rpc_error...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "rpc_error", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 1, "exit code should be 1");
    TEST_ASSERT(strstr(r.stderr_buf, "99") != NULL, "stderr should contain error code");
    TEST_ASSERT(strstr(r.stderr_buf, "mock error") != NULL,
                "stderr should contain error message");

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

static void test_connect_failure(void)
{
    printf("test_connect_failure...\n");

    /* No server running — client should fail to connect. */
    const char *argv[] = { TCR_CLIENT_BIN, "anything", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 1, "exit code should be 1");
    TEST_ASSERT(strstr(r.stderr_buf, "Error") != NULL ||
                strstr(r.stderr_buf, "error") != NULL ||
                strstr(r.stderr_buf, "connect") != NULL,
                "stderr should contain an error message");

    printf("  done.\n");
}

static void test_params_passed_correctly(void)
{
    printf("test_params_passed_correctly...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "echo_params", "--name", "foo", "-v", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 0, "exit code should be 0");

    /* stdout contains the JSON of the params object. Parse and validate. */
    cJSON *params = cJSON_Parse(r.stdout_buf);
    TEST_ASSERT(params != NULL, "stdout should be valid JSON");

    if (params) {
        /* Check args array */
        const cJSON *args = cJSON_GetObjectItemCaseSensitive(params, "args");
        TEST_ASSERT(cJSON_IsArray(args), "params.args should be an array");
        if (cJSON_IsArray(args)) {
            TEST_ASSERT(cJSON_GetArraySize(args) == 3, "args should have 3 elements");
            TEST_ASSERT(strcmp(cJSON_GetArrayItem(args, 0)->valuestring, "--name") == 0,
                        "args[0] should be '--name'");
            TEST_ASSERT(strcmp(cJSON_GetArrayItem(args, 1)->valuestring, "foo") == 0,
                        "args[1] should be 'foo'");
            TEST_ASSERT(strcmp(cJSON_GetArrayItem(args, 2)->valuestring, "-v") == 0,
                        "args[2] should be '-v'");
        }

        /* Check pwd exists */
        const cJSON *pwd = cJSON_GetObjectItemCaseSensitive(params, "pwd");
        TEST_ASSERT(cJSON_IsString(pwd), "params.pwd should be a string");

        /* Check pid exists and is a number */
        const cJSON *pid = cJSON_GetObjectItemCaseSensitive(params, "pid");
        TEST_ASSERT(cJSON_IsNumber(pid), "params.pid should be a number");
        if (cJSON_IsNumber(pid))
            TEST_ASSERT(pid->valuedouble > 0, "pid should be positive");

        cJSON_Delete(params);
    }

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

static void test_method_no_extra_args(void)
{
    printf("test_method_no_extra_args...\n");

    mock_server_ctx_t sctx = {0};
    pthread_t tid;
    start_mock_server(&sctx, &tid);

    const char *argv[] = { TCR_CLIENT_BIN, "echo_params", NULL };
    client_result_t r;
    run_client(argv, &r);

    TEST_ASSERT(r.exit_code == 0, "exit code should be 0");

    cJSON *params = cJSON_Parse(r.stdout_buf);
    TEST_ASSERT(params != NULL, "stdout should be valid JSON");

    if (params) {
        const cJSON *args = cJSON_GetObjectItemCaseSensitive(params, "args");
        TEST_ASSERT(cJSON_IsArray(args), "params.args should be an array");
        if (cJSON_IsArray(args))
            TEST_ASSERT(cJSON_GetArraySize(args) == 0, "args should be empty");
        cJSON_Delete(params);
    }

    stop_mock_server(&sctx, tid);
    printf("  done.\n");
}

/* -------------------------------------------------------------------------- */
/*  main                                                                      */
/* -------------------------------------------------------------------------- */

int main(void)
{
    printf("=== TCR Client Tests ===\n\n");

    test_no_args();
    test_exitcode_stdout();
    test_exitcode_stderr();
    test_exec_args();
    test_exec_true();
    test_exec_empty_args();
    test_rpc_error();
    test_connect_failure();
    test_params_passed_correctly();
    test_method_no_extra_args();

    printf("\n=== Results: %d passed, %d failed ===\n",
           test_pass_count, test_fail_count);

    return test_fail_count > 0 ? 1 : 0;
}
