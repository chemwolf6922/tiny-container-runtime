
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "rpc/rpc_client.h"
#include "app/common.h"

#include <cjson/cJSON.h>
#include <tev/tev.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TCR_REQUEST_TIMEOUT_MS 30000

/* -------------------------------------------------------------------------- */
/*  Global state for the single request lifecycle                             */
/* -------------------------------------------------------------------------- */

static tev_handle_t g_tev;
static rpc_client   g_client;
static int          g_exit_code = 1;

/* Stored from main() so callbacks can build the request. */
static int          g_argc;
static const char **g_argv;

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

/** Build the params object: { "args": [...], "pwd": "...", "pid": N } */
static cJSON *build_params(void)
{
    cJSON *params = cJSON_CreateObject();
    if (!params) return NULL;

    /* args = argv[2:] (skip binary and method) */
    cJSON *args = cJSON_AddArrayToObject(params, "args");
    for (int i = 2; i < g_argc; i++)
        cJSON_AddItemToArray(args, cJSON_CreateString(g_argv[i]));

    /* pwd */
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)))
        cJSON_AddStringToObject(params, "pwd", cwd);

    /* pid */
    cJSON_AddNumberToObject(params, "pid", (double)getpid());

    return params;
}

/* -------------------------------------------------------------------------- */
/*  RPC callbacks                                                             */
/* -------------------------------------------------------------------------- */

static void on_result(const cJSON *result, void *user_data)
{
    (void)user_data;

    /* Format 2: execArgs — exec into the given command. */
    const cJSON *exec_args = cJSON_GetObjectItemCaseSensitive(result, "execArgs");
    if (cJSON_IsArray(exec_args)) {
        int n = cJSON_GetArraySize(exec_args);
        if (n == 0) {
            fprintf(stderr, "Error: execArgs is empty\n");
            rpc_client_close(g_client);
            g_client = NULL;
            g_exit_code = 1;
            return;
        }

        /* Build argv for execvp. */
        char **exec_argv = calloc((size_t)(n + 1), sizeof(char *));
        for (int i = 0; i < n; i++) {
            const cJSON *item = cJSON_GetArrayItem(exec_args, i);
            exec_argv[i] = cJSON_IsString(item) ? item->valuestring : "";
        }
        exec_argv[n] = NULL;

        /* Close the RPC connection before exec. */
        rpc_client_close(g_client);
        g_client = NULL;

        execvp(exec_argv[0], exec_argv);

        /* If we get here, exec failed. */
        fprintf(stderr, "Error: exec failed: %s\n", strerror(errno));
        free(exec_argv);
        g_exit_code = 1;
        return;
    }

    /* Format 1: exitCode + stdOut + stdErr */
    const cJSON *exit_code_j = cJSON_GetObjectItemCaseSensitive(result, "exitCode");
    const cJSON *std_out     = cJSON_GetObjectItemCaseSensitive(result, "stdOut");
    const cJSON *std_err     = cJSON_GetObjectItemCaseSensitive(result, "stdErr");

    if (cJSON_IsString(std_out) && std_out->valuestring[0] != '\0')
        fputs(std_out->valuestring, stdout);

    if (cJSON_IsString(std_err) && std_err->valuestring[0] != '\0')
        fputs(std_err->valuestring, stderr);

    g_exit_code = cJSON_IsNumber(exit_code_j) ? exit_code_j->valueint : 0;
    rpc_client_close(g_client);
    g_client = NULL;
}

static void on_error(int error_code, const char *error_message, void *user_data)
{
    (void)user_data;
    fprintf(stderr, "Error (%d): %s\n", error_code, error_message ? error_message : "unknown");
    rpc_client_close(g_client);
    g_client = NULL;
    g_exit_code = 1;
}

static void on_cancel(void *user_data)
{
    (void)user_data;
    fprintf(stderr, "Error: request canceled (connection lost)\n");
    g_exit_code = 1;
    g_client = NULL;  /* no longer valid, handlers already removed */
}

static void on_disconnect(void *user_data)
{
    (void)user_data;
    fprintf(stderr, "Error: disconnected from daemon\n");
    g_exit_code = 1;
    g_client = NULL;  /* no longer valid, handlers already removed */
}

static void on_connect_result(bool success, void *user_data)
{
    (void)user_data;

    if (!success) {
        fprintf(stderr, "Error: could not connect to tcr daemon\n");
        g_client = NULL;  /* already released by rpc layer */
        g_exit_code = 1;
        return;
    }

    const char *method = g_argv[1];
    cJSON *params = build_params();
    if (!params) {
        fprintf(stderr, "Error: failed to build request\n");
        rpc_client_close(g_client);
        g_client = NULL;
        g_exit_code = 1;
        return;
    }

    int rc = rpc_client_make_request_async(
        g_client, method, params,
        TCR_REQUEST_TIMEOUT_MS,
        on_result, on_error, on_cancel, NULL);

    cJSON_Delete(params);

    if (rc != 0) {
        fprintf(stderr, "Error: failed to send request\n");
        rpc_client_close(g_client);
        g_client = NULL;
        g_exit_code = 1;
    }
}

/* -------------------------------------------------------------------------- */
/*  main                                                                      */
/* -------------------------------------------------------------------------- */

int main(int argc, const char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: tcr <command> [args...]\n");
        fprintf(stderr, "Run 'tcr help' for more information.\n");
        return 1;
    }

    g_argc = argc;
    g_argv = argv;

    g_tev = tev_create_ctx();
    if (!g_tev) {
        fprintf(stderr, "Error: failed to initialize event loop\n");
        return 1;
    }

    g_client = rpc_client_open_async(
        g_tev, TCR_SOCKET_PATH,
        on_connect_result, on_disconnect, NULL);

    if (!g_client) {
        fprintf(stderr, "Error: could not connect to tcr daemon\n");
        tev_free_ctx(g_tev);
        return 1;
    }

    tev_main_loop(g_tev);

    tev_free_ctx(g_tev);
    return g_exit_code;
}
