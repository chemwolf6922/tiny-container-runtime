#pragma once

/**
 * @brief A minimal JSON RPC server tailored for the needs of this project.
 * The main differences:
 * 1. No version field in the request/response.
 */

#include <cjson/cJSON.h>
#include <tev/tev.h>

typedef struct rpc_server_s* rpc_server;

typedef uint64_t rpc_request_handle;

/**
 * @brief Create a new RPC server.
 * 
 * @param tev Event loop handle.
 * @param socket_path UDS path. Set the first byte to '@' for abstract namespace.
 * @param on_request Callback for incoming RPC requests. Return 0 on synchronous success, or -1 on synchronous failure.
 * @param on_critical_error Callback for critical errors. The server is no longer valid inside and after this callback.
 * @param user_data User data to be passed to the callbacks.
 * @return rpc_server , or NULL on synchronous failure.
 */
rpc_server rpc_server_new(
    tev_handle_t tev, const char* socket_path,
    int(*on_request)(rpc_request_handle handle, const char* method, const cJSON* params, void* user_data),
    void(*on_critical_error)(const char* error_message, void* user_data),
    void* user_data);

/**
 * @brief Free the RPC server.
 * 
 * @param server The RPC server to free.
 */
void rpc_server_free(rpc_server server);

/**
 * @brief Reply to an RPC request with a result.
 * 
 * @param server The RPC server handling the request.
 * @param handle The handle of the RPC request.
 * @param result The result of the RPC request as a cJSON object.
 * @return int 0 on synchronous success, or -1 on synchronous failure.
 */
int rpc_server_reply_result(rpc_server server, rpc_request_handle handle, const cJSON* result);

/**
 * @brief Reply to an RPC request with an error.
 * 
 * @param server The RPC server handling the request.
 * @param handle The handle of the RPC request.
 * @param error_code The error code of the RPC request.
 * @param error_message The error message of the RPC request.
 * @return int 0 on synchronous success, or -1 on synchronous failure.
 */
int rpc_server_reply_error(rpc_server server, rpc_request_handle handle, int error_code, const char* error_message);
