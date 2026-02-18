#pragma once

/**
 * @brief A minimal JSON RPC client tailored for the needs of this project.
 * The main differences:
 * 1. No version field in the request/response.
 */

#include <stdint.h>
#include <cjson/cJSON.h>
#include <tev/tev.h>

typedef struct rpc_client_s* rpc_client;

/**
 * @brief Open a connection to the RPC server asynchronously.
 * 
 * @param tev event loop handle
 * @param socket_path UDS path. Set the first byte to '@' for abstract namespace.
 * @param on_connect_result callback for the async connection result.
 * @param on_disconnect callback for unexpected disconnection. This will not be called if the client calls close.
 *                     The rpc_client is not longer valid inside and after this callback.
 * @param user_data user data to be passed to the callbacks.
 * @return rpc_client , or NULL on synchronous failure.
 */
rpc_client rpc_client_open_async(
    tev_handle_t tev, const char* socket_path,
    void(*on_connect_result)(bool success, void* user_data),
    void(*on_disconnect)(void* user_data),
    void* user_data);

/**
 * @brief Close the RPC client connection.
 * 
 * @param client The RPC client to close.
 */
void rpc_client_close(rpc_client client);

/**
 * @brief Make an asynchronous RPC request.
 * 
 * @param client The RPC client to use for the request.
 * @param method The RPC method name.
 * @param params The RPC parameters as a cJSON object.
 * @param timeout_ms Timeout fot the request. Set to 0 for no timeout.
 * @param on_result Callback for the async request result.
 * @param on_error Callback for the async request error.
 * @param on_cancel Callback when the request is canceled due to connection issue. (Timeout is an error, not a cancel.)
 *                  The rpc_client should not be used inside and after this callback.
 * @param user_data User data to be passed to the callbacks.
 * @return int 0 on synchronous success (request sent), or -1 on synchronous failure.
 */
int rpc_client_make_request_async(
    rpc_client client,
    const char* method, const cJSON* params, uint64_t timeout_ms,
    void(*on_result)(const cJSON* result, void* user_data),
    void(*on_error)(int error_code, const char* error_message, void* user_data),
    void(*on_cancel)(void* user_data),
    void* user_data);
