#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <tev/tev.h>

#include "image/image_manager.h"
#include "network/nat_network_manager.h"
#include "network/port_forwarder.h"

typedef enum
{
    CONTAINER_RESTART_POLICY_NEVER,
    CONTAINER_RESTART_POLICY_UNLESS_STOPPED,
    CONTAINER_RESTART_POLICY_ALWAYS,
} container_restart_policy;

typedef struct container_manager_s* container_manager;

/**
 * @brief Create a new container manager.
 * 
 * @param img_manager The image manager to use.
 * @param root_path The root path for container storage.
 * @return container_manager The newly created container manager. NULL if failed.ß
 */
container_manager container_manager_new(
    tev_handle_t tev,
    image_manager img_manager,
    nat_network_manager nat_manager,
    const char* root_path);

/**
 * @brief Free the container manager and all associated resources.
 * This will stop all running containers and close the liveness pipe.
 * 
 * @param manager The container manager to free.
 */
void container_manager_free(container_manager manager);

/**
 * @brief Get the reference count of the image in the container manager.
 * 
 * @param manager The container manager to query.
 * @param img The image to query the reference count for.
 * @return int The reference count of the image.
 */
int container_manager_get_image_ref_count(container_manager manager, image img);

typedef struct container_args_s* container_args;

/**
 * @brief Create new container arguments with default values.
 * 
 * @return container_args The newly created container arguments. NULL if failed.
 */
container_args container_args_new();

/**
 * @brief Free container arguments.
 * 
 * @param args The container arguments to free. NULL is safe.
 */
void container_args_free(container_args args);

/**
 * @brief Set the container name. If not set, will use the id as the name.
 * 
 * @param args The container arguments to modify.
 * @param name The name to set for the container.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_name(container_args args, const char* name);

/**
 * @brief Set the target image digest. Cannot coexist with image name+tag.
 * 
 * @param args The container arguments to modify.
 * @param digest The digest of the image to use.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_image_by_digest(container_args args, const char* digest);

/**
 * @brief Set the target image by name and tag. Cannot coexist with image digest.
 * 
 * @param args The container arguments to modify.
 * @param name The name of the image.
 * @param tag The tag of the image.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_image_by_name(container_args args, const char* name, const char* tag);

/**
 * @brief Set the container to read-only mode.
 * 
 * @param args The container arguments to modify.
 * @param readonly Whether the container should be read-only.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_readonly(container_args args, bool readonly);

/**
 * @brief Set the container to terminal mode.
 * 
 * @param args The container arguments to modify.
 * @param is_tty Whether the container should be in terminal mode.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_terminal_mode(container_args args, bool is_tty);

/**
 * @brief Add a bind mount to the container.
 * 
 * @param args The container arguments to modify.
 * @param source The source path of the bind mount.
 * @param destination The destination path inside the container.
 * @param read_only Whether the bind mount should be read-only.
 * @return int 0 on success, -1 if failed.
 */
int container_args_add_bind_mount(
    container_args args, const char* source, const char* destination, bool read_only);

/**
 * @brief Add a tmpfs mount to the container.
 * 
 * @param args The container arguments to modify.
 * @param destination The destination path inside the container.
 * @param size_bytes The size of the tmpfs mount in bytes.
 * @return int 0 on success, -1 if failed.
 */
int container_args_add_tmpfs_mount(
    container_args args, const char* destination, size_t size_bytes);

/**
 * @brief Add an environment variable to the container.
 * 
 * @param args The container arguments to modify.
 * @param key The environment variable key.
 * @param value The environment variable value.
 * @return int 0 on success, -1 if failed.
 */
int container_args_add_env(container_args args, const char* key, const char* value);

/**
 * @brief Set the restart policy for the container. Default to never.
 * 
 * @param args The container arguments to modify.
 * @param policy The restart policy to set.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_restart_policy(container_args args, container_restart_policy policy);

/**
 * @brief Set the stop timeout for the container. Default to 10s.
 * 
 * @param args The container arguments to modify.
 * @param timeout_ms The stop timeout in milliseconds.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_stop_timeout(container_args args, int timeout_ms);

/**
 * @brief Set whether to automatically remove the container after it exits. Default to false.
 * 
 * @param args The container arguments to modify.
 * @param auto_remove Whether to automatically remove the container after it exits.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_auto_remove(container_args args, bool auto_remove);

/**
 * @brief Set whether the container should run in detached mode. Default to false.
 * 
 * @param args The container arguments to modify.
 * @param detached Whether the container should run in detached mode.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_detached(container_args args, bool detached);

/**
 * @brief Set the command to run in the container. Overrides the image's default entrypoint/cmd.
 * 
 * @param args The container arguments to modify.
 * @param argc The number of arguments.
 * @param argv The argument strings (copied).
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_command(container_args args, size_t argc, const char* const* argv);

/**
 * @brief Set the NAT network to use. Default to no network.
 * 
 * @param args The container arguments to modify.
 * @param nat_network_name The name of the NAT network to use. Will use the default if NULL.
 * @return int 0 on success, -1 if failed.
 */
int container_args_set_nat_network(container_args args, const char* nat_network_name);

/**
 * @brief Add a port forwarding rule to the container.
 * 
 * @param args The container arguments to modify.
 * @param host_ip The host IP address to bind the port on.
 * @param host_port The host port to bind.
 * @param container_port The container port to forward to.
 * @param protocol The protocol bitmap (PORT_FORWARD_PROTOCOL_TCP/UDP).
 * @return int 0 on success, -1 if failed.
 */
int container_args_add_port_forwarding(
    container_args args,
    struct in_addr host_ip, uint16_t host_port,
    uint16_t container_port,
    int protocol);

typedef struct container_s* container;

/**
 * @brief Create the container (w/o starting) with the given arguments.
 * 
 * @param manager The container manager to use for creating the container.
 * @param args The container arguments to use for creating the container.
 * @return container The created container, or NULL if creation failed.
 */
container container_manager_create_container(
    container_manager manager,
    container_args args);

/**
 * @brief Find a container by its name or id.
 * 
 * @param manager The container manager to search in.
 * @param name_or_id The name or ID of the container to find.
 * @return container The found container, or NULL if not found.
 */
container container_manager_find_container(
    container_manager manager,
    const char* name_or_id);

/**
 * @brief Iterate over all containers in the manager and call the given function on each container.
 * 
 * @param manager The container manager to iterate over.
 * @param fn The function to call for each container. 
 * @param user_data User data to pass to the function.
 * @return int 0 on success, -1 if failed.
 */
int container_manager_foreach_container_safe(
    container_manager manager,
    void (*fn)(container c, void* user_data),
    void* user_data);

/**
 * @brief Stop the container if running.
 * @note If immediate is not set, the container will be given some time to stop gracefully before being forcefully killed.
 * 
 * @param c The container to stop.
 * @param immediately Whether to stop the container immediately.
 * @return int 0 on success, -1 if failed.
 */
int container_stop(container c, bool immediately);

/**
 * @brief Remove the container with all resources. The container should not be referenced afterwards.
 * @warning This will forcefully stop the container immediately if it's still running.
 * 
 * @param c The container to remove.
 * @return int 0 on success, -1 if failed.
 */
int container_remove(container c);

/**
 * @brief Get the ID of the container.
 * 
 * @param c The container to get the ID from.
 * @return const char* The ID of the container. Lives with the container.
 */
const char* container_get_id(container c);

/**
 * @brief Get the name of the container.
 * 
 * @param c The container to get the name from.
 * @return const char* The name of the container. Lives with the container.
 */
const char* container_get_name(container c);

/**
 * @brief Check if the container is running.
 * 
 * @param c The container to check.
 * @return true If the container is running.
 * @return false If the container is not running.
 */
bool container_is_running(container c);

/**
 * @brief Check if the container is in detached mode.
 * 
 * @param c The container to check.
 * @return true If the container is in detached mode.
 * @return false If the container is not in detached mode.
 */
bool container_is_detached(container c);

/** Detached mode: Run in the background and manage the container lifecycle.
 *
 * The daemon fork+exec's `crun run`. The child process calls
 * prctl(PR_SET_PDEATHSIG, SIGKILL) before exec, so if the daemon dies
 * (even from SIGKILL), the container process is killed immediately by
 * the kernel. No orphaned containers.
 */

/**
 * @brief Start a detached container. The container should have been created with detached mode enabled.
 * 
 * @param c The container to start.
 * @return int 0 on success, -1 if failed. If restart policy is not never, this will return 0 on failure and retry asynchronously.
 */
int container_start(container c);

/** Interactive mode: Run directly on client side and monitor the client pid.
 *
 * @note Crash safety is NOT handled for interactive containers. If the daemon
 * crashes while an interactive container is running, the crun process will
 * keep running unmanaged until it exits on its own. The overlay (if any)
 * will not be cleaned up until the daemon restarts.
 */

/**
 * @brief Get the exact crun command to run this container.
 * @warning This only works for container that's not running. And has the restart policy set to never.
 * 
 * @param c The container to get the crun command for.
 * @param out_argv The output argument vector for the crun command.
 * @param out_argc The output argument count for the crun command.
 * @return int 0 on success, -1 if failed.
 */
int container_get_crun_args(container c, char*** out_argv, size_t* out_argc);

/**
 * @brief Free the argv returned by container_get_crun_args.
 * 
 * @param argv The argument vector to free.
 * @param argc The argument count.
 */
void container_free_crun_args(char** argv, size_t argc);

/**
 * @brief Associate the process with the container. And cleanup the container status based on the settings.
 * 
 * @param c The container to monitor the process for.
 * @param pid The process ID to associate with the container.
 * @return int 0 on success, -1 if failed.
 */
int container_monitor_process(container c, int pid);
