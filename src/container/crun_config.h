#pragma once

#include <cjson/cJSON.h>
#include <stdbool.h>

/**
 * @brief Create a base crun config. Default to read-only rootfs and non-tty.
 * 
 * @param bundle_path OCI bundle path.
 * @return cJSON* The config object. Caller is responsible for freeing it with cJSON_Delete. NULL if failed.
 */
cJSON* crun_config_create(const char* bundle_path);

/**
 * @brief Set the read-only flag for the container's root filesystem. (Default to true)
 * 
 * @param config The crun config to modify.
 * @param readonly Whether to set the root filesystem as read-only.
 * @return int 0 on success, -1 if failed. 
 */
int crun_config_set_readonly(cJSON* config, bool readonly);

/**
 * @brief Set a new root filesystem path for the container. (Default to the bundle's rootfs)
 * 
 * @param config The crun config to modify.
 * @param rootfs_path The path to the root filesystem.
 * @return int 0 on success, -1 if failed.
 */
int crun_config_set_rootfs(cJSON* config, const char* rootfs_path);

/**
 * @brief Set the terminal mode for the container.
 * 
 * @param config The crun config to modify.
 * @param is_tty Whether to enable TTY mode.
 * @return int 0 on success, -1 if failed.
 */
int crun_config_set_terminal_mode(cJSON* config, bool is_tty);

/**
 * @brief Set the arguments for the container's process.
 * 
 * @param config The crun config to modify.
 * @param argc The number of arguments.
 * @param argv The array of argument strings.
 * @return int 0 on success, -1 if failed.
 */
int crun_config_set_args(cJSON* config, size_t argc, const char* const* argv);

/**
 * @brief Add a bind mount to the container.
 * 
 * @param config The crun config to modify.
 * @param source The source path on the host.
 * @param destination The destination path inside the container.
 * @param read_only Whether the mount should be read-only.
 * @return int 0 on success, -1 if failed.
 */
int crun_config_add_bind_mount(cJSON* config, const char* source, const char* destination, bool read_only);

/**
 * @brief Add a tmpfs mount to the container.
 * 
 * @param config The crun config to modify.
 * @param destination The destination path inside the container.
 * @param size_bytes The size of the tmpfs mount in bytes.
 * @return int 0 on success, -1 if failed.
 */
int crun_config_add_tmpfs_mount(cJSON* config, const char* destination, size_t size_bytes);

/**
 * @brief Add an environment variable to the container.
 * 
 * @param config The crun config to modify.
 * @param key The environment variable key.
 * @param value The environment variable value.
 * @return int 0 on success, -1 if failed.
 */
int crun_config_add_env(cJSON* config, const char* key, const char* value);

/**
 * @brief Set the network namespace for the container.
 * 
 * @param config The crun config to modify.
 * @param ns_path The path to the network namespace.
 * @return int 0 on success, -1 if failed.
 */
int crun_config_set_network_ns(cJSON* config, const char* ns_path);
