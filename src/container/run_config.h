#pragma once

#include "container/container_manager.h"

/**
 * @brief Parse a JSON config file and populate container_args.
 *
 * Reads the file at @a config_path, parses the JSON according to the
 * run-config-schema, and fills all fields in the pre-allocated @a args.
 *
 * Relative paths in bind-mount sources are resolved against the directory
 * containing the config file (not the client's pwd).
 *
 * @param config_path  Absolute path to the JSON config file.
 * @param args         Pre-allocated container_args to populate.
 * @param[out] err_msg On failure, set to a malloc'd human-readable error
 *                     string.  Caller must free().  Set to NULL on success.
 * @return 0 on success, -1 on failure.
 */
int run_config_parse(const char *config_path, container_args args, char **err_msg);
