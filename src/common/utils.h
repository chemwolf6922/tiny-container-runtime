#pragma once

#include <cjson/cJSON.h>
#include <stddef.h>

/**
 * @brief Join two path components with '/'.
 *
 * Strips trailing slashes from @a a and leading slashes from @a b
 * before joining.
 *
 * @param a First path component.
 * @param b Second path component.
 * @return char* Newly allocated joined path. Caller must free(). NULL on allocation failure.
 */
char *path_join(const char *a, const char *b);

/**
 * @brief Load and parse a JSON file.
 *
 * Uses mmap for efficient I/O. Returns the parsed cJSON tree.
 *
 * @param path Path to the JSON file.
 * @return cJSON* Parsed JSON tree. Caller must cJSON_Delete(). NULL on failure.
 */
cJSON *load_json_file(const char *path);
