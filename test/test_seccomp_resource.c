/**
 * @file test_seccomp_resource.c
 * @brief Test that the embedded seccomp.json can be parsed by cJSON.
 */
#include "seccomp_json.h"
#include "test_util.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <string.h>

static void test_embedded_json_not_empty(void)
{
    printf("  test_embedded_json_not_empty... ");
    CHECK(SECCOMP_JSON_DATA != NULL, "embedded JSON data is NULL");
    CHECK(SECCOMP_JSON_LEN > 0, "embedded JSON length is 0");
    printf("OK (len=%zu)\n", SECCOMP_JSON_LEN);
}

static void test_parse_json(void)
{
    printf("  test_parse_json... ");

    cJSON *root = cJSON_ParseWithLength(SECCOMP_JSON_DATA, SECCOMP_JSON_LEN);
    CHECK(root != NULL, "cJSON_Parse failed");

    /* Validate expected top-level keys */
    cJSON *defaultAction = cJSON_GetObjectItem(root, "defaultAction");
    CHECK(defaultAction != NULL, "missing 'defaultAction'");
    CHECK(cJSON_IsString(defaultAction), "'defaultAction' is not a string");
    CHECK(strcmp(defaultAction->valuestring, "SCMP_ACT_ERRNO") == 0,
          "unexpected defaultAction value");

    cJSON *syscalls = cJSON_GetObjectItem(root, "syscalls");
    CHECK(syscalls != NULL, "missing 'syscalls'");
    CHECK(cJSON_IsArray(syscalls), "'syscalls' is not an array");
    CHECK(cJSON_GetArraySize(syscalls) > 0, "'syscalls' array is empty");

    cJSON_Delete(root);
    printf("OK\n");
}

int main(void)
{
    printf("test_seccomp_resource:\n");
    test_embedded_json_not_empty();
    test_parse_json();
    printf("All tests passed.\n");
    return 0;
}
