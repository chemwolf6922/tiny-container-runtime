#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "test_util.h"
#include "container/run_config.h"
#include "container/container_manager.h"
#include "common/utils.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_assertions = 0;

/* ── Helper: write a string to a temp file and return its path ──────────── */

static char *write_config(const char *data_dir, const char *name, const char *json)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", data_dir, name);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL, "fopen config file");
    fputs(json, f);
    fclose(f);
    return strdup(path);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Tests                                                                     */
/* ═══════════════════════════════════════════════════════════════════════════ */

static void test_minimal_config(const char *data_dir)
{
    printf("  test_minimal_config\n");

    char *path = write_config(data_dir, "minimal.json",
        "{ \"image\": \"alpine\" }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc == 0, err ? err : "parse failed");
    CHECK(err == NULL, "err should be NULL on success");

    CHECK(strcmp(container_args_get_image(args), "alpine") == 0, "image should be alpine");
    CHECK(container_args_get_detached(args) == false, "detached should default to false");
    g_assertions += 4;

    container_args_free(args);
    free(path);
}

static void test_full_config(const char *data_dir)
{
    printf("  test_full_config\n");

    char *path = write_config(data_dir, "full.json",
        "{\n"
        "  \"image\": \"nginx:1.25\",\n"
        "  \"name\": \"webserver\",\n"
        "  \"detached\": true,\n"
        "  \"terminal\": true,\n"
        "  \"readonly\": true,\n"
        "  \"autoRemove\": true,\n"
        "  \"command\": [\"/bin/sh\", \"-c\", \"echo hello\"],\n"
        "  \"env\": { \"FOO\": \"bar\", \"DEBUG\": \"1\" },\n"
        "  \"mounts\": [\n"
        "    { \"source\": \"/host/data\", \"destination\": \"/data\", \"readonly\": true },\n"
        "    { \"source\": \"/host/logs\", \"destination\": \"/logs\" }\n"
        "  ],\n"
        "  \"tmpfs\": [\n"
        "    { \"destination\": \"/tmp\", \"size\": 33554432 },\n"
        "    { \"destination\": \"/run\" }\n"
        "  ],\n"
        "  \"ports\": [\n"
        "    { \"hostPort\": 8080, \"containerPort\": 80, \"protocol\": \"tcp\" },\n"
        "    { \"hostPort\": 5353, \"containerPort\": 53, \"protocol\": \"udp\",\n"
        "      \"hostIp\": \"127.0.0.1\" }\n"
        "  ],\n"
        "  \"network\": \"my_net\",\n"
        "  \"restartPolicy\": \"unless-stopped\",\n"
        "  \"stopTimeout\": 30\n"
        "}\n");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc == 0, err ? err : "parse failed");

    CHECK(strcmp(container_args_get_image(args), "nginx:1.25") == 0, "image");
    CHECK(container_args_get_detached(args) == true, "detached");
    g_assertions += 4;

    container_args_free(args);
    free(path);
}

static void test_no_network(const char *data_dir)
{
    printf("  test_no_network\n");

    char *path = write_config(data_dir, "nonet.json",
        "{ \"image\": \"alpine\", \"noNetwork\": true }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc == 0, err ? err : "parse failed");
    g_assertions += 2;

    container_args_free(args);
    free(path);
}

static void test_network_and_nonetwork_conflict(const char *data_dir)
{
    printf("  test_network_and_nonetwork_conflict\n");

    char *path = write_config(data_dir, "conflict.json",
        "{ \"image\": \"alpine\", \"network\": \"mynet\", \"noNetwork\": true }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc != 0, "should fail with conflicting network options");
    CHECK(err != NULL, "should have error message");
    CHECK(strstr(err, "mutually exclusive") != NULL, "error should mention mutual exclusion");
    g_assertions += 4;

    free(err);
    container_args_free(args);
    free(path);
}

static void test_missing_image(const char *data_dir)
{
    printf("  test_missing_image\n");

    char *path = write_config(data_dir, "no_image.json",
        "{ \"name\": \"test\" }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc != 0, "should fail without image");
    CHECK(err != NULL, "should have error message");
    CHECK(strstr(err, "image") != NULL, "error should mention 'image'");
    g_assertions += 4;

    free(err);
    container_args_free(args);
    free(path);
}

static void test_invalid_json(const char *data_dir)
{
    printf("  test_invalid_json\n");

    char *path = write_config(data_dir, "bad.json", "{ not valid json }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc != 0, "should fail on invalid JSON");
    CHECK(err != NULL, "should have error message");
    g_assertions += 3;

    free(err);
    container_args_free(args);
    free(path);
}

static void test_nonexistent_file(void)
{
    printf("  test_nonexistent_file\n");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse("/tmp/does_not_exist_12345.json", args, &err);
    CHECK(rc != 0, "should fail on nonexistent file");
    CHECK(err != NULL, "should have error message");
    g_assertions += 3;

    free(err);
    container_args_free(args);
}

static void test_bad_type_env(const char *data_dir)
{
    printf("  test_bad_type_env\n");

    char *path = write_config(data_dir, "bad_env.json",
        "{ \"image\": \"alpine\", \"env\": [\"FOO=bar\"] }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc != 0, "should fail when env is not an object");
    CHECK(err != NULL, "should have error message");
    g_assertions += 3;

    free(err);
    container_args_free(args);
    free(path);
}

static void test_bad_restart_policy(const char *data_dir)
{
    printf("  test_bad_restart_policy\n");

    char *path = write_config(data_dir, "bad_restart.json",
        "{ \"image\": \"alpine\", \"restartPolicy\": \"invalid\" }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc != 0, "should fail with invalid restart policy");
    CHECK(err != NULL, "should have error message");
    g_assertions += 3;

    free(err);
    container_args_free(args);
    free(path);
}

static void test_bad_port_range(const char *data_dir)
{
    printf("  test_bad_port_range\n");

    char *path = write_config(data_dir, "bad_port.json",
        "{ \"image\": \"alpine\", \"ports\": [{ \"hostPort\": 99999, \"containerPort\": 80 }] }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc != 0, "should fail with out-of-range port");
    CHECK(err != NULL, "should have error message");
    g_assertions += 3;

    free(err);
    container_args_free(args);
    free(path);
}

static void test_relative_mount_path(const char *data_dir)
{
    printf("  test_relative_mount_path\n");

    /* Source is relative — should be resolved against config file's directory */
    char *path = write_config(data_dir, "rel_mount.json",
        "{ \"image\": \"alpine\", \"mounts\": "
        "[{ \"source\": \"mydata\", \"destination\": \"/data\" }] }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc == 0, err ? err : "parse failed");
    /* We can't easily inspect the resolved path from outside,
       but the parse should succeed without error. */
    g_assertions += 2;

    container_args_free(args);
    free(path);
}

static void test_empty_command(const char *data_dir)
{
    printf("  test_empty_command\n");

    char *path = write_config(data_dir, "empty_cmd.json",
        "{ \"image\": \"alpine\", \"command\": [] }");

    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new");

    char *err = NULL;
    int rc = run_config_parse(path, args, &err);
    CHECK(rc != 0, "should fail with empty command array");
    CHECK(err != NULL, "should have error message");
    g_assertions += 3;

    free(err);
    container_args_free(args);
    free(path);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/*  Main                                                                      */
/* ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Use a temp directory for test config files — no root needed */
    char test_dir[] = "/tmp/tcr_test_run_config_XXXXXX";
    CHECK(mkdtemp(test_dir) != NULL, "mkdtemp");

    printf("test_run_config:\n");

    test_minimal_config(test_dir);
    test_full_config(test_dir);
    test_no_network(test_dir);
    test_network_and_nonetwork_conflict(test_dir);
    test_missing_image(test_dir);
    test_invalid_json(test_dir);
    test_nonexistent_file();
    test_bad_type_env(test_dir);
    test_bad_restart_policy(test_dir);
    test_bad_port_range(test_dir);
    test_relative_mount_path(test_dir);
    test_empty_command(test_dir);

    printf("OK (%d assertions)\n", g_assertions);
    return 0;
}
