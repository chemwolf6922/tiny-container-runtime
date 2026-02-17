#include "test_util.h"
#include "crun_config.h"
#include "image_manager.h"
#include "resource/seccomp_json.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/*  Global test state — set up by main()                                       */
/* -------------------------------------------------------------------------- */

static const char *g_bundle_path; /* points into the mounted image */

/* -------------------------------------------------------------------------- */
/*  Tests                                                                      */
/* -------------------------------------------------------------------------- */

static void test_create_basic(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    /* Verify readonly is true (default) */
    cJSON *root = cJSON_GetObjectItemCaseSensitive(config, "root");
    CHECK(root != NULL, "root missing");
    cJSON *ro = cJSON_GetObjectItemCaseSensitive(root, "readonly");
    CHECK(cJSON_IsTrue(ro), "root.readonly should default to true");

    /* Verify terminal is false (default) */
    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    CHECK(process != NULL, "process missing");
    cJSON *term = cJSON_GetObjectItemCaseSensitive(process, "terminal");
    CHECK(cJSON_IsFalse(term), "process.terminal should default to false");

    /* Verify capabilities exist with all 5 sets */
    cJSON *caps = cJSON_GetObjectItemCaseSensitive(process, "capabilities");
    CHECK(caps != NULL, "capabilities missing");
    CHECK(cJSON_GetObjectItemCaseSensitive(caps, "bounding") != NULL, "bounding missing");
    CHECK(cJSON_GetObjectItemCaseSensitive(caps, "effective") != NULL, "effective missing");
    CHECK(cJSON_GetObjectItemCaseSensitive(caps, "inheritable") != NULL, "inheritable missing");
    CHECK(cJSON_GetObjectItemCaseSensitive(caps, "permitted") != NULL, "permitted missing");
    CHECK(cJSON_GetObjectItemCaseSensitive(caps, "ambient") != NULL, "ambient missing");

    /* Each set should have 14 caps */
    cJSON *bounding = cJSON_GetObjectItemCaseSensitive(caps, "bounding");
    CHECK(cJSON_GetArraySize(bounding) == 14, "expected 14 caps in bounding");

    /* Verify namespaces */
    cJSON *linux_obj = cJSON_GetObjectItemCaseSensitive(config, "linux");
    CHECK(linux_obj != NULL, "linux missing");
    cJSON *ns = cJSON_GetObjectItemCaseSensitive(linux_obj, "namespaces");
    CHECK(ns != NULL, "namespaces missing");
    CHECK(cJSON_GetArraySize(ns) == 5, "expected 5 namespaces");

    /* Verify seccomp */
    cJSON *seccomp = cJSON_GetObjectItemCaseSensitive(linux_obj, "seccomp");
    CHECK(seccomp != NULL, "seccomp missing");
    cJSON *default_action = cJSON_GetObjectItemCaseSensitive(seccomp, "defaultAction");
    CHECK(cJSON_IsString(default_action), "defaultAction should be string");
    CHECK(strcmp(default_action->valuestring, "SCMP_ACT_ERRNO") == 0, "wrong defaultAction");

    cJSON *architectures = cJSON_GetObjectItemCaseSensitive(seccomp, "architectures");
    CHECK(cJSON_IsArray(architectures), "architectures should be array");
    CHECK(cJSON_GetArraySize(architectures) > 0, "architectures should not be empty");

    cJSON *syscalls = cJSON_GetObjectItemCaseSensitive(seccomp, "syscalls");
    CHECK(cJSON_IsArray(syscalls), "syscalls should be array");
    CHECK(cJSON_GetArraySize(syscalls) > 0, "syscalls should not be empty");

    /* Verify default mounts exist */
    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(config, "mounts");
    CHECK(mounts != NULL, "mounts missing");
    CHECK(cJSON_GetArraySize(mounts) >= 6, "expected at least 6 default mounts");

    cJSON_Delete(config);
    printf("  PASS: test_create_basic\n");
}

static void test_set_readonly(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    /* Set to false */
    CHECK(crun_config_set_readonly(config, false) == 0, "set_readonly failed");
    cJSON *root = cJSON_GetObjectItemCaseSensitive(config, "root");
    cJSON *ro = cJSON_GetObjectItemCaseSensitive(root, "readonly");
    CHECK(cJSON_IsFalse(ro), "readonly should be false");

    /* Set back to true */
    CHECK(crun_config_set_readonly(config, true) == 0, "set_readonly failed");
    ro = cJSON_GetObjectItemCaseSensitive(root, "readonly");
    CHECK(cJSON_IsTrue(ro), "readonly should be true");

    cJSON_Delete(config);
    printf("  PASS: test_set_readonly\n");
}

static void test_set_rootfs(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    CHECK(crun_config_set_rootfs(config, "/custom/rootfs") == 0, "set_rootfs failed");
    cJSON *root = cJSON_GetObjectItemCaseSensitive(config, "root");
    cJSON *path = cJSON_GetObjectItemCaseSensitive(root, "path");
    CHECK(cJSON_IsString(path), "path should be string");
    CHECK(strcmp(path->valuestring, "/custom/rootfs") == 0, "wrong rootfs path");

    cJSON_Delete(config);
    printf("  PASS: test_set_rootfs\n");
}

static void test_set_terminal_mode(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    CHECK(crun_config_set_terminal_mode(config, true) == 0, "set_terminal_mode failed");
    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    cJSON *term = cJSON_GetObjectItemCaseSensitive(process, "terminal");
    CHECK(cJSON_IsTrue(term), "terminal should be true");

    cJSON_Delete(config);
    printf("  PASS: test_set_terminal_mode\n");
}

static void test_set_args(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    const char *argv[] = { "/usr/bin/echo", "hello", "world" };
    CHECK(crun_config_set_args(config, 3, argv) == 0, "set_args failed");

    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    cJSON *args = cJSON_GetObjectItemCaseSensitive(process, "args");
    CHECK(cJSON_GetArraySize(args) == 3, "expected 3 args");
    CHECK(strcmp(cJSON_GetArrayItem(args, 0)->valuestring, "/usr/bin/echo") == 0, "wrong arg[0]");
    CHECK(strcmp(cJSON_GetArrayItem(args, 1)->valuestring, "hello") == 0, "wrong arg[1]");
    CHECK(strcmp(cJSON_GetArrayItem(args, 2)->valuestring, "world") == 0, "wrong arg[2]");

    cJSON_Delete(config);
    printf("  PASS: test_set_args\n");
}

static void test_add_bind_mount(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    int initial_mounts = cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(config, "mounts"));

    /* Read-write bind mount */
    CHECK(crun_config_add_bind_mount(config, "/host/data", "/mnt/data", false) == 0, "add_bind_mount rw failed");
    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(config, "mounts");
    CHECK(cJSON_GetArraySize(mounts) == initial_mounts + 1, "mount count wrong");

    cJSON *last = cJSON_GetArrayItem(mounts, cJSON_GetArraySize(mounts) - 1);
    cJSON *dst = cJSON_GetObjectItemCaseSensitive(last, "destination");
    CHECK(strcmp(dst->valuestring, "/mnt/data") == 0, "wrong destination");
    cJSON *type = cJSON_GetObjectItemCaseSensitive(last, "type");
    CHECK(strcmp(type->valuestring, "bind") == 0, "wrong type");
    cJSON *opts = cJSON_GetObjectItemCaseSensitive(last, "options");
    CHECK(cJSON_GetArraySize(opts) == 1, "rw bind should have 1 option");
    CHECK(strcmp(cJSON_GetArrayItem(opts, 0)->valuestring, "bind") == 0, "missing bind option");

    /* Read-only bind mount */
    CHECK(crun_config_add_bind_mount(config, "/host/config", "/etc/app", true) == 0, "add_bind_mount ro failed");
    last = cJSON_GetArrayItem(mounts, cJSON_GetArraySize(mounts) - 1);
    opts = cJSON_GetObjectItemCaseSensitive(last, "options");
    CHECK(cJSON_GetArraySize(opts) == 2, "ro bind should have 2 options");
    CHECK(strcmp(cJSON_GetArrayItem(opts, 1)->valuestring, "ro") == 0, "missing ro option");

    cJSON_Delete(config);
    printf("  PASS: test_add_bind_mount\n");
}

static void test_add_tmpfs_mount(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    /* 64 MiB tmpfs */
    size_t size = 64 * 1024 * 1024;
    CHECK(crun_config_add_tmpfs_mount(config, "/tmp", size) == 0, "add_tmpfs_mount failed");

    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(config, "mounts");
    cJSON *last = cJSON_GetArrayItem(mounts, cJSON_GetArraySize(mounts) - 1);
    cJSON *dst = cJSON_GetObjectItemCaseSensitive(last, "destination");
    CHECK(strcmp(dst->valuestring, "/tmp") == 0, "wrong destination");
    cJSON *type = cJSON_GetObjectItemCaseSensitive(last, "type");
    CHECK(strcmp(type->valuestring, "tmpfs") == 0, "wrong type");

    cJSON *opts = cJSON_GetObjectItemCaseSensitive(last, "options");
    CHECK(cJSON_GetArraySize(opts) == 4, "expected 4 tmpfs options");
    CHECK(strcmp(cJSON_GetArrayItem(opts, 0)->valuestring, "nosuid") == 0, "missing nosuid");
    CHECK(strcmp(cJSON_GetArrayItem(opts, 1)->valuestring, "nodev") == 0, "missing nodev");
    CHECK(strcmp(cJSON_GetArrayItem(opts, 2)->valuestring, "mode=1777") == 0, "missing mode");

    /* Verify size option contains the byte count */
    char expected_size[64];
    snprintf(expected_size, sizeof(expected_size), "size=%zu", size);
    CHECK(strcmp(cJSON_GetArrayItem(opts, 3)->valuestring, expected_size) == 0, "wrong size option");

    cJSON_Delete(config);
    printf("  PASS: test_add_tmpfs_mount\n");
}

static void test_add_env(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    CHECK(crun_config_add_env(config, "MY_VAR", "my_value") == 0, "add_env failed");

    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    cJSON *env = cJSON_GetObjectItemCaseSensitive(process, "env");
    CHECK(env != NULL, "env missing");

    /* Find our entry — it may not be the first since the image has its own env */
    bool found = false;
    const cJSON *item;
    cJSON_ArrayForEach(item, env) {
        if (cJSON_IsString(item) && strcmp(item->valuestring, "MY_VAR=my_value") == 0) {
            found = true;
            break;
        }
    }
    CHECK(found, "MY_VAR=my_value not found in env");

    cJSON_Delete(config);
    printf("  PASS: test_add_env\n");
}

static void test_set_network_ns(void)
{
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    const char *ns_path = "/var/run/netns/tcr-mycontainer";
    CHECK(crun_config_set_network_ns(config, ns_path) == 0, "set_network_ns failed");

    cJSON *linux_obj = cJSON_GetObjectItemCaseSensitive(config, "linux");
    cJSON *namespaces = cJSON_GetObjectItemCaseSensitive(linux_obj, "namespaces");

    /* Find the network namespace and verify path */
    bool found = false;
    const cJSON *ns;
    cJSON_ArrayForEach(ns, namespaces) {
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(ns, "type");
        if (cJSON_IsString(type) && strcmp(type->valuestring, "network") == 0) {
            const cJSON *path = cJSON_GetObjectItemCaseSensitive(ns, "path");
            CHECK(cJSON_IsString(path), "network ns should have path");
            CHECK(strcmp(path->valuestring, ns_path) == 0, "wrong network ns path");
            found = true;
            break;
        }
    }
    CHECK(found, "network namespace not found");

    cJSON_Delete(config);
    printf("  PASS: test_set_network_ns\n");
}

static void test_null_args(void)
{
    /* All functions should handle NULL gracefully */
    CHECK(crun_config_create(NULL) == NULL, "create(NULL) should return NULL");
    CHECK(crun_config_set_readonly(NULL, true) == -1, "set_readonly(NULL) should fail");
    CHECK(crun_config_set_rootfs(NULL, "/x") == -1, "set_rootfs(NULL) should fail");
    CHECK(crun_config_set_terminal_mode(NULL, true) == -1, "set_terminal_mode(NULL) should fail");
    CHECK(crun_config_set_args(NULL, 0, NULL) == -1, "set_args(NULL) should fail");
    CHECK(crun_config_add_bind_mount(NULL, "/a", "/b", false) == -1, "add_bind_mount(NULL) should fail");
    CHECK(crun_config_add_tmpfs_mount(NULL, "/tmp", 1024) == -1, "add_tmpfs_mount(NULL) should fail");
    CHECK(crun_config_add_env(NULL, "K", "V") == -1, "add_env(NULL) should fail");
    CHECK(crun_config_set_network_ns(NULL, "/x") == -1, "set_network_ns(NULL) should fail");

    printf("  PASS: test_null_args\n");
}

static void test_seccomp_no_conditional(void)
{
    /* Verify that conditional syscall entries (with includes/excludes) are stripped */
    cJSON *config = crun_config_create(g_bundle_path);
    CHECK(config != NULL, "crun_config_create returned NULL");

    cJSON *linux_obj = cJSON_GetObjectItemCaseSensitive(config, "linux");
    cJSON *seccomp = cJSON_GetObjectItemCaseSensitive(linux_obj, "seccomp");
    cJSON *syscalls = cJSON_GetObjectItemCaseSensitive(seccomp, "syscalls");

    /* No entry should have includes or excludes fields */
    const cJSON *sc;
    cJSON_ArrayForEach(sc, syscalls) {
        const cJSON *includes = cJSON_GetObjectItemCaseSensitive(sc, "includes");
        CHECK(includes == NULL, "converted syscall should not have includes");
        const cJSON *excludes = cJSON_GetObjectItemCaseSensitive(sc, "excludes");
        CHECK(excludes == NULL, "converted syscall should not have excludes");
        const cJSON *comment = cJSON_GetObjectItemCaseSensitive(sc, "comment");
        CHECK(comment == NULL, "converted syscall should not have comment");
    }

    cJSON_Delete(config);
    printf("  PASS: test_seccomp_no_conditional\n");
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                       */
/* -------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <sqfs-file>\n", argv[0]);
        return 1;
    }
    const char *sqfs_path = argv[1];

    printf("=== crun_config tests ===\n");
    printf("    image: %s\n", sqfs_path);

    /* --- Load and mount the image via image_manager --- */
    char data_dir[256];
    test_get_data_dir(data_dir, sizeof(data_dir), argv[0]);
    char img_root_path[512];
    snprintf(img_root_path, sizeof(img_root_path), "%s/tcr-test-crun-config", data_dir);
    image_manager mgr = image_manager_new(img_root_path);
    CHECK(mgr != NULL, "image_manager_new failed");

    image img = image_manager_load(mgr, sqfs_path);
    CHECK(img != NULL, "image_manager_load failed");
    CHECK(image_get_mounted(img), "image should be mounted after load");

    g_bundle_path = image_get_bundle_path(img);
    CHECK(g_bundle_path != NULL, "bundle path should not be NULL");
    printf("    bundle: %s\n\n", g_bundle_path);

    /* --- Run tests --- */
    test_create_basic();
    test_set_readonly();
    test_set_rootfs();
    test_set_terminal_mode();
    test_set_args();
    test_add_bind_mount();
    test_add_tmpfs_mount();
    test_add_env();
    test_set_network_ns();
    test_null_args();
    test_seccomp_no_conditional();

    /* --- Cleanup --- */
    image_manager_free(mgr, true);

    printf("\n=== All crun_config tests passed ===\n");
    return 0;
}
