#include "test_util.h"
#include "container/container_manager.h"
#include "image/image_manager.h"
#include "network/nat_network_manager.h"

#include <cjson/cJSON.h>
#include <tev/tev.h>

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Global test state                                                          */
/* -------------------------------------------------------------------------- */

static tev_handle_t g_tev;
static image_manager g_img_mgr;
static nat_network_manager g_nat_mgr;
static const char *g_sqfs_path;

#define CM_ROOT "/tmp/tcr-test-container-manager"
#define IMG_ROOT "/tmp/tcr-test-cm-images"
#define NAT_ROOT "/tmp/tcr-test-cm-nat"

/* -------------------------------------------------------------------------- */
/*  Helper: verify file exists                                                 */
/* -------------------------------------------------------------------------- */

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* -------------------------------------------------------------------------- */
/*  Tests: container_args builder                                               */
/* -------------------------------------------------------------------------- */

static void test_args_new_free(void)
{
    container_args args = container_args_new();
    CHECK(args != NULL, "container_args_new returned NULL");
    container_args_free(args);

    /* NULL is safe */
    container_args_free(NULL);

    printf("  PASS: test_args_new_free\n");
}

static void test_args_set_name(void)
{
    container_args args = container_args_new();
    CHECK(args != NULL, "new");

    CHECK(container_args_set_name(args, "mycontainer") == 0, "set_name");
    CHECK(container_args_set_name(NULL, "x") == -1, "set_name(NULL) should fail");
    CHECK(container_args_set_name(args, NULL) == -1, "set_name(_, NULL) should fail");

    container_args_free(args);
    printf("  PASS: test_args_set_name\n");
}

static void test_args_image_mutual_exclusion(void)
{
    container_args args = container_args_new();
    CHECK(args != NULL, "new");

    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set_image_by_name");
    CHECK(container_args_set_image_by_digest(args, "sha256:abc") == -1,
          "set_image_by_digest should fail when name is set");

    container_args_free(args);

    args = container_args_new();
    CHECK(args != NULL, "new");

    CHECK(container_args_set_image_by_digest(args, "sha256:abc") == 0, "set_image_by_digest");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == -1,
          "set_image_by_name should fail when digest is set");

    container_args_free(args);
    printf("  PASS: test_args_image_mutual_exclusion\n");
}

static void test_args_setters(void)
{
    container_args args = container_args_new();
    CHECK(args != NULL, "new");

    CHECK(container_args_set_readonly(args, true) == 0, "set_readonly");
    CHECK(container_args_set_terminal_mode(args, true) == 0, "set_terminal_mode");
    CHECK(container_args_set_detached(args, true) == 0, "set_detached");
    CHECK(container_args_set_auto_remove(args, true) == 0, "set_auto_remove");
    CHECK(container_args_set_stop_timeout(args, 5000) == 0, "set_stop_timeout");
    CHECK(container_args_set_restart_policy(args, CONTAINER_RESTART_POLICY_ALWAYS) == 0,
          "set_restart_policy");

    /* command */
    const char *cmd[] = { "/bin/sh", "-c", "echo hello" };
    CHECK(container_args_set_command(args, 3, cmd) == 0, "set_command");
    /* overwrite command */
    const char *cmd2[] = { "ls" };
    CHECK(container_args_set_command(args, 1, cmd2) == 0, "set_command overwrite");

    /* clear command */
    CHECK(container_args_set_command(args, 0, NULL) == 0, "set_command clear");

    /* env */
    CHECK(container_args_add_env(args, "FOO", "bar") == 0, "add_env");
    CHECK(container_args_add_env(args, "BAZ", "qux") == 0, "add_env 2");

    /* bind mount */
    CHECK(container_args_add_bind_mount(args, "/tmp", "/mnt/tmp", true) == 0, "add_bind_mount");

    /* tmpfs mount */
    CHECK(container_args_add_tmpfs_mount(args, "/tmp/test", 64 * 1024 * 1024) == 0,
          "add_tmpfs_mount");

    /* nat network */
    CHECK(container_args_set_nat_network(args, NULL) == 0, "set_nat_network default");

    /* port forwarding */
    struct in_addr any_ip;
    any_ip.s_addr = INADDR_ANY;
    CHECK(container_args_add_port_forwarding(args, any_ip, 8080, 80,
          PORT_FORWARDER_PROTOCOL_TCP) == 0, "add_port_forwarding");

    /* NULL checks */
    CHECK(container_args_set_readonly(NULL, true) == -1, "NULL args");
    CHECK(container_args_add_env(NULL, "A", "B") == -1, "NULL args env");
    CHECK(container_args_add_bind_mount(NULL, "/a", "/b", false) == -1, "NULL args bind");
    CHECK(container_args_add_tmpfs_mount(NULL, "/t", 1024) == -1, "NULL args tmpfs");

    container_args_free(args);
    printf("  PASS: test_args_setters\n");
}

/* -------------------------------------------------------------------------- */
/*  Tests: container_manager lifecycle                                          */
/* -------------------------------------------------------------------------- */

static void test_manager_new_free(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "container_manager_new returned NULL");
    container_manager_free(mgr);

    /* NULL is safe */
    container_manager_free(NULL);

    /* NULL args */
    CHECK(container_manager_new(NULL, g_img_mgr, g_nat_mgr, CM_ROOT) == NULL,
          "new(NULL tev) should fail");
    CHECK(container_manager_new(g_tev, NULL, g_nat_mgr, CM_ROOT) == NULL,
          "new(NULL img_mgr) should fail");
    CHECK(container_manager_new(g_tev, g_img_mgr, g_nat_mgr, NULL) == NULL,
          "new(NULL root) should fail");

    printf("  PASS: test_manager_new_free\n");
}

static void test_create_container_readonly(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_name(args, "test-ro") == 0, "set name");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container returned NULL");
    container_args_free(args);

    /* Verify getters */
    const char *id = container_get_id(c);
    CHECK(id != NULL, "id should not be NULL");
    CHECK(strlen(id) == 16, "id should be 16 hex chars");

    const char *name = container_get_name(c);
    CHECK(name != NULL, "name should not be NULL");
    CHECK(strcmp(name, "test-ro") == 0, "name should be test-ro");

    CHECK(!container_is_running(c), "should not be running");
    CHECK(!container_is_detached(c), "should not be detached");

    /* Find by id */
    container found = container_manager_find_container(mgr, id);
    CHECK(found == c, "find by id");

    /* Find by name */
    found = container_manager_find_container(mgr, "test-ro");
    CHECK(found == c, "find by name");

    /* Not found */
    found = container_manager_find_container(mgr, "nonexistent");
    CHECK(found == NULL, "should not find nonexistent");

    /* Config file should exist */
    char config_path[512];
    snprintf(config_path, sizeof(config_path), "%s/containers/%s/config.json", CM_ROOT, id);
    CHECK(file_exists(config_path), "config.json should exist");

    /* Verify config.json is valid JSON with expected fields */
    FILE *f = fopen(config_path, "r");
    CHECK(f != NULL, "open config.json");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    CHECK(buf != NULL, "malloc");
    CHECK(fread(buf, 1, (size_t)len, f) == (size_t)len, "fread");
    buf[len] = '\0';
    fclose(f);

    cJSON *config = cJSON_Parse(buf);
    free(buf);
    CHECK(config != NULL, "parse config.json");

    cJSON *root = cJSON_GetObjectItemCaseSensitive(config, "root");
    CHECK(root != NULL, "root");
    cJSON *ro = cJSON_GetObjectItemCaseSensitive(root, "readonly");
    CHECK(cJSON_IsTrue(ro), "readonly should be true");

    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    CHECK(process != NULL, "process");
    cJSON *term = cJSON_GetObjectItemCaseSensitive(process, "terminal");
    CHECK(cJSON_IsFalse(term), "terminal should be false");

    cJSON_Delete(config);

    /* Image ref count */
    image img = image_manager_find_by_name(g_img_mgr, "alpine", "latest");
    CHECK(img != NULL, "find image");
    CHECK(container_manager_get_image_ref_count(mgr, img) == 1, "ref count should be 1");

    /* Remove */
    CHECK(container_remove(c) == 0, "remove");
    CHECK(container_manager_get_image_ref_count(mgr, img) == 0, "ref count should be 0 after remove");
    CHECK(!file_exists(config_path), "config.json should be removed");

    container_manager_free(mgr);
    printf("  PASS: test_create_container_readonly\n");
}

static void test_create_container_rw_overlay(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, false) == 0, "set rw");
    CHECK(container_args_set_name(args, "test-rw") == 0, "set name");
    CHECK(container_args_set_detached(args, false) == 0, "set not detached");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container returned NULL");
    container_args_free(args);

    const char *id = container_get_id(c);

    /* Verify overlay dirs exist */
    char path[512];
    snprintf(path, sizeof(path), "%s/containers/%s/overlay/upper", CM_ROOT, id);
    CHECK(file_exists(path), "overlay/upper should exist");
    snprintf(path, sizeof(path), "%s/containers/%s/overlay/work", CM_ROOT, id);
    CHECK(file_exists(path), "overlay/work should exist");
    snprintf(path, sizeof(path), "%s/containers/%s/overlay/merged", CM_ROOT, id);
    CHECK(file_exists(path), "overlay/merged should exist");

    /* Verify config has writable rootfs pointing to overlay merged */
    snprintf(path, sizeof(path), "%s/containers/%s/config.json", CM_ROOT, id);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL, "open config");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    CHECK(fread(buf, 1, (size_t)len, f) == (size_t)len, "fread");
    buf[len] = '\0';
    fclose(f);

    cJSON *config = cJSON_Parse(buf);
    free(buf);
    CHECK(config != NULL, "parse config");

    cJSON *root = cJSON_GetObjectItemCaseSensitive(config, "root");
    cJSON *ro = cJSON_GetObjectItemCaseSensitive(root, "readonly");
    CHECK(cJSON_IsFalse(ro), "readonly should be false for rw container");

    cJSON *rootpath = cJSON_GetObjectItemCaseSensitive(root, "path");
    CHECK(rootpath != NULL && cJSON_IsString(rootpath), "root.path");
    CHECK(strstr(rootpath->valuestring, "overlay/merged") != NULL,
          "rootfs path should point to overlay/merged");

    cJSON_Delete(config);

    /* Remove */
    CHECK(container_remove(c) == 0, "remove");

    container_manager_free(mgr);
    printf("  PASS: test_create_container_rw_overlay\n");
}

static void test_create_container_with_options(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_terminal_mode(args, true) == 0, "set tty");
    CHECK(container_args_set_name(args, "test-opts") == 0, "set name");

    const char *cmd[] = { "/bin/echo", "hello", "world" };
    CHECK(container_args_set_command(args, 3, cmd) == 0, "set command");
    CHECK(container_args_add_env(args, "MY_VAR", "my_value") == 0, "add env");
    CHECK(container_args_add_tmpfs_mount(args, "/tmp/test", 32 * 1024 * 1024) == 0,
          "add tmpfs");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    /* Verify config */
    const char *id = container_get_id(c);
    char path[512];
    snprintf(path, sizeof(path), "%s/containers/%s/config.json", CM_ROOT, id);

    FILE *f = fopen(path, "r");
    CHECK(f != NULL, "open config");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    CHECK(fread(buf, 1, (size_t)len, f) == (size_t)len, "fread");
    buf[len] = '\0';
    fclose(f);

    cJSON *config = cJSON_Parse(buf);
    free(buf);
    CHECK(config != NULL, "parse config");

    /* Terminal mode */
    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    cJSON *term = cJSON_GetObjectItemCaseSensitive(process, "terminal");
    CHECK(cJSON_IsTrue(term), "terminal should be true");

    /* Command override */
    cJSON *pargs = cJSON_GetObjectItemCaseSensitive(process, "args");
    CHECK(pargs != NULL, "args");
    CHECK(cJSON_GetArraySize(pargs) == 3, "should have 3 args");
    CHECK(strcmp(cJSON_GetArrayItem(pargs, 0)->valuestring, "/bin/echo") == 0, "arg0");
    CHECK(strcmp(cJSON_GetArrayItem(pargs, 1)->valuestring, "hello") == 0, "arg1");
    CHECK(strcmp(cJSON_GetArrayItem(pargs, 2)->valuestring, "world") == 0, "arg2");

    /* Environment variable */
    cJSON *env = cJSON_GetObjectItemCaseSensitive(process, "env");
    CHECK(env != NULL, "env");
    bool found_var = false;
    cJSON *item;
    cJSON_ArrayForEach(item, env)
    {
        if (cJSON_IsString(item) && strcmp(item->valuestring, "MY_VAR=my_value") == 0)
            found_var = true;
    }
    CHECK(found_var, "MY_VAR=my_value should be in env");

    /* tmpfs mount */
    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(config, "mounts");
    CHECK(mounts != NULL, "mounts");
    bool found_tmpfs = false;
    cJSON *mount;
    cJSON_ArrayForEach(mount, mounts)
    {
        cJSON *dst = cJSON_GetObjectItemCaseSensitive(mount, "destination");
        if (dst && cJSON_IsString(dst) && strcmp(dst->valuestring, "/tmp/test") == 0)
            found_tmpfs = true;
    }
    CHECK(found_tmpfs, "/tmp/test tmpfs mount should exist");

    cJSON_Delete(config);
    CHECK(container_remove(c) == 0, "remove");

    container_manager_free(mgr);
    printf("  PASS: test_create_container_with_options\n");
}

static void test_create_no_image(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");

    /* No image set — should fail */
    container c = container_manager_create_container(mgr, args);
    CHECK(c == NULL, "create without image should fail");
    container_args_free(args);

    /* Nonexistent image */
    args = container_args_new();
    CHECK(container_args_set_image_by_name(args, "nonexistent", "v999") == 0, "set bad image");
    c = container_manager_create_container(mgr, args);
    CHECK(c == NULL, "create with nonexistent image should fail");
    container_args_free(args);

    container_manager_free(mgr);
    printf("  PASS: test_create_no_image\n");
}

static void count_cb(container c, void *ud)
{
    (void)c;
    (*(int *)ud)++;
}

static void test_multiple_containers(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    /* Create 3 containers */
    container containers[3];
    char names[3][32];
    for (int i = 0; i < 3; i++)
    {
        container_args args = container_args_new();
        CHECK(args != NULL, "args_new");
        CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
        CHECK(container_args_set_readonly(args, true) == 0, "set ro");
        snprintf(names[i], sizeof(names[i]), "multi-%d", i);
        CHECK(container_args_set_name(args, names[i]) == 0, "set name");

        containers[i] = container_manager_create_container(mgr, args);
        CHECK(containers[i] != NULL, "create_container");
        container_args_free(args);
    }

    /* Image ref count should be 3 */
    image img = image_manager_find_by_name(g_img_mgr, "alpine", "latest");
    CHECK(container_manager_get_image_ref_count(mgr, img) == 3, "ref count = 3");

    /* Find all by name */
    for (int i = 0; i < 3; i++)
    {
        container found = container_manager_find_container(mgr, names[i]);
        CHECK(found == containers[i], "find by name");
    }

    /* foreach */
    int count = 0;
    container_manager_foreach_container_safe(mgr, count_cb, &count);
    CHECK(count == 3, "foreach should visit 3 containers");

    /* Remove middle one */
    CHECK(container_remove(containers[1]) == 0, "remove");
    CHECK(container_manager_get_image_ref_count(mgr, img) == 2, "ref count = 2");
    CHECK(container_manager_find_container(mgr, names[1]) == NULL,
          "removed container should not be found");

    /* Remaining containers still findable */
    CHECK(container_manager_find_container(mgr, names[0]) == containers[0], "still find 0");
    CHECK(container_manager_find_container(mgr, names[2]) == containers[2], "still find 2");

    /* Remove remaining */
    CHECK(container_remove(containers[0]) == 0, "remove 0");
    CHECK(container_remove(containers[2]) == 0, "remove 2");
    CHECK(container_manager_get_image_ref_count(mgr, img) == 0, "ref count = 0");

    container_manager_free(mgr);
    printf("  PASS: test_multiple_containers\n");
}

static void test_get_crun_args_interactive(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_name(args, "interactive-test") == 0, "set name");
    /* Not detached (interactive mode) */
    CHECK(container_args_set_detached(args, false) == 0, "set not detached");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    /* get_crun_args should work for interactive container */
    char **argv = NULL;
    size_t argc = 0;
    CHECK(container_get_crun_args(c, &argv, &argc) == 0, "get_crun_args");
    CHECK(argc == 7, "argc should be 7");
    CHECK(strcmp(argv[0], "crun") == 0, "argv[0] = crun");
    CHECK(strcmp(argv[1], "run") == 0, "argv[1] = run");
    CHECK(strcmp(argv[2], "--bundle") == 0, "argv[2] = --bundle");
    CHECK(argv[3] != NULL, "argv[3] = bundle path");
    CHECK(strcmp(argv[4], "--config") == 0, "argv[4] = --config");
    CHECK(argv[5] != NULL, "argv[5] = config path");
    CHECK(strcmp(argv[6], container_get_id(c)) == 0, "argv[6] = container id");

    container_free_crun_args(argv, argc);

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_get_crun_args_interactive\n");
}

static void test_get_crun_args_rejects_restart_policy(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, false) == 0, "set not detached");
    CHECK(container_args_set_restart_policy(args, CONTAINER_RESTART_POLICY_ALWAYS) == 0,
          "set restart policy");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    char **argv = NULL;
    size_t argc = 0;
    CHECK(container_get_crun_args(c, &argv, &argc) == -1,
          "get_crun_args should reject restart policy");

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_get_crun_args_rejects_restart_policy\n");
}

static void test_start_rejects_non_detached(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, false) == 0, "set not detached");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    CHECK(container_start(c) == -1, "start should reject non-detached container");

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_start_rejects_non_detached\n");
}

static void test_detached_container_lifecycle(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, true) == 0, "set detached");
    CHECK(container_args_set_name(args, "detached-test") == 0, "set name");
    const char *cmd[] = { "/bin/sleep", "30" };
    CHECK(container_args_set_command(args, 2, cmd) == 0, "set command");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    CHECK(container_is_detached(c), "should be detached");
    CHECK(!container_is_running(c), "should not be running yet");

    /* Start the container */
    CHECK(container_start(c) == 0, "start");
    CHECK(container_is_running(c), "should be running after start");

    /* Double start should fail */
    CHECK(container_start(c) == -1, "double start should fail");

    /* Stop immediately */
    CHECK(container_stop(c, true) == 0, "stop immediately");

    /* Give the event loop a chance to process the pidfd */
    usleep(100000); /* 100ms */

    /* Remove (also stops if still running) */
    CHECK(container_remove(c) == 0, "remove");

    container_manager_free(mgr);
    printf("  PASS: test_detached_container_lifecycle\n");
}

static void test_manager_free_kills_detached(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, true) == 0, "set detached");
    const char *cmd[] = { "/bin/sleep", "60" };
    CHECK(container_args_set_command(args, 2, cmd) == 0, "set command");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    CHECK(container_start(c) == 0, "start");
    CHECK(container_is_running(c), "should be running");

    /* Free the manager — should kill all detached containers */
    container_manager_free(mgr);

    /* If we get here without hanging, the kill worked */
    printf("  PASS: test_manager_free_kills_detached\n");
}

static void test_stop_not_running(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create");
    container_args_free(args);

    /* Stopping a non-running container should return 0 */
    CHECK(container_stop(c, false) == 0, "stop non-running = ok");
    CHECK(container_stop(c, true) == 0, "stop immediate non-running = ok");

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_stop_not_running\n");
}

static void test_find_by_digest(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    /* Find the image digest first */
    image img = image_manager_find_by_name(g_img_mgr, "alpine", "latest");
    CHECK(img != NULL, "find image");
    const char *digest = image_get_digest(img);
    CHECK(digest != NULL, "digest should not be NULL");

    container_args args = container_args_new();
    CHECK(container_args_set_image_by_digest(args, digest) == 0, "set image by digest");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create by digest");
    container_args_free(args);

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_find_by_digest\n");
}

static void test_null_safety(void)
{
    /* Getter NULL safety */
    CHECK(container_get_id(NULL) == NULL, "get_id(NULL)");
    CHECK(container_get_name(NULL) == NULL, "get_name(NULL)");
    CHECK(!container_is_running(NULL), "is_running(NULL)");
    CHECK(!container_is_detached(NULL), "is_detached(NULL)");
    CHECK(container_stop(NULL, true) == -1, "stop(NULL)");
    CHECK(container_remove(NULL) == -1, "remove(NULL)");
    CHECK(container_start(NULL) == -1, "start(NULL)");
    CHECK(container_monitor_process(NULL, 1) == -1, "monitor(NULL)");

    char **argv = NULL;
    size_t argc = 0;
    CHECK(container_get_crun_args(NULL, &argv, &argc) == -1, "get_crun_args(NULL)");

    CHECK(container_manager_create_container(NULL, NULL) == NULL, "create(NULL, NULL)");
    CHECK(container_manager_find_container(NULL, "x") == NULL, "find(NULL)");
    CHECK(container_manager_foreach_container_safe(NULL, NULL, NULL) == -1, "foreach(NULL)");
    CHECK(container_manager_get_image_ref_count(NULL, NULL) == 0, "ref_count(NULL)");

    container_free_crun_args(NULL, 0);

    printf("  PASS: test_null_safety\n");
}

/* -------------------------------------------------------------------------- */
/*  Tests: meta.json persistence                                               */
/* -------------------------------------------------------------------------- */

static void test_meta_json_written(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, true) == 0, "set detached");
    CHECK(container_args_set_name(args, "meta-test") == 0, "set name");
    CHECK(container_args_set_restart_policy(args, CONTAINER_RESTART_POLICY_ALWAYS) == 0,
          "set restart");
    CHECK(container_args_set_stop_timeout(args, 7000) == 0, "set timeout");
    const char *cmd[] = { "/bin/sleep", "30" };
    CHECK(container_args_set_command(args, 2, cmd) == 0, "set command");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);

    /* Verify meta.json exists */
    char meta_path[512];
    snprintf(meta_path, sizeof(meta_path), "%s/containers/%s/meta.json", CM_ROOT, id);
    CHECK(file_exists(meta_path), "meta.json should exist");

    /* Parse and validate meta.json */
    FILE *f = fopen(meta_path, "r");
    CHECK(f != NULL, "open meta.json");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    CHECK(fread(buf, 1, (size_t)len, f) == (size_t)len, "fread");
    buf[len] = '\0';
    fclose(f);

    cJSON *meta = cJSON_Parse(buf);
    free(buf);
    CHECK(meta != NULL, "parse meta.json");

    /* Check fields */
    cJSON *j_id = cJSON_GetObjectItemCaseSensitive(meta, "id");
    CHECK(cJSON_IsString(j_id), "id is string");
    CHECK(strcmp(j_id->valuestring, id) == 0, "id matches");

    cJSON *j_name = cJSON_GetObjectItemCaseSensitive(meta, "name");
    CHECK(cJSON_IsString(j_name), "name is string");
    CHECK(strcmp(j_name->valuestring, "meta-test") == 0, "name matches");

    cJSON *j_det = cJSON_GetObjectItemCaseSensitive(meta, "detached");
    CHECK(cJSON_IsTrue(j_det), "detached = true");

    cJSON *j_ro = cJSON_GetObjectItemCaseSensitive(meta, "readonly");
    CHECK(cJSON_IsTrue(j_ro), "readonly = true");

    cJSON *j_pol = cJSON_GetObjectItemCaseSensitive(meta, "restart_policy");
    CHECK(cJSON_IsNumber(j_pol), "restart_policy is number");
    CHECK((int)j_pol->valuedouble == CONTAINER_RESTART_POLICY_ALWAYS,
          "restart_policy = ALWAYS");

    cJSON *j_timeout = cJSON_GetObjectItemCaseSensitive(meta, "stop_timeout_ms");
    CHECK(cJSON_IsNumber(j_timeout), "stop_timeout_ms is number");
    CHECK((int)j_timeout->valuedouble == 7000, "stop_timeout_ms = 7000");

    cJSON *j_digest = cJSON_GetObjectItemCaseSensitive(meta, "image_digest");
    CHECK(cJSON_IsString(j_digest), "image_digest is string");

    cJSON *j_bundle = cJSON_GetObjectItemCaseSensitive(meta, "bundle_path");
    CHECK(cJSON_IsString(j_bundle), "bundle_path is string");

    cJSON_Delete(meta);

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_meta_json_written\n");
}

static void test_meta_json_not_restartable_ignored(void)
{
    /* Create a non-restartable container (restart_policy=NEVER).
     * Free the manager. Create a new one. The container should NOT be restored. */
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, true) == 0, "set detached");
    CHECK(container_args_set_name(args, "no-restart") == 0, "set name");
    CHECK(container_args_set_restart_policy(args, CONTAINER_RESTART_POLICY_NEVER) == 0,
          "set restart never");
    const char *cmd[] = { "/bin/sleep", "30" };
    CHECK(container_args_set_command(args, 2, cmd) == 0, "set command");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);
    char id_copy[64];
    snprintf(id_copy, sizeof(id_copy), "%s", id);

    /* meta.json should still be written (for record-keeping) */
    char meta_path[512];
    snprintf(meta_path, sizeof(meta_path), "%s/containers/%s/meta.json", CM_ROOT, id);
    CHECK(file_exists(meta_path), "meta.json should exist");

    /* Don't remove the container — leave it on disk and free the manager */
    container_manager_free(mgr);

    /* Create a new manager — the non-restartable container should NOT be restored */
    mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new2");

    container found = container_manager_find_container(mgr, id_copy);
    CHECK(found == NULL, "non-restartable container should not be restored");

    /* meta.json should still be on disk (not cleaned up) */
    CHECK(file_exists(meta_path), "meta.json should still exist on disk");

    /* Clean up the leftover directory manually for test hygiene */
    char rm_cmd[512];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s/containers/%s", CM_ROOT, id_copy);
    (void)system(rm_cmd);

    container_manager_free(mgr);
    printf("  PASS: test_meta_json_not_restartable_ignored\n");
}

static void test_restart_on_manager_recreate(void)
{
    /* Create a detached container with restart_policy=ALWAYS, start it,
     * free the manager (kills the process), recreate the manager,
     * and verify the container was restored and started. */

    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image_by_name(args, "alpine", "latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, true) == 0, "set detached");
    CHECK(container_args_set_name(args, "restart-test") == 0, "set name");
    CHECK(container_args_set_restart_policy(args, CONTAINER_RESTART_POLICY_ALWAYS) == 0,
          "set restart always");
    const char *cmd[] = { "/bin/sleep", "60" };
    CHECK(container_args_set_command(args, 2, cmd) == 0, "set command");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);
    char id_copy[64];
    snprintf(id_copy, sizeof(id_copy), "%s", id);
    const char *name = container_get_name(c);
    char name_copy[64];
    snprintf(name_copy, sizeof(name_copy), "%s", name);

    /* Start the container */
    CHECK(container_start(c) == 0, "start");
    CHECK(container_is_running(c), "should be running");

    /* Free the manager — kills all detached containers but does NOT remove dirs */
    container_manager_free(mgr);

    /* container dirs should still be on disk */
    char meta_path[512];
    snprintf(meta_path, sizeof(meta_path), "%s/containers/%s/meta.json", CM_ROOT, id_copy);
    CHECK(file_exists(meta_path), "meta.json should survive manager free");

    /* Create a new manager at the same root — should restore the container */
    mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new2");

    /* The container should be restored by id or name */
    container restored = container_manager_find_container(mgr, id_copy);
    CHECK(restored != NULL, "container should be restored");
    CHECK(strcmp(container_get_id(restored), id_copy) == 0, "restored id matches");
    CHECK(strcmp(container_get_name(restored), name_copy) == 0, "restored name matches");
    CHECK(container_is_detached(restored), "restored should be detached");
    CHECK(container_is_running(restored), "restored should be running");

    /* Clean up: stop and remove the restored container */
    CHECK(container_stop(restored, true) == 0, "stop restored");
    usleep(100000);
    CHECK(container_remove(restored) == 0, "remove restored");

    container_manager_free(mgr);
    printf("  PASS: test_restart_on_manager_recreate\n");
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                       */
/* -------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <sqfs-file>\n", argv[0]);
        return 1;
    }
    g_sqfs_path = argv[1];

    printf("=== container_manager tests ===\n");
    printf("    image: %s\n", g_sqfs_path);

    /* --- Setup dependencies --- */
    g_tev = tev_create_ctx();
    CHECK(g_tev != NULL, "tev_create_ctx");

    g_img_mgr = image_manager_new(IMG_ROOT);
    CHECK(g_img_mgr != NULL, "image_manager_new");

    image img = image_manager_load(g_img_mgr, g_sqfs_path);
    CHECK(img != NULL, "image_manager_load");
    CHECK(image_get_mounted(img), "image should be mounted");
    printf("    bundle: %s\n", image_get_bundle_path(img));

    g_nat_mgr = nat_network_manager_new(g_tev, NAT_ROOT);
    CHECK(g_nat_mgr != NULL, "nat_network_manager_new");

    printf("\n");

    /* --- container_args tests (no root needed for these) --- */
    test_args_new_free();
    test_args_set_name();
    test_args_image_mutual_exclusion();
    test_args_setters();

    /* --- container_manager tests --- */
    test_manager_new_free();
    test_null_safety();
    test_create_no_image();
    test_create_container_readonly();
    test_create_container_rw_overlay();
    test_create_container_with_options();
    test_multiple_containers();
    test_find_by_digest();
    test_get_crun_args_interactive();
    test_get_crun_args_rejects_restart_policy();
    test_start_rejects_non_detached();
    test_stop_not_running();
    test_detached_container_lifecycle();
    test_manager_free_kills_detached();

    /* --- restart persistence tests --- */
    test_meta_json_written();
    test_meta_json_not_restartable_ignored();
    test_restart_on_manager_recreate();

    /* --- Cleanup --- */
    nat_network_manager_free(g_nat_mgr);
    image_manager_free(g_img_mgr, true);
    tev_free_ctx(g_tev);

    printf("\n=== All container_manager tests passed ===\n");
    return 0;
}
