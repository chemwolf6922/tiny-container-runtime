#include "test_util.h"
#include "container/container_manager.h"
#include "image/image_manager.h"
#include "network/nat_network_manager.h"

/* CM_ROOT/IMG_ROOT/NAT_ROOT are now runtime-computed char arrays rather than
   string literals, so GCC cannot statically prove every snprintf fits.
   snprintf handles truncation safely; silence the warning. */
#pragma GCC diagnostic ignored "-Wformat-truncation"

#include <cjson/cJSON.h>
#include <tev/tev.h>

#include <arpa/inet.h>
#include <fcntl.h>
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

static char _cm_root[512];
static char _img_root[512];
static char _nat_root[512];
#define CM_ROOT _cm_root
#define IMG_ROOT _img_root
#define NAT_ROOT _nat_root

/* -------------------------------------------------------------------------- */
/*  Helper: verify file exists                                                 */
/* -------------------------------------------------------------------------- */

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* -------------------------------------------------------------------------- */
/*  Helper: read file to string                                                */
/* -------------------------------------------------------------------------- */

static char *test_read_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n != st.st_size) { free(buf); return NULL; }
    buf[n] = '\0';
    return buf;
}

/**
 * Check if /etc/hosts contains a line with the given tag.
 */
static int hosts_has_tag(const char *tag)
{
    char *content = test_read_file("/etc/hosts");
    if (!content) return 0;
    int found = strstr(content, tag) != NULL;
    free(content);
    return found;
}

/**
 * Check if /etc/hosts has a line containing both the given hostname and tag.
 */
static int hosts_has_entry(const char *hostname, const char *tag)
{
    char *content = test_read_file("/etc/hosts");
    if (!content) return 0;

    /* Search line by line */
    char *line = content;
    int found = 0;
    while (*line)
    {
        char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);

        /* Check if this line contains both the hostname and tag */
        char *t = strstr(line, tag);
        char *h = strstr(line, hostname);
        if (t && h && (!eol || (t < line + len && h < line + len)))
        {
            found = 1;
            break;
        }

        line += len;
        if (*line == '\n') line++;
    }

    free(content);
    return found;
}

/* Small helper — search for needle within n bytes of haystack */
static int strnstr_helper(const char *haystack, size_t n, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen > n) return 0;
    for (size_t i = 0; i <= n - nlen; i++)
    {
        if (memcmp(haystack + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

/**
 * Extract the IP address from /etc/hosts for a given tag (e.g. "# tcr:<id>").
 * Returns a dynamically allocated string or NULL if not found.
 */
static char *hosts_get_ip(const char *tag)
{
    char *content = test_read_file("/etc/hosts");
    if (!content) return NULL;

    char *line = content;
    char *result = NULL;
    while (*line)
    {
        char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);

        if (len > 0 && strnstr_helper(line, len, tag))
        {
            /* First token is the IP address */
            char tmp[INET_ADDRSTRLEN];
            if (sscanf(line, "%15s", tmp) == 1)
                result = strdup(tmp);
            break;
        }

        line += len;
        if (*line == '\n') line++;
    }

    free(content);
    return result;
}

/**
 * Run dig against the DNS forwarder by forking:
 *   child  – runs tev_main_loop() so the forwarder can answer
 *   parent – runs dig, collects the A-record result, kills child
 *
 * Returns a dynamically allocated string with the IP, or NULL.
 */
static char *dig_lookup(const char *server_ip, const char *hostname)
{
    pid_t pid = fork();
    if (pid < 0) return NULL;

    if (pid == 0)
    {
        /* Child: pump the event loop to serve DNS queries */
        tev_main_loop(g_tev);
        _exit(0);
    }

    /* Parent: give child time to enter epoll_wait */
    usleep(200000); /* 200 ms */

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "dig @%s %s A +short +time=2 +tries=1 2>/dev/null",
             server_ip, hostname);

    char *result = NULL;
    FILE *fp = popen(cmd, "r");
    if (fp)
    {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp))
        {
            size_t len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
            if (buf[0]) result = strdup(buf);
        }
        pclose(fp);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return result;
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "nonexistent:v999") == 0, "set bad image");
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
        CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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

static void test_network_ref_count(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    /* Create a network — no containers attached yet */
    nat_network net = nat_network_manager_get_network(g_nat_mgr, "refcount_net");
    CHECK(net != NULL, "create test network");

    /* No containers at all — ref count should be 0 */
    CHECK(container_manager_get_network_ref_count(mgr, net) == 0,
          "ref count should be 0 with no containers");

    /* Create containers without networking — should not affect network ref count */
    container containers[2];
    for (int i = 0; i < 2; i++)
    {
        container_args args = container_args_new();
        CHECK(args != NULL, "args_new");
        CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
        CHECK(container_args_set_readonly(args, true) == 0, "set ro");
        char name[32];
        snprintf(name, sizeof(name), "netref-%d", i);
        CHECK(container_args_set_name(args, name) == 0, "set name");

        containers[i] = container_manager_create_container(mgr, args);
        CHECK(containers[i] != NULL, "create_container");
        container_args_free(args);
    }

    /* Non-networked containers should not count */
    CHECK(container_manager_get_network_ref_count(mgr, net) == 0,
          "ref count should still be 0 for non-networked containers");

    /* NULL safety */
    CHECK(container_manager_get_network_ref_count(NULL, net) == 0,
          "ref_count(NULL mgr) should be 0");
    CHECK(container_manager_get_network_ref_count(mgr, NULL) == 0,
          "ref_count(NULL net) should be 0");

    /* Cleanup */
    CHECK(container_remove(containers[0]) == 0, "remove 0");
    CHECK(container_remove(containers[1]) == 0, "remove 1");
    nat_network_remove_network(g_nat_mgr, "refcount_net");
    container_manager_free(mgr);
    printf("  PASS: test_network_ref_count\n");
}

static void test_get_crun_args_interactive(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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

static void test_find_by_id(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    /* Find the image id first */
    image img = image_manager_find_by_name(g_img_mgr, "alpine", "latest");
    CHECK(img != NULL, "find image");
    const char *id = image_get_id(img);
    CHECK(id != NULL, "id should not be NULL");

    container_args args = container_args_new();
    CHECK(container_args_set_image(args, id) == 0, "set image by id");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create by id");
    container_args_free(args);

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_find_by_id\n");
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
    CHECK(container_manager_get_network_ref_count(NULL, NULL) == 0, "net_ref_count(NULL)");

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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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

    cJSON *j_pol = cJSON_GetObjectItemCaseSensitive(meta, "restartPolicy");
    CHECK(cJSON_IsNumber(j_pol), "restartPolicy is number");
    CHECK((int)j_pol->valuedouble == CONTAINER_RESTART_POLICY_ALWAYS,
          "restartPolicy = ALWAYS");

    cJSON *j_timeout = cJSON_GetObjectItemCaseSensitive(meta, "stopTimeoutMs");
    CHECK(cJSON_IsNumber(j_timeout), "stopTimeoutMs is number");
    CHECK((int)j_timeout->valuedouble == 7000, "stopTimeoutMs = 7000");

    cJSON *j_image_id = cJSON_GetObjectItemCaseSensitive(meta, "imageId");
    CHECK(cJSON_IsString(j_image_id), "imageId is string");

    cJSON *j_bundle = cJSON_GetObjectItemCaseSensitive(meta, "bundlePath");
    CHECK(cJSON_IsString(j_bundle), "bundlePath is string");

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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
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

static void test_unless_stopped_not_restored_after_stop(void)
{
    /* Create a detached container with UNLESS_STOPPED, start it,
     * explicitly stop it, free the manager, recreate it,
     * and verify the container is NOT restored. */

    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, true) == 0, "set detached");
    CHECK(container_args_set_name(args, "unless-stop-test") == 0, "set name");
    CHECK(container_args_set_restart_policy(args, CONTAINER_RESTART_POLICY_UNLESS_STOPPED) == 0,
          "set restart unless_stopped");
    const char *cmd[] = { "/bin/sleep", "60" };
    CHECK(container_args_set_command(args, 2, cmd) == 0, "set command");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);
    char id_copy[64];
    snprintf(id_copy, sizeof(id_copy), "%s", id);

    /* Start the container */
    CHECK(container_start(c) == 0, "start");
    CHECK(container_is_running(c), "should be running");

    /* Explicitly stop — this should mark explicitly_stopped in meta.json */
    CHECK(container_stop(c, true) == 0, "stop");

    /* Free the manager */
    container_manager_free(mgr);

    /* meta.json should still exist on disk */
    char meta_path[512];
    snprintf(meta_path, sizeof(meta_path), "%s/containers/%s/meta.json", CM_ROOT, id_copy);
    CHECK(file_exists(meta_path), "meta.json should exist on disk");

    /* Recreate manager — UNLESS_STOPPED + explicitly_stopped should NOT be restored */
    mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new2");

    container found = container_manager_find_container(mgr, id_copy);
    CHECK(found == NULL, "explicitly stopped UNLESS_STOPPED should not be restored");

    /* Clean up leftover on disk */
    char rm_cmd[512];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s/containers/%s", CM_ROOT, id_copy);
    (void)system(rm_cmd);

    container_manager_free(mgr);
    printf("  PASS: test_unless_stopped_not_restored_after_stop\n");
}

static void test_always_restored_after_stop(void)
{
    /* Create a detached container with ALWAYS, start it,
     * explicitly stop it, free the manager, recreate it,
     * and verify the container IS restored (ALWAYS overrides explicit stop). */

    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_detached(args, true) == 0, "set detached");
    CHECK(container_args_set_name(args, "always-stop-test") == 0, "set name");
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

    /* Start the container */
    CHECK(container_start(c) == 0, "start");
    CHECK(container_is_running(c), "should be running");

    /* Explicitly stop — for ALWAYS, this should NOT prevent restore on daemon restart */
    CHECK(container_stop(c, true) == 0, "stop");

    /* Free the manager */
    container_manager_free(mgr);

    /* Recreate manager — ALWAYS should be restored regardless of explicit stop */
    mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new2");

    container restored = container_manager_find_container(mgr, id_copy);
    CHECK(restored != NULL, "ALWAYS container should be restored even after explicit stop");
    CHECK(container_is_running(restored), "restored should be running");

    /* Clean up */
    CHECK(container_stop(restored, true) == 0, "stop restored");
    usleep(100000);
    CHECK(container_remove(restored) == 0, "remove restored");

    container_manager_free(mgr);
    printf("  PASS: test_always_restored_after_stop\n");
}

/* -------------------------------------------------------------------------- */
/*  Tests: /etc/hosts entries                                                  */
/* -------------------------------------------------------------------------- */

static void test_hosts_entries_on_create_remove(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_name(args, "my-web-app") == 0, "set name");
    CHECK(container_args_set_nat_network(args, NULL) == 0, "set nat network");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);
    const char *name = container_get_name(c);
    CHECK(id != NULL, "id");
    CHECK(name != NULL, "name");
    CHECK(strcmp(name, "my-web-app") == 0, "name should be my-web-app");

    /* Build expected entries */
    char id_tag[128], id_host[128], name_host[128];
    snprintf(id_tag, sizeof(id_tag), "# tcr:%s", id);
    snprintf(id_host, sizeof(id_host), "tcr-%s", id);
    snprintf(name_host, sizeof(name_host), "tcr-%s", name);

    /* /etc/hosts should have entries for both id and name */
    CHECK(hosts_has_tag(id_tag), "/etc/hosts should have tcr tag after create");
    CHECK(hosts_has_entry(id_host, id_tag),
          "/etc/hosts should have tcr-<id> hostname");
    CHECK(hosts_has_entry(name_host, id_tag),
          "/etc/hosts should have tcr-<name> hostname");

    /* Remove the container */
    CHECK(container_remove(c) == 0, "remove");

    /* /etc/hosts entries should be gone */
    CHECK(!hosts_has_tag(id_tag), "/etc/hosts tag should be removed after remove");

    container_manager_free(mgr);
    printf("  PASS: test_hosts_entries_on_create_remove\n");
}

static void test_hosts_name_equals_id(void)
{
    /* When no custom name is set, name defaults to id.
     * In this case only tcr-<id> should appear (no duplicate). */
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    /* No name set — will default to id */
    CHECK(container_args_set_nat_network(args, NULL) == 0, "set nat network");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);
    const char *name = container_get_name(c);
    CHECK(strcmp(name, id) == 0, "name should equal id when not explicitly set");

    char id_tag[128], id_host[128];
    snprintf(id_tag, sizeof(id_tag), "# tcr:%s", id);
    snprintf(id_host, sizeof(id_host), "tcr-%s", id);

    /* /etc/hosts should have the id entry */
    CHECK(hosts_has_entry(id_host, id_tag),
          "/etc/hosts should have tcr-<id> entry");

    /* Remove and verify cleanup */
    CHECK(container_remove(c) == 0, "remove");
    CHECK(!hosts_has_tag(id_tag), "/etc/hosts should be clean");

    container_manager_free(mgr);
    printf("  PASS: test_hosts_name_equals_id\n");
}

static void test_hosts_no_network(void)
{
    /* Containers without NAT networking should NOT get /etc/hosts entries */
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_name(args, "no-net-host-test") == 0, "set name");
    /* No nat network set */

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);
    char id_tag[128];
    snprintf(id_tag, sizeof(id_tag), "# tcr:%s", id);

    /* Should NOT have any /etc/hosts entry */
    CHECK(!hosts_has_tag(id_tag),
          "container without network should not have /etc/hosts entry");

    CHECK(container_remove(c) == 0, "remove");
    container_manager_free(mgr);
    printf("  PASS: test_hosts_no_network\n");
}

/* -------------------------------------------------------------------------- */
/*  Tests: DNS forwarder entries (verified via dig)                             */
/* -------------------------------------------------------------------------- */

static void test_dns_entries_via_dig(void)
{
    container_manager mgr = container_manager_new(g_tev, g_img_mgr, g_nat_mgr, CM_ROOT);
    CHECK(mgr != NULL, "new");

    container_args args = container_args_new();
    CHECK(args != NULL, "args_new");
    CHECK(container_args_set_image(args, "alpine:latest") == 0, "set image");
    CHECK(container_args_set_readonly(args, true) == 0, "set readonly");
    CHECK(container_args_set_name(args, "dig-test-app") == 0, "set name");
    CHECK(container_args_set_nat_network(args, NULL) == 0, "set nat network");

    container c = container_manager_create_container(mgr, args);
    CHECK(c != NULL, "create_container");
    container_args_free(args);

    const char *id = container_get_id(c);
    const char *name = container_get_name(c);
    CHECK(strcmp(name, "dig-test-app") == 0, "name");

    /* Get gateway IP (= DNS forwarder listen address) */
    nat_network net = nat_network_manager_get_network(g_nat_mgr, NULL);
    CHECK(net != NULL, "get default network");
    struct in_addr gateway;
    CHECK(nat_network_get_gateway(net, &gateway) == 0, "get gateway");
    char gw_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &gateway, gw_str, sizeof(gw_str));

    /* Get expected IP from /etc/hosts */
    char id_tag[128];
    snprintf(id_tag, sizeof(id_tag), "# tcr:%s", id);
    char *expected_ip = hosts_get_ip(id_tag);
    CHECK(expected_ip != NULL, "should have /etc/hosts entry to derive expected IP");

    /* dig tcr-<id> via the DNS forwarder */
    char id_host[128];
    snprintf(id_host, sizeof(id_host), "tcr-%s", id);
    char *dig_id = dig_lookup(gw_str, id_host);
    CHECK(dig_id != NULL, "dig tcr-<id> should resolve");
    CHECK(strcmp(dig_id, expected_ip) == 0, "dig tcr-<id> should match allocated IP");

    /* dig tcr-<name> via the DNS forwarder */
    char name_host[128];
    snprintf(name_host, sizeof(name_host), "tcr-%s", name);
    char *dig_name = dig_lookup(gw_str, name_host);
    CHECK(dig_name != NULL, "dig tcr-<name> should resolve");
    CHECK(strcmp(dig_name, expected_ip) == 0, "dig tcr-<name> should match allocated IP");

    free(dig_id);
    free(dig_name);

    /* Remove container — DNS entries should be cleaned up */
    CHECK(container_remove(c) == 0, "remove");

    /* After removal, dig should return nothing (entry removed) */
    char *dig_after = dig_lookup(gw_str, id_host);
    CHECK(dig_after == NULL, "dig tcr-<id> should not resolve after removal");
    free(dig_after); /* safe even if NULL */

    free(expected_ip);
    container_manager_free(mgr);
    printf("  PASS: test_dns_entries_via_dig\n");
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

    /* Compute data directory from binary location (test/build/../data) */
    char data_dir[256];
    test_get_data_dir(data_dir, sizeof(data_dir), argv[0]);
    snprintf(_cm_root, sizeof(_cm_root), "%s/tcr-test-container-manager", data_dir);
    snprintf(_img_root, sizeof(_img_root), "%s/tcr-test-cm-images", data_dir);
    snprintf(_nat_root, sizeof(_nat_root), "%s/tcr-test-cm-nat", data_dir);

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
    test_args_setters();

    /* --- container_manager tests --- */
    test_manager_new_free();
    test_null_safety();
    test_create_no_image();
    test_create_container_readonly();
    test_create_container_rw_overlay();
    test_create_container_with_options();
    test_multiple_containers();
    test_find_by_id();
    test_get_crun_args_interactive();
    test_get_crun_args_rejects_restart_policy();
    test_start_rejects_non_detached();
    test_stop_not_running();
    test_detached_container_lifecycle();
    test_manager_free_kills_detached();

    test_network_ref_count();

    /* --- restart persistence tests --- */
    test_meta_json_written();
    test_meta_json_not_restartable_ignored();
    test_restart_on_manager_recreate();
    test_unless_stopped_not_restored_after_stop();
    test_always_restored_after_stop();

    /* --- /etc/hosts tests --- */
    test_hosts_entries_on_create_remove();
    test_hosts_name_equals_id();
    test_hosts_no_network();

    /* --- DNS forwarder tests (via dig) --- */
    test_dns_entries_via_dig();

    /* --- Cleanup --- */
    nat_network_manager_free(g_nat_mgr);
    image_manager_free(g_img_mgr, true);
    tev_free_ctx(g_tev);

    printf("\n=== All container_manager tests passed ===\n");
    return 0;
}
