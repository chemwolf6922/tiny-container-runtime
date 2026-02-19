#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "container_manager.h"

#include "container/crun_config.h"
#include "common/list.h"
#include "common/utils.h"

#include <cjson/cJSON.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Constants                                                                  */
/* -------------------------------------------------------------------------- */

#define CONTAINERS_DIRNAME  "containers"
#define CONFIG_FILENAME     "config.json"
#define META_FILENAME       "meta.json"
#define RESOLV_CONF_FILE    "resolv.conf"
#define CONTAINER_ID_BYTES  8   /* 8 random bytes → 16 hex chars */
#define DEFAULT_STOP_TIMEOUT_MS  10000

#define HOSTS_FILE          "/etc/hosts"

/* meta.json key names (camelCase per JSON convention) */
#define JKEY_ID                 "id"
#define JKEY_NAME               "name"
#define JKEY_DETACHED           "detached"
#define JKEY_AUTO_REMOVE        "autoRemove"
#define JKEY_READONLY           "readonly"
#define JKEY_RESTART_POLICY     "restartPolicy"
#define JKEY_STOP_TIMEOUT_MS    "stopTimeoutMs"
#define JKEY_EXPLICITLY_STOPPED "explicitlyStopped"
#define JKEY_BUNDLE_PATH        "bundlePath"
#define JKEY_IMAGE_ID           "imageId"
#define JKEY_NAT_NETWORK_NAME   "natNetworkName"
#define JKEY_NETNS_NAME         "netnsName"
#define JKEY_ALLOCATED_IP       "allocatedIp"
#define JKEY_PORT_FORWARDS      "portForwards"
#define JKEY_HOST_IP            "hostIp"
#define JKEY_HOST_PORT          "hostPort"
#define JKEY_CONTAINER_PORT     "containerPort"
#define JKEY_PROTOCOL           "protocol"

/* -------------------------------------------------------------------------- */
/*  Data structures                                                            */
/* -------------------------------------------------------------------------- */

/* Dynamic array for bind mounts */
typedef struct {
    char *source;
    char *destination;
    bool read_only;
} bind_mount_entry;

/* Dynamic array for tmpfs mounts */
typedef struct {
    char *destination;
    size_t size_bytes;
} tmpfs_mount_entry;

/* Dynamic array for environment variables */
typedef struct {
    char *key;
    char *value;
} env_entry;

/* Dynamic array for port forwarding specs */
typedef struct {
    struct in_addr host_ip;
    uint16_t host_port;
    uint16_t container_port;
    int protocol;
} port_forward_entry;

struct container_args_s
{
    char *name;

    /* image reference (id or "name:tag") */
    char *image_ref;

    bool readonly;
    bool is_tty;
    bool detached;
    bool auto_remove;

    container_restart_policy restart_policy;
    int stop_timeout_ms;

    /* command override */
    char **command;
    size_t command_count;

    /* bind mounts */
    bind_mount_entry *bind_mounts;
    size_t bind_mount_count;
    size_t bind_mount_cap;

    /* tmpfs mounts */
    tmpfs_mount_entry *tmpfs_mounts;
    size_t tmpfs_mount_count;
    size_t tmpfs_mount_cap;

    /* environment variables */
    env_entry *envs;
    size_t env_count;
    size_t env_cap;

    /* NAT network */
    char *nat_network_name; /* NULL = no network; non-NULL = use this network (or default) */
    bool use_nat_network;

    /* port forwarding */
    port_forward_entry *port_forwards;
    size_t port_forward_count;
    size_t port_forward_cap;
};

typedef enum {
    CONTAINER_STATE_CREATED,
    CONTAINER_STATE_RUNNING,
    CONTAINER_STATE_STOPPED,
} container_state;

struct container_s
{
    struct list_head list;

    /* identity */
    char *id;
    char *name;

    /* configuration */
    bool detached;
    bool auto_remove;
    bool readonly;
    container_restart_policy restart_policy;
    int stop_timeout_ms;

    /* paths */
    char *container_dir;
    char *config_path;
    char *bundle_path;  /* image bundle path (not owned, from image) */

    /* overlay (non-readonly only) */
    char *overlay_lower;
    char *overlay_upper;
    char *overlay_work;
    char *overlay_merged;
    bool overlay_mounted;

    /* network */
    char *nat_network_name; /* NULL if no network */
    nat_network network;    /* borrowed ref from nat_manager */
    struct in_addr allocated_ip;
    bool has_ip;
    char *netns_name;
    char *resolv_conf_path;

    /* port forwarders (owned) */
    port_forwarder *port_forwarders;
    size_t port_forwarder_count;

    /* port forwarding specs (for persistence, mirrors port_forwarders) */
    port_forward_entry *port_forward_specs;
    size_t port_forward_spec_count;

    /* DNS domain registered in dns_forwarder */
    char *dns_domain;

    /* set when container_stop() is called — suppresses UNLESS_STOPPED restart */
    bool explicitly_stopped;

    /* process tracking */
    container_state state;
    pid_t pid;
    int pidfd;

    /* graceful stop */
    tev_timeout_handle_t stop_timer;

    /* image ref (for ref counting) */
    image img;

    /* back-pointer to manager */
    struct container_manager_s *manager;
};

struct container_manager_s
{
    tev_handle_t tev;
    image_manager img_manager;
    nat_network_manager nat_manager;

    char *root_path;
    char *containers_dir;

    struct list_head containers;
};

/* -------------------------------------------------------------------------- */
/*  Forward declarations                                                       */
/* -------------------------------------------------------------------------- */

static void on_process_exit(void *ctx);
static void on_stop_timeout(void *ctx);
static int setup_process_monitor(struct container_s *c, pid_t pid);
static void cleanup_process_monitor(struct container_s *c);
static int mount_overlay(struct container_s *c);
static void umount_overlay(struct container_s *c);
static void cleanup_network(struct container_s *c);
static void container_free_internal(struct container_s *c);

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static int mkdir_p(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int rmdir_recursive_cb(const char *fpath, const struct stat *sb,
                              int typeflag, struct FTW *ftwbuf)
{
    (void)sb; (void)ftwbuf;
    if (typeflag == FTW_DP)
        return rmdir(fpath) == 0 ? 0 : -1;
    return remove(fpath) == 0 ? 0 : -1;
}

static int rmdir_recursive(const char *path)
{
    return nftw(path, rmdir_recursive_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/**
 * Generate a random container ID (16 hex characters).
 */
static char *generate_container_id(void)
{
    unsigned char buf[CONTAINER_ID_BYTES];
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;

    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n != sizeof(buf)) return NULL;

    char *id = malloc(CONTAINER_ID_BYTES * 2 + 1);
    if (!id) return NULL;

    for (int i = 0; i < CONTAINER_ID_BYTES; i++)
        snprintf(id + i * 2, 3, "%02x", buf[i]);

    return id;
}

/**
 * Write a string to a file, creating it if needed.
 */
static int write_string_to_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -1;

    size_t len = strlen(content);
    ssize_t written = write(fd, content, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

/**
 * Read entire file into a malloc'd string. Returns NULL on failure.
 */
static char *read_file_to_string(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) { close(fd); return NULL; }

    size_t len = (size_t)st.st_size;
    char *buf = malloc(len + 1);
    if (!buf) { close(fd); return NULL; }

    ssize_t n = read(fd, buf, len);
    close(fd);
    if (n != (ssize_t)len) { free(buf); return NULL; }

    buf[len] = '\0';
    return buf;
}

/**
 * Write container metadata as meta.json.
 * This captures everything needed to restore the container on manager restart.
 */
static int write_container_meta(struct container_s *c)
{
    cJSON *meta = cJSON_CreateObject();
    if (!meta) return -1;

    cJSON_AddStringToObject(meta, JKEY_ID, c->id);
    cJSON_AddStringToObject(meta, JKEY_NAME, c->name);
    cJSON_AddBoolToObject(meta, JKEY_DETACHED, c->detached);
    cJSON_AddBoolToObject(meta, JKEY_AUTO_REMOVE, c->auto_remove);
    cJSON_AddBoolToObject(meta, JKEY_READONLY, c->readonly);
    cJSON_AddNumberToObject(meta, JKEY_RESTART_POLICY, (double)c->restart_policy);
    cJSON_AddNumberToObject(meta, JKEY_STOP_TIMEOUT_MS, (double)c->stop_timeout_ms);
    cJSON_AddBoolToObject(meta, JKEY_EXPLICITLY_STOPPED, c->explicitly_stopped);
    cJSON_AddStringToObject(meta, JKEY_BUNDLE_PATH, c->bundle_path);

    /* Image id for restoration */
    if (c->img)
    {
        const char *id = image_get_id(c->img);
        if (id)
            cJSON_AddStringToObject(meta, JKEY_IMAGE_ID, id);
    }

    /* Network fields */
    if (c->nat_network_name)
        cJSON_AddStringToObject(meta, JKEY_NAT_NETWORK_NAME, c->nat_network_name);
    if (c->netns_name)
        cJSON_AddStringToObject(meta, JKEY_NETNS_NAME, c->netns_name);
    if (c->has_ip)
    {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &c->allocated_ip, ip_str, sizeof(ip_str));
        cJSON_AddStringToObject(meta, JKEY_ALLOCATED_IP, ip_str);
    }

    /* Port forwarding entries */
    if (c->port_forward_spec_count > 0)
    {
        cJSON *pf_arr = cJSON_AddArrayToObject(meta, JKEY_PORT_FORWARDS);
        if (pf_arr)
        {
            for (size_t i = 0; i < c->port_forward_spec_count; i++)
            {
                port_forward_entry *pfe = &c->port_forward_specs[i];
                cJSON *pf = cJSON_CreateObject();
                if (!pf) continue;

                char hip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pfe->host_ip, hip, sizeof(hip));
                cJSON_AddStringToObject(pf, JKEY_HOST_IP, hip);
                cJSON_AddNumberToObject(pf, JKEY_HOST_PORT, pfe->host_port);
                cJSON_AddNumberToObject(pf, JKEY_CONTAINER_PORT, pfe->container_port);
                cJSON_AddNumberToObject(pf, JKEY_PROTOCOL, pfe->protocol);
                cJSON_AddItemToArray(pf_arr, pf);
            }
        }
    }

    char *meta_path = path_join(c->container_dir, META_FILENAME);
    if (!meta_path) { cJSON_Delete(meta); return -1; }

    char *str = cJSON_Print(meta);
    cJSON_Delete(meta);
    if (!str) { free(meta_path); return -1; }

    int ret = write_string_to_file(meta_path, str);
    free(str);
    free(meta_path);
    return ret;
}

/* -------------------------------------------------------------------------- */
/*  /etc/hosts management (host-local DNS resolution for containers)           */
/* -------------------------------------------------------------------------- */

/**
 * Add /etc/hosts entries for a container so the host can reach it by name.
 * Entry format: <ip> tcr-<id> [tcr-<name>] # tcr:<id>
 */
static void add_hosts_entry(const char *id, const char *name, const char *ip)
{
    char *tag = NULL, *id_host = NULL, *name_host = NULL;
    char *new_line = NULL, *content = NULL, *output = NULL;

    if (asprintf(&tag, "# tcr:%s", id) < 0) return;
    if (asprintf(&id_host, "tcr-%s", id) < 0) { free(tag); return; }

    /* Also add tcr-<name> alias if name differs from id */
    if (name && strcmp(name, id) != 0)
    {
        if (asprintf(&name_host, "tcr-%s", name) < 0)
            name_host = NULL; /* non-fatal, skip name alias */
    }

    if (name_host)
    {
        if (asprintf(&new_line, "%s %s %s %s\n", ip, id_host, name_host, tag) < 0)
        { new_line = NULL; goto out; }
    }
    else
    {
        if (asprintf(&new_line, "%s %s %s\n", ip, id_host, tag) < 0)
        { new_line = NULL; goto out; }
    }

    content = read_file_to_string(HOSTS_FILE);

    size_t new_line_len = strlen(new_line);
    size_t content_len = content ? strlen(content) : 0;
    output = malloc(content_len + new_line_len + 1);
    if (!output) goto out;

    /* Copy existing lines, filtering out any stale entry for this container */
    size_t out_pos = 0;
    if (content)
    {
        char *line = content;
        while (*line)
        {
            char *eol = strchr(line, '\n');
            size_t len = eol ? (size_t)(eol - line + 1) : strlen(line);

            char *found = strstr(line, tag);
            bool has_tag = found && (!eol || found < eol);
            if (!has_tag)
            {
                memcpy(output + out_pos, line, len);
                out_pos += len;
            }

            line += len;
        }
    }

    memcpy(output + out_pos, new_line, new_line_len);
    out_pos += new_line_len;
    output[out_pos] = '\0';

    write_string_to_file(HOSTS_FILE, output);

out:
    free(output);
    free(new_line);
    free(name_host);
    free(id_host);
    free(tag);
    free(content);
}

/**
 * Remove /etc/hosts entries for a container.
 * Removes all lines tagged with "# tcr:<id>".
 */
static void remove_hosts_entry(const char *id)
{
    char *tag = NULL;
    if (asprintf(&tag, "# tcr:%s", id) < 0) return;

    char *content = read_file_to_string(HOSTS_FILE);
    if (!content) { free(tag); return; }

    size_t content_len = strlen(content);
    char *output = malloc(content_len + 1);
    if (!output) { free(tag); free(content); return; }

    size_t out_pos = 0;
    char *line = content;
    while (*line)
    {
        char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line + 1) : strlen(line);

        char *found = strstr(line, tag);
        bool has_tag = found && (!eol || found < eol);
        if (!has_tag)
        {
            memcpy(output + out_pos, line, len);
            out_pos += len;
        }

        line += len;
    }
    output[out_pos] = '\0';

    write_string_to_file(HOSTS_FILE, output);

    free(output);
    free(tag);
    free(content);
}

/* -------------------------------------------------------------------------- */
/*  container_args API                                                         */
/* -------------------------------------------------------------------------- */

container_args container_args_new(void)
{
    struct container_args_s *args = calloc(1, sizeof(*args));
    if (!args) return NULL;

    args->restart_policy = CONTAINER_RESTART_POLICY_NEVER;
    args->stop_timeout_ms = DEFAULT_STOP_TIMEOUT_MS;

    return args;
}

void container_args_free(container_args args)
{
    if (!args) return;
    struct container_args_s *a = args;

    free(a->name);
    free(a->image_ref);

    for (size_t i = 0; i < a->command_count; i++)
        free(a->command[i]);
    free(a->command);

    for (size_t i = 0; i < a->bind_mount_count; i++)
    {
        free(a->bind_mounts[i].source);
        free(a->bind_mounts[i].destination);
    }
    free(a->bind_mounts);

    for (size_t i = 0; i < a->tmpfs_mount_count; i++)
        free(a->tmpfs_mounts[i].destination);
    free(a->tmpfs_mounts);

    for (size_t i = 0; i < a->env_count; i++)
    {
        free(a->envs[i].key);
        free(a->envs[i].value);
    }
    free(a->envs);

    free(a->nat_network_name);
    free(a->port_forwards);

    free(a);
}

int container_args_set_name(container_args args, const char *name)
{
    if (!args || !name) return -1;
    free(args->name);
    args->name = strdup(name);
    return args->name ? 0 : -1;
}

int container_args_set_image(container_args args, const char *ref)
{
    if (!args || !ref) return -1;
    free(args->image_ref);
    args->image_ref = strdup(ref);
    return args->image_ref ? 0 : -1;
}

int container_args_set_readonly(container_args args, bool readonly)
{
    if (!args) return -1;
    args->readonly = readonly;
    return 0;
}

int container_args_set_terminal_mode(container_args args, bool is_tty)
{
    if (!args) return -1;
    args->is_tty = is_tty;
    return 0;
}

int container_args_add_bind_mount(
    container_args args, const char *source, const char *destination, bool read_only)
{
    if (!args || !source || !destination) return -1;

    if (args->bind_mount_count >= args->bind_mount_cap)
    {
        size_t new_cap = args->bind_mount_cap ? args->bind_mount_cap * 2 : 4;
        bind_mount_entry *new_arr = realloc(args->bind_mounts, new_cap * sizeof(*new_arr));
        if (!new_arr) return -1;
        args->bind_mounts = new_arr;
        args->bind_mount_cap = new_cap;
    }

    bind_mount_entry *e = &args->bind_mounts[args->bind_mount_count];
    e->source = strdup(source);
    e->destination = strdup(destination);
    e->read_only = read_only;
    if (!e->source || !e->destination)
    {
        free(e->source);
        free(e->destination);
        return -1;
    }
    args->bind_mount_count++;
    return 0;
}

int container_args_add_tmpfs_mount(
    container_args args, const char *destination, size_t size_bytes)
{
    if (!args || !destination) return -1;

    if (args->tmpfs_mount_count >= args->tmpfs_mount_cap)
    {
        size_t new_cap = args->tmpfs_mount_cap ? args->tmpfs_mount_cap * 2 : 4;
        tmpfs_mount_entry *new_arr = realloc(args->tmpfs_mounts, new_cap * sizeof(*new_arr));
        if (!new_arr) return -1;
        args->tmpfs_mounts = new_arr;
        args->tmpfs_mount_cap = new_cap;
    }

    tmpfs_mount_entry *e = &args->tmpfs_mounts[args->tmpfs_mount_count];
    e->destination = strdup(destination);
    e->size_bytes = size_bytes;
    if (!e->destination) return -1;
    args->tmpfs_mount_count++;
    return 0;
}

int container_args_add_env(container_args args, const char *key, const char *value)
{
    if (!args || !key || !value) return -1;

    if (args->env_count >= args->env_cap)
    {
        size_t new_cap = args->env_cap ? args->env_cap * 2 : 4;
        env_entry *new_arr = realloc(args->envs, new_cap * sizeof(*new_arr));
        if (!new_arr) return -1;
        args->envs = new_arr;
        args->env_cap = new_cap;
    }

    env_entry *e = &args->envs[args->env_count];
    e->key = strdup(key);
    e->value = strdup(value);
    if (!e->key || !e->value)
    {
        free(e->key);
        free(e->value);
        return -1;
    }
    args->env_count++;
    return 0;
}

int container_args_set_restart_policy(container_args args, container_restart_policy policy)
{
    if (!args) return -1;
    args->restart_policy = policy;
    return 0;
}

int container_args_set_stop_timeout(container_args args, int timeout_ms)
{
    if (!args) return -1;
    args->stop_timeout_ms = timeout_ms;
    return 0;
}

int container_args_set_auto_remove(container_args args, bool auto_remove)
{
    if (!args) return -1;
    args->auto_remove = auto_remove;
    return 0;
}

int container_args_set_detached(container_args args, bool detached)
{
    if (!args) return -1;
    args->detached = detached;
    return 0;
}

int container_args_set_command(container_args args, size_t argc, const char *const *argv)
{
    if (!args || (argc > 0 && !argv)) return -1;

    /* free old command */
    for (size_t i = 0; i < args->command_count; i++)
        free(args->command[i]);
    free(args->command);

    if (argc == 0)
    {
        args->command = NULL;
        args->command_count = 0;
        return 0;
    }

    args->command = malloc(argc * sizeof(char *));
    if (!args->command) return -1;

    for (size_t i = 0; i < argc; i++)
    {
        args->command[i] = strdup(argv[i]);
        if (!args->command[i])
        {
            for (size_t j = 0; j < i; j++) free(args->command[j]);
            free(args->command);
            args->command = NULL;
            args->command_count = 0;
            return -1;
        }
    }
    args->command_count = argc;
    return 0;
}

const char *container_args_get_image(container_args args)
{
    return args ? args->image_ref : NULL;
}

bool container_args_get_detached(container_args args)
{
    return args ? args->detached : false;
}

int container_args_set_nat_network(container_args args, const char *nat_network_name)
{
    if (!args) return -1;
    free(args->nat_network_name);
    args->nat_network_name = nat_network_name ? strdup(nat_network_name) : NULL;
    if (nat_network_name && !args->nat_network_name) return -1;
    args->use_nat_network = true;
    return 0;
}

int container_args_add_port_forwarding(
    container_args args,
    struct in_addr host_ip, uint16_t host_port,
    uint16_t container_port,
    int protocol)
{
    if (!args) return -1;

    if (args->port_forward_count >= args->port_forward_cap)
    {
        size_t new_cap = args->port_forward_cap ? args->port_forward_cap * 2 : 4;
        port_forward_entry *new_arr = realloc(args->port_forwards, new_cap * sizeof(*new_arr));
        if (!new_arr) return -1;
        args->port_forwards = new_arr;
        args->port_forward_cap = new_cap;
    }

    port_forward_entry *e = &args->port_forwards[args->port_forward_count];
    e->host_ip = host_ip;
    e->host_port = host_port;
    e->container_port = container_port;
    e->protocol = protocol;
    args->port_forward_count++;
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  Overlay management                                                         */
/* -------------------------------------------------------------------------- */

static int mount_overlay(struct container_s *c)
{
    if (!c || c->readonly || !c->overlay_merged) return 0;
    if (c->overlay_mounted) return 0;

    char *opts = NULL;
    if (asprintf(&opts, "lowerdir=%s,upperdir=%s,workdir=%s",
                 c->overlay_lower, c->overlay_upper, c->overlay_work) < 0)
        return -1;

    int ret = mount("overlay", c->overlay_merged, "overlay", 0, opts);
    free(opts);

    if (ret != 0)
    {
        fprintf(stderr, "container_manager: failed to mount overlay at %s: %s\n",
                c->overlay_merged, strerror(errno));
        return -1;
    }

    c->overlay_mounted = true;
    return 0;
}

static void umount_overlay(struct container_s *c)
{
    if (!c || !c->overlay_mounted || !c->overlay_merged) return;

    if (umount(c->overlay_merged) != 0)
        fprintf(stderr, "container_manager: failed to umount overlay at %s: %s\n",
                c->overlay_merged, strerror(errno));
    else
        c->overlay_mounted = false;
}

/* -------------------------------------------------------------------------- */
/*  Network cleanup                                                            */
/* -------------------------------------------------------------------------- */

static void cleanup_network(struct container_s *c)
{
    if (!c->network) return;

    /* Remove port forwarders */
    for (size_t i = 0; i < c->port_forwarder_count; i++)
    {
        if (c->port_forwarders[i])
            port_forwarder_free(c->port_forwarders[i]);
    }
    free(c->port_forwarders);
    c->port_forwarders = NULL;
    c->port_forwarder_count = 0;

    /* Remove DNS lookup entries */
    if (c->network)
    {
        dns_forwarder fwd = nat_network_get_dns_forwarder(c->network);
        if (fwd)
        {
            if (c->dns_domain)
                dns_forwarder_remove_lookup(fwd, c->dns_domain);
            /* Also remove name-based DNS entry if different from id-based */
            if (c->name && strcmp(c->name, c->id) != 0)
            {
                char *name_domain = NULL;
                if (asprintf(&name_domain, "tcr-%s", c->name) >= 0)
                {
                    dns_forwarder_remove_lookup(fwd, name_domain);
                    free(name_domain);
                }
            }
        }
    }

    /* Remove /etc/hosts entry */
    if (c->id)
        remove_hosts_entry(c->id);

    /* Remove network namespace */
    if (c->netns_name)
        nat_network_remove_network_namespace(c->network, c->netns_name);

    /* Release IP */
    if (c->has_ip)
    {
        nat_network_release_ip(c->network, c->allocated_ip);
        c->has_ip = false;
    }

    /* Release reference to the nat_network (and possibly remove it) */
    if (c->nat_network_name &&
        strcmp(c->nat_network_name, NAT_NETWORK_MANAGER_DEFAULT_NAME) != 0)
    {
        /* Check if any other container uses this network */
        int ref = 0;
        struct list_head *pos;
        list_for_each(pos, &c->manager->containers)
        {
            struct container_s *other = list_entry(pos, struct container_s, list);
            if (other != c && other->nat_network_name &&
                strcmp(other->nat_network_name, c->nat_network_name) == 0)
                ref++;
        }
        if (ref == 0)
            nat_network_remove_network(c->manager->nat_manager, c->nat_network_name);
    }

    c->network = NULL;
}

/* -------------------------------------------------------------------------- */
/*  Process monitoring via pidfd                                               */
/* -------------------------------------------------------------------------- */

static int setup_process_monitor(struct container_s *c, pid_t pid)
{
    c->pid = pid;
    c->state = CONTAINER_STATE_RUNNING;

    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0)
    {
        fprintf(stderr, "container_manager: pidfd_open(%d) failed: %s\n",
                pid, strerror(errno));
        return -1;
    }
    c->pidfd = pidfd;

    if (tev_set_read_handler(c->manager->tev, pidfd, on_process_exit, c) != 0)
    {
        fprintf(stderr, "container_manager: failed to set read handler for pidfd\n");
        close(pidfd);
        c->pidfd = -1;
        return -1;
    }

    return 0;
}

static void cleanup_process_monitor(struct container_s *c)
{
    if (c->stop_timer)
    {
        tev_clear_timeout(c->manager->tev, c->stop_timer);
        c->stop_timer = NULL;
    }

    if (c->pidfd >= 0)
    {
        tev_set_read_handler(c->manager->tev, c->pidfd, NULL, NULL);
        close(c->pidfd);
        c->pidfd = -1;
    }
}

/**
 * Called when a monitored process exits (pidfd becomes readable).
 */
static void on_process_exit(void *ctx)
{
    struct container_s *c = ctx;

    /* Reap the child */
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    if (waitid(P_PIDFD, (id_t)c->pidfd, &info, WEXITED | WNOHANG) == 0 && info.si_pid != 0)
    {
        fprintf(stderr, "container_manager: container '%s' (pid %d) exited with status %d\n",
                c->id, c->pid, info.si_status);
    }
    else
    {
        fprintf(stderr, "container_manager: container '%s' (pid %d) exited\n",
                c->id, c->pid);
    }

    cleanup_process_monitor(c);
    c->state = CONTAINER_STATE_STOPPED;
    c->pid = -1;

    /* Unmount overlay */
    umount_overlay(c);

    /* Handle restart policy (only for detached containers) */
    if (c->detached && c->restart_policy != CONTAINER_RESTART_POLICY_NEVER &&
        !(c->explicitly_stopped &&
          c->restart_policy == CONTAINER_RESTART_POLICY_UNLESS_STOPPED))
    {
        c->explicitly_stopped = false;
        /* re-start the container */
        fprintf(stderr, "container_manager: restarting container '%s' per restart policy\n",
                c->id);
        if (container_start(c) != 0)
        {
            fprintf(stderr, "container_manager: failed to restart container '%s'\n", c->id);
            /* For restart policy failures, we don't auto-remove — keep trying via timeout */
        }
        return;
    }

    /* Auto-remove if configured */
    if (c->auto_remove)
    {
        fprintf(stderr, "container_manager: auto-removing container '%s'\n", c->id);
        container_remove(c);
        return;
    }
}

/**
 * Called when the graceful stop timeout expires — send SIGKILL.
 */
static void on_stop_timeout(void *ctx)
{
    struct container_s *c = ctx;
    c->stop_timer = NULL;

    if (c->state != CONTAINER_STATE_RUNNING || c->pid <= 0) return;

    fprintf(stderr, "container_manager: container '%s' did not stop gracefully, sending SIGKILL\n",
            c->id);
    kill(c->pid, SIGKILL);
}

/* -------------------------------------------------------------------------- */
/*  Container restoration on startup                                           */
/* -------------------------------------------------------------------------- */

/**
 * Attempt to restore a single container from its meta.json.
 * Only restores detached containers with a restart policy != NEVER.
 * Returns a started container_s on success, NULL on skip or failure.
 */
static struct container_s *restore_container(
    struct container_manager_s *mgr, const char *container_dir)
{
    char *meta_path = path_join(container_dir, META_FILENAME);
    if (!meta_path) return NULL;

    char *meta_str = read_file_to_string(meta_path);
    free(meta_path);
    if (!meta_str) return NULL;

    cJSON *meta = cJSON_Parse(meta_str);
    free(meta_str);
    if (!meta) return NULL;

    /* Check if this container should be restored */
    cJSON *j_detached = cJSON_GetObjectItemCaseSensitive(meta, JKEY_DETACHED);
    cJSON *j_policy   = cJSON_GetObjectItemCaseSensitive(meta, JKEY_RESTART_POLICY);

    if (!cJSON_IsBool(j_detached) || !cJSON_IsTrue(j_detached) ||
        !cJSON_IsNumber(j_policy) ||
        (int)j_policy->valuedouble == CONTAINER_RESTART_POLICY_NEVER)
    {
        cJSON_Delete(meta);
        return NULL;
    }

    /* UNLESS_STOPPED: do not restore if the user explicitly stopped it */
    cJSON *j_stopped = cJSON_GetObjectItemCaseSensitive(meta, JKEY_EXPLICITLY_STOPPED);
    if ((int)j_policy->valuedouble == CONTAINER_RESTART_POLICY_UNLESS_STOPPED &&
        cJSON_IsBool(j_stopped) && cJSON_IsTrue(j_stopped))
    {
        cJSON_Delete(meta);
        return NULL;
    }

    /* Extract fields */
    cJSON *j_id         = cJSON_GetObjectItemCaseSensitive(meta, JKEY_ID);
    cJSON *j_name       = cJSON_GetObjectItemCaseSensitive(meta, JKEY_NAME);
    cJSON *j_auto_rm    = cJSON_GetObjectItemCaseSensitive(meta, JKEY_AUTO_REMOVE);
    cJSON *j_readonly   = cJSON_GetObjectItemCaseSensitive(meta, JKEY_READONLY);
    cJSON *j_timeout    = cJSON_GetObjectItemCaseSensitive(meta, JKEY_STOP_TIMEOUT_MS);
    cJSON *j_bundle     = cJSON_GetObjectItemCaseSensitive(meta, JKEY_BUNDLE_PATH);
    cJSON *j_image_id   = cJSON_GetObjectItemCaseSensitive(meta, JKEY_IMAGE_ID);
    cJSON *j_net_name   = cJSON_GetObjectItemCaseSensitive(meta, JKEY_NAT_NETWORK_NAME);
    cJSON *j_netns      = cJSON_GetObjectItemCaseSensitive(meta, JKEY_NETNS_NAME);
    cJSON *j_alloc_ip   = cJSON_GetObjectItemCaseSensitive(meta, JKEY_ALLOCATED_IP);
    cJSON *j_pf_arr     = cJSON_GetObjectItemCaseSensitive(meta, JKEY_PORT_FORWARDS);

    if (!cJSON_IsString(j_id) || !cJSON_IsString(j_name) || !cJSON_IsString(j_image_id))
    {
        cJSON_Delete(meta);
        return NULL;
    }

    /* Find and mount image */
    image img = image_manager_find_by_id(mgr->img_manager, j_image_id->valuestring);
    if (!img)
    {
        fprintf(stderr, "container_manager: restore '%s': image with id '%s' not found\n",
                j_id->valuestring, j_image_id->valuestring);
        cJSON_Delete(meta);
        return NULL;
    }
    if (!image_get_mounted(img))
    {
        if (image_manager_mount_image(mgr->img_manager, img) != 0)
        {
            fprintf(stderr, "container_manager: restore '%s': failed to mount image\n",
                    j_id->valuestring);
            cJSON_Delete(meta);
            return NULL;
        }
    }

    /* Allocate container */
    struct container_s *c = calloc(1, sizeof(*c));
    if (!c) { cJSON_Delete(meta); return NULL; }

    c->pidfd = -1;
    c->pid = -1;
    c->state = CONTAINER_STATE_CREATED;
    c->manager = mgr;
    c->img = img;

    c->id = strdup(j_id->valuestring);
    c->name = strdup(j_name->valuestring);
    if (!c->id || !c->name) goto restore_fail;

    c->detached = true;
    c->auto_remove = cJSON_IsTrue(j_auto_rm);
    c->readonly = cJSON_IsTrue(j_readonly);
    c->restart_policy = (container_restart_policy)(int)j_policy->valuedouble;
    c->stop_timeout_ms = cJSON_IsNumber(j_timeout) ? (int)j_timeout->valuedouble
                                                    : DEFAULT_STOP_TIMEOUT_MS;

    c->container_dir = strdup(container_dir);
    if (!c->container_dir) goto restore_fail;

    c->config_path = path_join(c->container_dir, CONFIG_FILENAME);
    if (!c->config_path) goto restore_fail;

    /* bundle_path: prefer the one from meta, fall back to image bundle */
    if (cJSON_IsString(j_bundle))
        c->bundle_path = strdup(j_bundle->valuestring);
    else
        c->bundle_path = strdup(image_get_bundle_path(img));
    if (!c->bundle_path) goto restore_fail;

    /* Setup overlay paths (dirs already exist on disk from original creation) */
    if (!c->readonly)
    {
        char *overlay_dir = path_join(c->container_dir, "overlay");
        if (!overlay_dir) goto restore_fail;

        c->overlay_upper = path_join(overlay_dir, "upper");
        c->overlay_work = path_join(overlay_dir, "work");
        c->overlay_merged = path_join(overlay_dir, "merged");

        char *rootfs_path = path_join(c->bundle_path, "rootfs");
        c->overlay_lower = rootfs_path;

        free(overlay_dir);

        if (!c->overlay_upper || !c->overlay_work ||
            !c->overlay_merged || !c->overlay_lower)
            goto restore_fail;
    }

    /* Restore networking */
    if (cJSON_IsString(j_net_name) && mgr->nat_manager)
    {
        nat_network net = nat_network_manager_get_network(mgr->nat_manager,
                                                          j_net_name->valuestring);
        if (!net)
        {
            fprintf(stderr, "container_manager: restore '%s': network '%s' not available\n",
                    c->id, j_net_name->valuestring);
            goto restore_fail;
        }
        c->network = net;
        c->nat_network_name = strdup(j_net_name->valuestring);
        if (!c->nat_network_name) goto restore_fail;

        /* Reserve IP */
        if (cJSON_IsString(j_alloc_ip))
        {
            if (inet_pton(AF_INET, j_alloc_ip->valuestring, &c->allocated_ip) == 1)
            {
                if (nat_network_reserve_ip(net, c->allocated_ip) != 0)
                {
                    fprintf(stderr, "container_manager: restore '%s': failed to reserve IP %s\n",
                            c->id, j_alloc_ip->valuestring);
                    goto restore_fail;
                }
                c->has_ip = true;
            }
        }

        /* Recreate network namespace */
        if (cJSON_IsString(j_netns))
        {
            c->netns_name = strdup(j_netns->valuestring);
            if (!c->netns_name) goto restore_fail;

            if (nat_network_create_network_namespace(net, c->netns_name,
                                                     c->allocated_ip) != 0)
            {
                fprintf(stderr, "container_manager: restore '%s': failed to create netns '%s'\n",
                        c->id, c->netns_name);
                goto restore_fail;
            }
        }

        /* Regenerate resolv.conf */
        struct in_addr gateway;
        if (nat_network_get_gateway(net, &gateway) == 0)
        {
            char gw_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &gateway, gw_str, sizeof(gw_str));

            char *resolv_content = NULL;
            if (asprintf(&resolv_content, "nameserver %s\n", gw_str) >= 0)
            {
                c->resolv_conf_path = path_join(c->container_dir, RESOLV_CONF_FILE);
                if (c->resolv_conf_path)
                    write_string_to_file(c->resolv_conf_path, resolv_content);
                free(resolv_content);
            }
        }

        /* Register DNS entries */
        dns_forwarder dns = nat_network_get_dns_forwarder(net);
        if (dns && c->has_ip)
        {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &c->allocated_ip, ip_str, sizeof(ip_str));
            if (asprintf(&c->dns_domain, "tcr-%s", c->id) >= 0)
                dns_forwarder_add_lookup(dns, c->dns_domain, ip_str);
            /* Also register by container name if different from id */
            if (c->name && strcmp(c->name, c->id) != 0)
            {
                char *name_domain = NULL;
                if (asprintf(&name_domain, "tcr-%s", c->name) >= 0)
                {
                    dns_forwarder_add_lookup(dns, name_domain, ip_str);
                    free(name_domain);
                }
            }
        }

        /* Add /etc/hosts entry for host-local DNS resolution */
        if (c->has_ip)
        {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &c->allocated_ip, ip_str, sizeof(ip_str));
            add_hosts_entry(c->id, c->name, ip_str);
        }

        /* Restore port forwarders */
        if (cJSON_IsArray(j_pf_arr))
        {
            int pf_count = cJSON_GetArraySize(j_pf_arr);
            if (pf_count > 0)
            {
                const char *table_name = nat_network_get_name(net);

                c->port_forwarders = calloc((size_t)pf_count, sizeof(port_forwarder));
                c->port_forward_specs = calloc((size_t)pf_count, sizeof(port_forward_entry));
                if (!c->port_forwarders || !c->port_forward_specs) goto restore_fail;

                for (int i = 0; i < pf_count; i++)
                {
                    cJSON *pf_item = cJSON_GetArrayItem(j_pf_arr, i);
                    cJSON *j_hip = cJSON_GetObjectItemCaseSensitive(pf_item, JKEY_HOST_IP);
                    cJSON *j_hp  = cJSON_GetObjectItemCaseSensitive(pf_item, JKEY_HOST_PORT);
                    cJSON *j_cp  = cJSON_GetObjectItemCaseSensitive(pf_item, JKEY_CONTAINER_PORT);
                    cJSON *j_pr  = cJSON_GetObjectItemCaseSensitive(pf_item, JKEY_PROTOCOL);

                    if (!cJSON_IsString(j_hip) || !cJSON_IsNumber(j_hp) ||
                        !cJSON_IsNumber(j_cp) || !cJSON_IsNumber(j_pr))
                        continue;

                    port_forward_entry pfe;
                    inet_pton(AF_INET, j_hip->valuestring, &pfe.host_ip);
                    pfe.host_port = (uint16_t)j_hp->valuedouble;
                    pfe.container_port = (uint16_t)j_cp->valuedouble;
                    pfe.protocol = (int)j_pr->valuedouble;

                    port_forwarder fwd = port_forwarder_new(
                        table_name, c->id,
                        pfe.host_ip, pfe.host_port,
                        c->allocated_ip, pfe.container_port,
                        pfe.protocol);
                    /* non-fatal if port forward fails */

                    c->port_forwarders[c->port_forwarder_count++] = fwd;
                    c->port_forward_specs[c->port_forward_spec_count++] = pfe;
                }
            }
        }
    }

    cJSON_Delete(meta);

    /* Start the container */
    list_add_tail(&c->list, &mgr->containers);
    if (container_start(c) != 0)
    {
        fprintf(stderr, "container_manager: restore '%s': failed to start\n", c->id);
        list_del(&c->list);
        cleanup_network(c);
        container_free_internal(c);
        return NULL;
    }

    fprintf(stderr, "container_manager: restored and started container '%s' (name='%s')\n",
            c->id, c->name);
    return c;

restore_fail:
    cJSON_Delete(meta);
    cleanup_network(c);
    container_free_internal(c);
    return NULL;
}

/**
 * Scan the containers directory and restore all eligible containers.
 */
static void restore_containers(struct container_manager_s *mgr)
{
    DIR *dir = opendir(mgr->containers_dir);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL)
    {
        if (ent->d_name[0] == '.') continue;

        char *container_dir = path_join(mgr->containers_dir, ent->d_name);
        if (!container_dir) continue;

        /* Check if it's a directory with a meta.json */
        struct stat st;
        if (stat(container_dir, &st) != 0 || !S_ISDIR(st.st_mode))
        {
            free(container_dir);
            continue;
        }

        restore_container(mgr, container_dir);
        free(container_dir);
    }

    closedir(dir);
}

/* -------------------------------------------------------------------------- */
/*  container_manager API                                                      */
/* -------------------------------------------------------------------------- */

container_manager container_manager_new(
    tev_handle_t tev,
    image_manager img_manager,
    nat_network_manager nat_manager,
    const char *root_path)
{
    if (!tev || !img_manager || !root_path) return NULL;

    struct container_manager_s *mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    mgr->tev = tev;
    mgr->img_manager = img_manager;
    mgr->nat_manager = nat_manager;

    char resolved[PATH_MAX];
    if (realpath(root_path, resolved))
        mgr->root_path = strdup(resolved);
    else
        mgr->root_path = strdup(root_path);
    if (!mgr->root_path) goto fail;

    mgr->containers_dir = path_join(mgr->root_path, CONTAINERS_DIRNAME);
    if (!mgr->containers_dir) goto fail;

    if (mkdir_p(mgr->root_path) != 0 || mkdir_p(mgr->containers_dir) != 0) goto fail;

    list_head_init(&mgr->containers);

    /* Restore containers with restart policies from previous run */
    restore_containers(mgr);

    return mgr;

fail:
    free(mgr->containers_dir);
    free(mgr->root_path);
    free(mgr);
    return NULL;
}

/**
 * Kill all detached containers immediately on manager teardown.
 */
static void kill_all_detached(struct container_manager_s *mgr)
{
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &mgr->containers)
    {
        struct container_s *c = list_entry(pos, struct container_s, list);
        if (c->detached && c->state == CONTAINER_STATE_RUNNING && c->pid > 0)
        {
            fprintf(stderr, "container_manager: killing detached container '%s' (pid %d)\n",
                    c->id, c->pid);
            kill(c->pid, SIGKILL);
            waitpid(c->pid, NULL, 0);
            c->state = CONTAINER_STATE_STOPPED;
            c->pid = -1;
        }
    }
}

void container_manager_free(container_manager manager)
{
    if (!manager) return;
    struct container_manager_s *mgr = manager;

    /* Kill all detached containers */
    kill_all_detached(mgr);

    /* Free all containers */
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &mgr->containers)
    {
        struct container_s *c = list_entry(pos, struct container_s, list);
        list_del(&c->list);
        cleanup_process_monitor(c);
        umount_overlay(c);
        cleanup_network(c);
        container_free_internal(c);
    }

    free(mgr->containers_dir);
    free(mgr->root_path);
    free(mgr);
}

int container_manager_get_image_ref_count(container_manager manager, image img)
{
    if (!manager || !img) return 0;
    struct container_manager_s *mgr = manager;

    int count = 0;
    struct list_head *pos;
    list_for_each(pos, &mgr->containers)
    {
        struct container_s *c = list_entry(pos, struct container_s, list);
        if (c->img == img) count++;
    }
    return count;
}

int container_manager_get_network_ref_count(container_manager manager, nat_network net)
{
    if (!manager || !net) return 0;
    struct container_manager_s *mgr = manager;

    int count = 0;
    struct list_head *pos;
    list_for_each(pos, &mgr->containers)
    {
        struct container_s *c = list_entry(pos, struct container_s, list);
        if (c->network == net) count++;
    }
    return count;
}

/* -------------------------------------------------------------------------- */
/*  container_manager_create_container                                         */
/* -------------------------------------------------------------------------- */

container container_manager_create_container(
    container_manager manager,
    container_args args)
{
    if (!manager || !args) return NULL;
    struct container_manager_s *mgr = manager;
    struct container_args_s *a = args;

    /* ── Resolve image ── */
    image img = NULL;
    if (a->image_ref)
        img = image_manager_find_by_id_or_name(mgr->img_manager, a->image_ref);
    else
    {
        fprintf(stderr, "container_manager: no image specified\n");
        return NULL;
    }

    if (!img)
    {
        fprintf(stderr, "container_manager: image not found\n");
        return NULL;
    }

    /* Ensure image is mounted */
    if (!image_get_mounted(img))
    {
        if (image_manager_mount_image(mgr->img_manager, img) != 0)
        {
            fprintf(stderr, "container_manager: failed to mount image\n");
            return NULL;
        }
    }

    const char *bundle_path = image_get_bundle_path(img);
    if (!bundle_path)
    {
        fprintf(stderr, "container_manager: image has no bundle path\n");
        return NULL;
    }

    /* ── Generate ID and create container dir ── */
    char *id = generate_container_id();
    if (!id) return NULL;

    struct container_s *c = calloc(1, sizeof(*c));
    if (!c) { free(id); return NULL; }

    c->id = id;
    c->pidfd = -1;
    c->pid = -1;
    c->state = CONTAINER_STATE_CREATED;
    c->manager = mgr;
    c->img = img;

    c->name = strdup(a->name ? a->name : id);
    if (!c->name) goto fail;

    c->detached = a->detached;
    c->auto_remove = a->auto_remove;
    c->readonly = a->readonly;
    c->restart_policy = a->restart_policy;
    c->stop_timeout_ms = a->stop_timeout_ms;

    c->container_dir = path_join(mgr->containers_dir, id);
    if (!c->container_dir) goto fail;

    c->config_path = path_join(c->container_dir, CONFIG_FILENAME);
    if (!c->config_path) goto fail;

    c->bundle_path = strdup(bundle_path);
    if (!c->bundle_path) goto fail;

    if (mkdir_p(c->container_dir) != 0)
    {
        fprintf(stderr, "container_manager: failed to create container dir: %s\n",
                strerror(errno));
        goto fail;
    }

    /* ── Build crun config ── */
    cJSON *config = crun_config_create(bundle_path);
    if (!config)
    {
        fprintf(stderr, "container_manager: failed to create crun config\n");
        goto fail;
    }

    /* rootfs + readonly */
    if (a->readonly)
    {
        crun_config_set_readonly(config, true);
    }
    else
    {
        /* Setup overlay directories */
        char *overlay_dir = path_join(c->container_dir, "overlay");
        if (!overlay_dir) { cJSON_Delete(config); goto fail; }

        c->overlay_upper = path_join(overlay_dir, "upper");
        c->overlay_work = path_join(overlay_dir, "work");
        c->overlay_merged = path_join(overlay_dir, "merged");

        char *rootfs_path = path_join(bundle_path, "rootfs");
        c->overlay_lower = rootfs_path;

        if (!c->overlay_upper || !c->overlay_work || !c->overlay_merged || !c->overlay_lower)
        {
            free(overlay_dir);
            cJSON_Delete(config);
            goto fail;
        }

        if (mkdir_p(overlay_dir) != 0 ||
            mkdir_p(c->overlay_upper) != 0 || mkdir_p(c->overlay_work) != 0 ||
            mkdir_p(c->overlay_merged) != 0)
        {
            fprintf(stderr, "container_manager: failed to create overlay dirs: %s\n",
                    strerror(errno));
            free(overlay_dir);
            cJSON_Delete(config);
            goto fail;
        }

        free(overlay_dir);

        crun_config_set_readonly(config, false);
        crun_config_set_rootfs(config, c->overlay_merged);
    }

    /* Terminal mode */
    crun_config_set_terminal_mode(config, a->is_tty);

    /* Command override */
    if (a->command_count > 0)
        crun_config_set_args(config, a->command_count, (const char *const *)a->command);

    /* Bind mounts */
    for (size_t i = 0; i < a->bind_mount_count; i++)
    {
        crun_config_add_bind_mount(config,
                                   a->bind_mounts[i].source,
                                   a->bind_mounts[i].destination,
                                   a->bind_mounts[i].read_only);
    }

    /* Tmpfs mounts */
    for (size_t i = 0; i < a->tmpfs_mount_count; i++)
    {
        crun_config_add_tmpfs_mount(config,
                                    a->tmpfs_mounts[i].destination,
                                    a->tmpfs_mounts[i].size_bytes);
    }

    /* Environment variables */
    for (size_t i = 0; i < a->env_count; i++)
        crun_config_add_env(config, a->envs[i].key, a->envs[i].value);

    /* ── Network setup ── */
    if (a->use_nat_network && mgr->nat_manager)
    {
        const char *net_name = a->nat_network_name ? a->nat_network_name
                                                   : NAT_NETWORK_MANAGER_DEFAULT_NAME;

        nat_network net = nat_network_manager_get_network(mgr->nat_manager, net_name);
        if (!net)
        {
            fprintf(stderr, "container_manager: failed to get NAT network '%s'\n", net_name);
            cJSON_Delete(config);
            goto fail;
        }

        c->network = net;
        c->nat_network_name = strdup(net_name);
        if (!c->nat_network_name) { cJSON_Delete(config); goto fail; }

        /* Allocate IP */
        if (nat_network_allocate_ip(net, &c->allocated_ip) != 0)
        {
            fprintf(stderr, "container_manager: failed to allocate IP from network '%s'\n",
                    net_name);
            cJSON_Delete(config);
            goto fail;
        }
        c->has_ip = true;

        /* Create network namespace */
        if (asprintf(&c->netns_name, "tcr-%s", c->id) < 0)
        {
            c->netns_name = NULL;
            cJSON_Delete(config);
            goto fail;
        }

        if (nat_network_create_network_namespace(net, c->netns_name, c->allocated_ip) != 0)
        {
            fprintf(stderr, "container_manager: failed to create netns '%s'\n", c->netns_name);
            cJSON_Delete(config);
            goto fail;
        }

        /* Set network namespace in config */
        char *netns_path = NULL;
        if (asprintf(&netns_path, "/var/run/netns/%s", c->netns_name) < 0)
        {
            cJSON_Delete(config);
            goto fail;
        }
        crun_config_set_network_ns(config, netns_path);
        free(netns_path);

        /* Generate resolv.conf with gateway as nameserver */
        struct in_addr gateway;
        if (nat_network_get_gateway(net, &gateway) == 0)
        {
            char gw_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &gateway, gw_str, sizeof(gw_str));

            char *resolv_content = NULL;
            if (asprintf(&resolv_content, "nameserver %s\n", gw_str) >= 0)
            {
                c->resolv_conf_path = path_join(c->container_dir, RESOLV_CONF_FILE);
                if (c->resolv_conf_path)
                {
                    write_string_to_file(c->resolv_conf_path, resolv_content);
                    crun_config_add_bind_mount(config,
                                               c->resolv_conf_path,
                                               "/etc/resolv.conf",
                                               true);
                }
                free(resolv_content);
            }
        }

        /* Register DNS lookup entries */
        {
            dns_forwarder fwd = nat_network_get_dns_forwarder(net);
            if (fwd)
            {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &c->allocated_ip, ip_str, sizeof(ip_str));
                if (asprintf(&c->dns_domain, "tcr-%s", c->id) >= 0)
                    dns_forwarder_add_lookup(fwd, c->dns_domain, ip_str);
                /* Also register by container name if different from id */
                if (c->name && strcmp(c->name, c->id) != 0)
                {
                    char *name_domain = NULL;
                    if (asprintf(&name_domain, "tcr-%s", c->name) >= 0)
                    {
                        dns_forwarder_add_lookup(fwd, name_domain, ip_str);
                        free(name_domain);
                    }
                }
            }
        }

        /* Add /etc/hosts entry for host-local DNS resolution */
        {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &c->allocated_ip, ip_str, sizeof(ip_str));
            add_hosts_entry(c->id, c->name, ip_str);
        }

        /* Port forwarding */
        if (a->port_forward_count > 0)
        {
            const char *table_name = nat_network_get_name(net);

            c->port_forwarders = calloc(a->port_forward_count, sizeof(port_forwarder));
            if (!c->port_forwarders) { cJSON_Delete(config); goto fail; }

            c->port_forward_specs = calloc(a->port_forward_count, sizeof(port_forward_entry));
            if (!c->port_forward_specs) { cJSON_Delete(config); goto fail; }

            for (size_t i = 0; i < a->port_forward_count; i++)
            {
                port_forward_entry *pf = &a->port_forwards[i];
                port_forwarder fwd = port_forwarder_new(
                    table_name, c->id,
                    pf->host_ip, pf->host_port,
                    c->allocated_ip, pf->container_port,
                    pf->protocol);
                if (!fwd)
                {
                    fprintf(stderr, "container_manager: failed to create port forwarder "
                            "(%d -> %d)\n", pf->host_port, pf->container_port);
                    /* non-fatal: continue without this port forward */
                }
                c->port_forwarders[c->port_forwarder_count++] = fwd;
                c->port_forward_specs[c->port_forward_spec_count++] = *pf;
            }
        }
    }

    /* ── Write config.json ── */
    char *config_str = cJSON_Print(config);
    cJSON_Delete(config);
    if (!config_str) goto fail;

    if (write_string_to_file(c->config_path, config_str) != 0)
    {
        fprintf(stderr, "container_manager: failed to write config.json\n");
        free(config_str);
        goto fail;
    }
    free(config_str);

    /* Write meta.json for restart persistence */
    if (write_container_meta(c) != 0)
    {
        fprintf(stderr, "container_manager: failed to write meta.json\n");
        goto fail;
    }

    /* Add to manager list */
    list_add_tail(&c->list, &mgr->containers);

    fprintf(stderr, "container_manager: created container '%s' (name='%s')\n",
            c->id, c->name);
    return c;

fail:
    /* Cleanup partially created container */
    cleanup_network(c);
    if (c->container_dir) rmdir_recursive(c->container_dir);
    container_free_internal(c);
    return NULL;
}

/* -------------------------------------------------------------------------- */
/*  container_start (detached mode)                                            */
/* -------------------------------------------------------------------------- */

int container_start(container c)
{
    if (!c) return -1;

    if (!c->detached)
    {
        fprintf(stderr, "container_manager: container '%s' is not in detached mode, "
                "use container_get_crun_args instead\n", c->id);
        return -1;
    }

    if (c->state == CONTAINER_STATE_RUNNING)
    {
        fprintf(stderr, "container_manager: container '%s' is already running\n", c->id);
        return -1;
    }

    /* Mount overlay if needed */
    if (mount_overlay(c) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "container_manager: fork failed: %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0)
    {
        /* ── Child process ── */

        /* If daemon dies, kernel sends SIGKILL to this child */
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        /*
         * prctl(PR_SET_PDEATHSIG) has a race: if the parent already died
         * between fork() and prctl(), the death signal is never delivered.
         * Detect this by checking if getppid() changed to 1 (init).
         * We saved the parent PID before fork().
         */
        if (getppid() == 1)
            _exit(1);

        /* Redirect stdin/stdout/stderr to /dev/null for detached mode */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0)
        {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }

        execlp("crun", "crun", "run",
               "--bundle", c->bundle_path,
               "--config", c->config_path,
               c->id,
               (char *)NULL);

        _exit(127);
    }

    /* ── Parent process ── */
    if (setup_process_monitor(c, pid) != 0)
    {
        /* If we can't monitor, kill the child */
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return -1;
    }

    fprintf(stderr, "container_manager: started detached container '%s' (pid %d)\n",
            c->id, pid);
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  container_get_crun_args (interactive mode)                                 */
/* -------------------------------------------------------------------------- */

int container_get_crun_args(container c, char ***out_argv, size_t *out_argc)
{
    if (!c || !out_argv || !out_argc) return -1;

    if (c->state == CONTAINER_STATE_RUNNING)
    {
        fprintf(stderr, "container_manager: container '%s' is already running\n", c->id);
        return -1;
    }

    if (c->restart_policy != CONTAINER_RESTART_POLICY_NEVER)
    {
        fprintf(stderr, "container_manager: container '%s' has restart policy set, "
                "cannot use interactive mode\n", c->id);
        return -1;
    }

    /* Mount overlay if needed */
    if (mount_overlay(c) != 0) return -1;

    /* Build argv: crun run --bundle <bundle> --config <config> <id> */
    size_t argc = 7;
    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv) return -1;

    argv[0] = strdup("crun");
    argv[1] = strdup("run");
    argv[2] = strdup("--bundle");
    argv[3] = strdup(c->bundle_path);
    argv[4] = strdup("--config");
    argv[5] = strdup(c->config_path);
    argv[6] = strdup(c->id);

    for (size_t i = 0; i < argc; i++)
    {
        if (!argv[i])
        {
            for (size_t j = 0; j < argc; j++) free(argv[j]);
            free(argv);
            return -1;
        }
    }

    *out_argv = argv;
    *out_argc = argc;
    return 0;
}

void container_free_crun_args(char **argv, size_t argc)
{
    if (!argv) return;
    for (size_t i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);
}

/* -------------------------------------------------------------------------- */
/*  container_get_exec_args                                                    */
/* -------------------------------------------------------------------------- */

int container_get_exec_args(container c,
                            bool detach, bool tty,
                            const char **env, size_t env_count,
                            const char **cmd, size_t cmd_count,
                            char ***out_argv, size_t *out_argc)
{
    if (!c || !out_argv || !out_argc || cmd_count == 0 || !cmd) return -1;

    if (c->state != CONTAINER_STATE_RUNNING)
    {
        fprintf(stderr, "container_manager: container '%s' is not running\n", c->id);
        return -1;
    }

    /* Calculate argc: "crun" "exec" [flags] <id> <cmd...> */
    size_t argc = 2; /* crun exec */
    if (detach) argc++;                  /* -d */
    if (tty) argc++;                     /* -t */
    argc += env_count * 2;               /* -e KEY=VALUE for each */
    argc++;                              /* container id */
    argc += cmd_count;                   /* command + args */

    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv) return -1;

    size_t i = 0;
    argv[i++] = strdup("crun");
    argv[i++] = strdup("exec");

    if (detach)
        argv[i++] = strdup("-d");
    if (tty)
        argv[i++] = strdup("-t");

    for (size_t e = 0; e < env_count; e++)
    {
        argv[i++] = strdup("-e");
        argv[i++] = strdup(env[e]);
    }

    argv[i++] = strdup(c->id);

    for (size_t j = 0; j < cmd_count; j++)
        argv[i++] = strdup(cmd[j]);

    /* Check for allocation failures */
    for (size_t k = 0; k < argc; k++)
    {
        if (!argv[k])
        {
            for (size_t m = 0; m < argc; m++) free(argv[m]);
            free(argv);
            return -1;
        }
    }

    *out_argv = argv;
    *out_argc = argc;
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  container_monitor_process (interactive mode)                               */
/* -------------------------------------------------------------------------- */

int container_monitor_process(container c, int pid)
{
    if (!c) return -1;

    if (c->state == CONTAINER_STATE_RUNNING)
    {
        fprintf(stderr, "container_manager: container '%s' is already running\n", c->id);
        return -1;
    }

    return setup_process_monitor(c, (pid_t)pid);
}

/* -------------------------------------------------------------------------- */
/*  container_stop                                                             */
/* -------------------------------------------------------------------------- */

int container_stop(container c, bool immediately)
{
    if (!c) return -1;

    if (c->state != CONTAINER_STATE_RUNNING || c->pid <= 0)
        return 0; /* nothing to stop */

    /* Mark as explicitly stopped so UNLESS_STOPPED won't restart */
    c->explicitly_stopped = true;

    /* Persist the flag so a daemon crash won't resurrect this container */
    write_container_meta(c);

    if (immediately)
    {
        /* Suppress restart so on_process_exit won't re-launch */
        c->restart_policy = CONTAINER_RESTART_POLICY_NEVER;
        kill(c->pid, SIGKILL);

        /* Synchronously wait for the child */
        cleanup_process_monitor(c);
        waitpid(c->pid, NULL, 0);
        c->pid = -1;
        c->state = CONTAINER_STATE_STOPPED;
        umount_overlay(c);
    }
    else
    {
        /* Send SIGTERM first */
        kill(c->pid, SIGTERM);

        /* Set a timer for forceful kill */
        if (!c->stop_timer)
        {
            c->stop_timer = tev_set_timeout(c->manager->tev,
                                             on_stop_timeout, c,
                                             c->stop_timeout_ms);
        }
    }

    return 0;
}

/* -------------------------------------------------------------------------- */
/*  container_remove                                                           */
/* -------------------------------------------------------------------------- */

int container_remove(container c)
{
    if (!c) return -1;

    /* Force stop if running */
    if (c->state == CONTAINER_STATE_RUNNING)
    {
        c->restart_policy = CONTAINER_RESTART_POLICY_NEVER;
        if (c->pid > 0) kill(c->pid, SIGKILL);

        /* Synchronously wait for the child */
        if (c->pid > 0)
        {
            cleanup_process_monitor(c);
            waitpid(c->pid, NULL, 0);
            c->pid = -1;
            c->state = CONTAINER_STATE_STOPPED;
        }
    }

    cleanup_process_monitor(c);
    umount_overlay(c);
    cleanup_network(c);

    /* Remove from list */
    list_del(&c->list);

    /* Remove container directory */
    if (c->container_dir)
        rmdir_recursive(c->container_dir);

    fprintf(stderr, "container_manager: removed container '%s'\n", c->id);
    container_free_internal(c);
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  Query & getter functions                                                   */
/* -------------------------------------------------------------------------- */

container container_manager_find_container(
    container_manager manager,
    const char *name_or_id)
{
    if (!manager || !name_or_id) return NULL;
    struct container_manager_s *mgr = manager;

    struct list_head *pos;
    list_for_each(pos, &mgr->containers)
    {
        struct container_s *c = list_entry(pos, struct container_s, list);
        if (strcmp(c->id, name_or_id) == 0 || strcmp(c->name, name_or_id) == 0)
            return c;
    }
    return NULL;
}

int container_manager_foreach_container_safe(
    container_manager manager,
    void (*fn)(container c, void *user_data),
    void *user_data)
{
    if (!manager || !fn) return -1;
    struct container_manager_s *mgr = manager;

    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &mgr->containers)
    {
        struct container_s *c = list_entry(pos, struct container_s, list);
        fn(c, user_data);
    }
    return 0;
}

const char *container_get_id(container c)
{
    return c ? c->id : NULL;
}

const char *container_get_name(container c)
{
    return c ? c->name : NULL;
}

bool container_is_running(container c)
{
    return c && c->state == CONTAINER_STATE_RUNNING;
}

bool container_is_detached(container c)
{
    return c && c->detached;
}

image container_get_image(container c)
{
    return c ? c->img : NULL;
}

/* -------------------------------------------------------------------------- */
/*  Internal cleanup                                                           */
/* -------------------------------------------------------------------------- */

static void container_free_internal(struct container_s *c)
{
    if (!c) return;

    free(c->id);
    free(c->name);
    free(c->container_dir);
    free(c->config_path);
    free(c->bundle_path);

    free(c->overlay_lower);
    free(c->overlay_upper);
    free(c->overlay_work);
    free(c->overlay_merged);

    free(c->nat_network_name);
    free(c->netns_name);
    free(c->resolv_conf_path);
    free(c->dns_domain);

    /* port_forwarders should already be cleaned up by cleanup_network */
    free(c->port_forwarders);
    free(c->port_forward_specs);

    free(c);
}
