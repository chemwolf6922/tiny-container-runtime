#include "crun_config.h"

#include "common/utils.h"
#include "resource/seccomp_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

/* -------------------------------------------------------------------------- */
/*  Constants                                                                  */
/* -------------------------------------------------------------------------- */

static const char *DEFAULT_CAPS[] = {
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
};
static const size_t NUM_DEFAULT_CAPS = sizeof(DEFAULT_CAPS) / sizeof(DEFAULT_CAPS[0]);

/* Arch mapping: uname machine -> SCMP_ARCH_* primary architecture name */
struct arch_entry {
    const char *machine;        /* uname().machine value */
    const char *scmp_arch;      /* SCMP_ARCH_* name in archMap */
};

static const struct arch_entry ARCH_MAP[] = {
    { "x86_64",  "SCMP_ARCH_X86_64"  },
    { "aarch64", "SCMP_ARCH_AARCH64"  },
    { "armv7l",  "SCMP_ARCH_ARM"      },
    { "ppc64le", "SCMP_ARCH_PPC64LE"  },
    { "s390x",   "SCMP_ARCH_S390X"    },
    { "mips64",  "SCMP_ARCH_MIPS64"   },
    { "riscv64", "SCMP_ARCH_RISCV64"  },
};
static const size_t NUM_ARCH_MAP = sizeof(ARCH_MAP) / sizeof(ARCH_MAP[0]);

/* Default mounts that must be present in config.json */
struct default_mount {
    const char *destination;
    const char *type;
    const char *source;
    const char *options[8]; /* NULL-terminated */
};

static const struct default_mount DEFAULT_MOUNTS[] = {
    { "/proc",       "proc",   "proc",   { NULL } },
    { "/dev",        "tmpfs",  "tmpfs",  { "nosuid", "strictatime", "mode=755", "size=65536k", NULL } },
    { "/dev/pts",    "devpts", "devpts", { "nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", NULL } },
    { "/dev/shm",    "tmpfs",  "shm",    { "nosuid", "noexec", "nodev", "mode=1777", "size=65536k", NULL } },
    { "/dev/mqueue", "mqueue", "mqueue", { "nosuid", "noexec", "nodev", NULL } },
    { "/sys",        "sysfs",  "sysfs",  { "nosuid", "noexec", "nodev", "ro", NULL } },
};
static const size_t NUM_DEFAULT_MOUNTS = sizeof(DEFAULT_MOUNTS) / sizeof(DEFAULT_MOUNTS[0]);

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Check whether a destination already exists in the mounts array.
 */
static bool mount_exists(const cJSON *mounts, const char *destination)
{
    const cJSON *entry;
    cJSON_ArrayForEach(entry, mounts) {
        const cJSON *dst = cJSON_GetObjectItemCaseSensitive(entry, "destination");
        if (cJSON_IsString(dst) && strcmp(dst->valuestring, destination) == 0)
            return true;
    }
    return false;
}

/**
 * Build a cJSON string array from a C string array with explicit count.
 * Returns NULL on allocation failure.
 */
static cJSON *strings_to_json_array(const char *const *strings, size_t count)
{
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;
    for (size_t i = 0; i < count; i++) {
        cJSON *s = cJSON_CreateString(strings[i]);
        if (!s || !cJSON_AddItemToArray(arr, s)) {
            cJSON_Delete(s);
            cJSON_Delete(arr);
            return NULL;
        }
    }
    return arr;
}

/**
 * Build a cJSON array from a NULL-terminated C string array (auto-counted).
 */
static cJSON *null_term_strings_to_json_array(const char *const *strings)
{
    size_t count = 0;
    while (strings[count]) count++;
    return strings_to_json_array(strings, count);
}

/* -------------------------------------------------------------------------- */
/*  Seccomp conversion                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Get the native SCMP_ARCH_* name for the running machine.
 * Returns NULL if unknown.
 */
static const char *get_native_scmp_arch(void)
{
    struct utsname uts;
    if (uname(&uts) != 0) return NULL;

    for (size_t i = 0; i < NUM_ARCH_MAP; i++) {
        if (strcmp(uts.machine, ARCH_MAP[i].machine) == 0)
            return ARCH_MAP[i].scmp_arch;
    }
    return NULL;
}

/**
 * Convert a single syscall entry from containers/common format to OCI format.
 * Strips: includes, excludes, comment, errno fields.
 * Keeps: names, action, args (if non-empty), errnoRet (if present and non-zero).
 *
 * Entries with non-empty "includes" or "excludes" are skipped (returns NULL)
 * because they are architecture- or capability-conditional and require runtime
 * evaluation that is not trivially portable. The base entries (with empty
 * includes/excludes) cover the common case.
 *
 * Returns a new cJSON object, or NULL to skip.
 */
static cJSON *convert_syscall_entry(const cJSON *src)
{
    /* Skip entries with non-empty includes or excludes — they are conditional */
    const cJSON *includes = cJSON_GetObjectItemCaseSensitive(src, "includes");
    if (includes && cJSON_IsObject(includes) && includes->child)
        return NULL;

    const cJSON *excludes = cJSON_GetObjectItemCaseSensitive(src, "excludes");
    if (excludes && cJSON_IsObject(excludes) && excludes->child)
        return NULL;

    cJSON *entry = cJSON_CreateObject();
    if (!entry) return NULL;

    /* names (required) */
    const cJSON *names = cJSON_GetObjectItemCaseSensitive(src, "names");
    if (!names) { cJSON_Delete(entry); return NULL; }
    cJSON *names_dup = cJSON_Duplicate(names, true);
    if (!names_dup || !cJSON_AddItemToObject(entry, "names", names_dup)) {
        cJSON_Delete(names_dup);
        cJSON_Delete(entry);
        return NULL;
    }

    /* action (required) */
    const cJSON *action = cJSON_GetObjectItemCaseSensitive(src, "action");
    if (!action) { cJSON_Delete(entry); return NULL; }
    cJSON *action_dup = cJSON_Duplicate(action, true);
    if (!action_dup || !cJSON_AddItemToObject(entry, "action", action_dup)) {
        cJSON_Delete(action_dup);
        cJSON_Delete(entry);
        return NULL;
    }

    /* args — only if present and non-empty (and not null) */
    const cJSON *args = cJSON_GetObjectItemCaseSensitive(src, "args");
    if (args && cJSON_IsArray(args) && cJSON_GetArraySize(args) > 0) {
        cJSON *args_dup = cJSON_Duplicate(args, true);
        if (!args_dup || !cJSON_AddItemToObject(entry, "args", args_dup)) {
            cJSON_Delete(args_dup);
            cJSON_Delete(entry);
            return NULL;
        }
    }

    /* errnoRet — only if present and > 0 */
    const cJSON *errno_ret = cJSON_GetObjectItemCaseSensitive(src, "errnoRet");
    if (errno_ret && cJSON_IsNumber(errno_ret) && errno_ret->valueint > 0) {
        if (!cJSON_AddNumberToObject(entry, "errnoRet", errno_ret->valueint)) {
            cJSON_Delete(entry);
            return NULL;
        }
    }

    return entry;
}

/**
 * Convert the embedded containers/common seccomp.json to OCI linux.seccomp format.
 * Returns a new cJSON object suitable for config.linux.seccomp, or NULL on failure.
 */
static cJSON *build_oci_seccomp(void)
{
    /* Parse the embedded seccomp profile */
    cJSON *src = cJSON_ParseWithLength(SECCOMP_JSON_DATA, SECCOMP_JSON_LEN);
    if (!src) return NULL;

    cJSON *oci = cJSON_CreateObject();
    if (!oci) {
        cJSON_Delete(src);
        return NULL;
    }

    /* defaultAction */
    const cJSON *da = cJSON_GetObjectItemCaseSensitive(src, "defaultAction");
    if (da) {
        cJSON *da_dup = cJSON_Duplicate(da, true);
        if (!da_dup || !cJSON_AddItemToObject(oci, "defaultAction", da_dup)) {
            cJSON_Delete(da_dup);
            goto fail;
        }
    }

    /* defaultErrnoRet */
    const cJSON *der = cJSON_GetObjectItemCaseSensitive(src, "defaultErrnoRet");
    if (der) {
        cJSON *der_dup = cJSON_Duplicate(der, true);
        if (!der_dup || !cJSON_AddItemToObject(oci, "defaultErrnoRet", der_dup)) {
            cJSON_Delete(der_dup);
            goto fail;
        }
    }

    /* architectures — filter archMap to native arch only */
    const char *native = get_native_scmp_arch();
    cJSON *arch_array = cJSON_CreateArray();
    if (!arch_array) goto fail;

    if (native) {
        const cJSON *arch_map = cJSON_GetObjectItemCaseSensitive(src, "archMap");
        const cJSON *map_entry;
        cJSON_ArrayForEach(map_entry, arch_map) {
            const cJSON *arch_name = cJSON_GetObjectItemCaseSensitive(map_entry, "architecture");
            if (!cJSON_IsString(arch_name)) continue;
            if (strcmp(arch_name->valuestring, native) != 0) continue;

            /* Found our arch — add primary */
            cJSON *primary = cJSON_CreateString(native);
            if (!primary || !cJSON_AddItemToArray(arch_array, primary)) {
                cJSON_Delete(primary);
                cJSON_Delete(arch_array);
                goto fail;
            }

            /* Add sub-architectures */
            const cJSON *sub_archs = cJSON_GetObjectItemCaseSensitive(map_entry, "subArchitectures");
            const cJSON *sub;
            cJSON_ArrayForEach(sub, sub_archs) {
                if (!cJSON_IsString(sub)) continue;
                cJSON *sub_str = cJSON_CreateString(sub->valuestring);
                if (!sub_str || !cJSON_AddItemToArray(arch_array, sub_str)) {
                    cJSON_Delete(sub_str);
                    cJSON_Delete(arch_array);
                    goto fail;
                }
            }
            break;
        }
    }
    if (!cJSON_AddItemToObject(oci, "architectures", arch_array)) {
        cJSON_Delete(arch_array);
        goto fail;
    }

    /* syscalls — convert each entry, skipping conditional ones */
    cJSON *syscalls = cJSON_CreateArray();
    if (!syscalls) goto fail;

    const cJSON *src_syscalls = cJSON_GetObjectItemCaseSensitive(src, "syscalls");
    const cJSON *sc;
    cJSON_ArrayForEach(sc, src_syscalls) {
        cJSON *converted = convert_syscall_entry(sc);
        if (converted && !cJSON_AddItemToArray(syscalls, converted))
            cJSON_Delete(converted);
    }
    if (!cJSON_AddItemToObject(oci, "syscalls", syscalls)) {
        cJSON_Delete(syscalls);
        goto fail;
    }

    cJSON_Delete(src);
    return oci;

fail:
    cJSON_Delete(oci);
    cJSON_Delete(src);
    return NULL;
}

/* -------------------------------------------------------------------------- */
/*  Capabilities                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Build the process.capabilities object with all 5 sets.
 */
static cJSON *build_capabilities(void)
{
    cJSON *caps = cJSON_CreateObject();
    if (!caps) return NULL;

    static const char *SET_NAMES[] = {
        "bounding", "effective", "inheritable", "permitted", "ambient"
    };

    for (size_t i = 0; i < 5; i++) {
        cJSON *arr = strings_to_json_array(DEFAULT_CAPS, NUM_DEFAULT_CAPS);
        if (!arr || !cJSON_AddItemToObject(caps, SET_NAMES[i], arr)) {
            cJSON_Delete(arr);
            cJSON_Delete(caps);
            return NULL;
        }
    }
    return caps;
}

/* -------------------------------------------------------------------------- */
/*  Namespaces                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Build the linux.namespaces array.
 */
static cJSON *build_namespaces(void)
{
    static const char *NS_TYPES[] = { "pid", "ipc", "uts", "mount", "network" };
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;

    for (size_t i = 0; i < 5; i++) {
        cJSON *ns = cJSON_CreateObject();
        if (!ns) {
            cJSON_Delete(arr);
            return NULL;
        }
        if (!cJSON_AddStringToObject(ns, "type", NS_TYPES[i]) ||
            !cJSON_AddItemToArray(arr, ns)) {
            cJSON_Delete(ns);
            cJSON_Delete(arr);
            return NULL;
        }
    }
    return arr;
}

/* -------------------------------------------------------------------------- */
/*  Default mounts                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Ensure all default mounts exist in the mounts array.
 * Adds any that are missing (does not overwrite existing ones).
 */
static int ensure_default_mounts(cJSON *config)
{
    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(config, "mounts");
    if (!mounts) {
        mounts = cJSON_CreateArray();
        if (!mounts) return -1;
        if (!cJSON_AddItemToObject(config, "mounts", mounts)) {
            cJSON_Delete(mounts);
            return -1;
        }
    }

    for (size_t i = 0; i < NUM_DEFAULT_MOUNTS; i++) {
        const struct default_mount *dm = &DEFAULT_MOUNTS[i];
        if (mount_exists(mounts, dm->destination))
            continue;

        cJSON *entry = cJSON_CreateObject();
        if (!entry) return -1;

        if (!cJSON_AddStringToObject(entry, "destination", dm->destination) ||
            !cJSON_AddStringToObject(entry, "type", dm->type) ||
            !cJSON_AddStringToObject(entry, "source", dm->source)) {
            cJSON_Delete(entry);
            return -1;
        }

        if (dm->options[0]) {
            cJSON *opts = null_term_strings_to_json_array(dm->options);
            if (!opts || !cJSON_AddItemToObject(entry, "options", opts)) {
                cJSON_Delete(opts);
                cJSON_Delete(entry);
                return -1;
            }
        }

        if (!cJSON_AddItemToArray(mounts, entry)) {
            cJSON_Delete(entry);
            return -1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                 */
/* -------------------------------------------------------------------------- */

cJSON *crun_config_create(const char *bundle_path)
{
    if (!bundle_path) return NULL;

    /* Read the skeleton config.json from the bundle */
    char *config_path = path_join(bundle_path, "config.json");
    if (!config_path) return NULL;

    cJSON *config = load_json_file(config_path);
    free(config_path);
    if (!config) return NULL;

    /* --- Defaults: readonly rootfs, no tty --- */
    if (crun_config_set_readonly(config, true) != 0)
        goto fail;
    if (crun_config_set_terminal_mode(config, false) != 0)
        goto fail;

    /* --- Capabilities --- */
    cJSON *caps = build_capabilities();
    if (!caps) goto fail;
    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    if (!process) goto fail;
    cJSON_DeleteItemFromObjectCaseSensitive(process, "capabilities");
    if (!cJSON_AddItemToObject(process, "capabilities", caps)) {
        cJSON_Delete(caps);
        goto fail;
    }

    /* --- Namespaces --- */
    cJSON *linux_obj = cJSON_GetObjectItemCaseSensitive(config, "linux");
    if (!linux_obj) {
        linux_obj = cJSON_CreateObject();
        if (!linux_obj) goto fail;
        if (!cJSON_AddItemToObject(config, "linux", linux_obj)) {
            cJSON_Delete(linux_obj);
            goto fail;
        }
    }
    cJSON_DeleteItemFromObjectCaseSensitive(linux_obj, "namespaces");
    cJSON *ns = build_namespaces();
    if (!ns) goto fail;
    if (!cJSON_AddItemToObject(linux_obj, "namespaces", ns)) {
        cJSON_Delete(ns);
        goto fail;
    }

    /* --- Seccomp --- */
    cJSON *seccomp = build_oci_seccomp();
    if (!seccomp) goto fail;
    cJSON_DeleteItemFromObjectCaseSensitive(linux_obj, "seccomp");
    if (!cJSON_AddItemToObject(linux_obj, "seccomp", seccomp)) {
        cJSON_Delete(seccomp);
        goto fail;
    }

    /* --- Default mounts --- */
    if (ensure_default_mounts(config) != 0)
        goto fail;

    return config;

fail:
    cJSON_Delete(config);
    return NULL;
}

int crun_config_set_readonly(cJSON *config, bool readonly)
{
    if (!config) return -1;

    cJSON *root = cJSON_GetObjectItemCaseSensitive(config, "root");
    if (!root) return -1;

    cJSON *ro = cJSON_GetObjectItemCaseSensitive(root, "readonly");
    if (ro) {
        cJSON *val = cJSON_CreateBool(readonly);
        if (!val) return -1;
        cJSON_ReplaceItemInObjectCaseSensitive(root, "readonly", val);
    } else {
        if (!cJSON_AddBoolToObject(root, "readonly", readonly)) return -1;
    }
    return 0;
}

int crun_config_set_rootfs(cJSON *config, const char *rootfs_path)
{
    if (!config || !rootfs_path) return -1;

    cJSON *root = cJSON_GetObjectItemCaseSensitive(config, "root");
    if (!root) return -1;

    cJSON *path = cJSON_GetObjectItemCaseSensitive(root, "path");
    if (path) {
        cJSON *val = cJSON_CreateString(rootfs_path);
        if (!val) return -1;
        cJSON_ReplaceItemInObjectCaseSensitive(root, "path", val);
    } else {
        if (!cJSON_AddStringToObject(root, "path", rootfs_path)) return -1;
    }
    return 0;
}

int crun_config_set_terminal_mode(cJSON *config, bool is_tty)
{
    if (!config) return -1;

    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    if (!process) return -1;

    cJSON *term = cJSON_GetObjectItemCaseSensitive(process, "terminal");
    if (term) {
        cJSON *val = cJSON_CreateBool(is_tty);
        if (!val) return -1;
        cJSON_ReplaceItemInObjectCaseSensitive(process, "terminal", val);
    } else {
        if (!cJSON_AddBoolToObject(process, "terminal", is_tty)) return -1;
    }
    return 0;
}

int crun_config_set_args(cJSON *config, size_t argc, const char *const *argv)
{
    if (!config || !argv || argc == 0) return -1;

    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    if (!process) return -1;

    cJSON *args = strings_to_json_array(argv, argc);
    if (!args) return -1;

    cJSON_DeleteItemFromObjectCaseSensitive(process, "args");
    if (!cJSON_AddItemToObject(process, "args", args)) {
        cJSON_Delete(args);
        return -1;
    }
    return 0;
}

int crun_config_add_bind_mount(cJSON *config, const char *source,
                               const char *destination, bool read_only)
{
    if (!config || !source || !destination) return -1;

    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(config, "mounts");
    if (!mounts) {
        mounts = cJSON_CreateArray();
        if (!mounts) return -1;
        if (!cJSON_AddItemToObject(config, "mounts", mounts)) {
            cJSON_Delete(mounts);
            return -1;
        }
    }

    cJSON *entry = cJSON_CreateObject();
    if (!entry) return -1;

    if (!cJSON_AddStringToObject(entry, "destination", destination) ||
        !cJSON_AddStringToObject(entry, "type", "bind") ||
        !cJSON_AddStringToObject(entry, "source", source)) {
        cJSON_Delete(entry);
        return -1;
    }

    cJSON *opts = cJSON_CreateArray();
    if (!opts || !cJSON_AddItemToObject(entry, "options", opts)) {
        cJSON_Delete(opts);
        cJSON_Delete(entry);
        return -1;
    }

    cJSON *bind_str = cJSON_CreateString("bind");
    if (!bind_str || !cJSON_AddItemToArray(opts, bind_str)) {
        cJSON_Delete(bind_str);
        cJSON_Delete(entry);
        return -1;
    }
    if (read_only) {
        cJSON *ro_str = cJSON_CreateString("ro");
        if (!ro_str || !cJSON_AddItemToArray(opts, ro_str)) {
            cJSON_Delete(ro_str);
            cJSON_Delete(entry);
            return -1;
        }
    }

    if (!cJSON_AddItemToArray(mounts, entry)) {
        cJSON_Delete(entry);
        return -1;
    }
    return 0;
}

int crun_config_add_tmpfs_mount(cJSON *config, const char *destination,
                                size_t size_bytes)
{
    if (!config || !destination) return -1;

    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(config, "mounts");
    if (!mounts) {
        mounts = cJSON_CreateArray();
        if (!mounts) return -1;
        if (!cJSON_AddItemToObject(config, "mounts", mounts)) {
            cJSON_Delete(mounts);
            return -1;
        }
    }

    cJSON *entry = cJSON_CreateObject();
    if (!entry) return -1;

    if (!cJSON_AddStringToObject(entry, "destination", destination) ||
        !cJSON_AddStringToObject(entry, "type", "tmpfs") ||
        !cJSON_AddStringToObject(entry, "source", "tmpfs")) {
        cJSON_Delete(entry);
        return -1;
    }

    /* Build options: nosuid, nodev, mode=1777, size=<N> */
    char size_opt[64];
    snprintf(size_opt, sizeof(size_opt), "size=%zu", size_bytes);

    static const char *TMPFS_OPTS[] = { "nosuid", "nodev", "mode=1777" };
    cJSON *opts = cJSON_CreateArray();
    if (!opts || !cJSON_AddItemToObject(entry, "options", opts)) {
        cJSON_Delete(opts);
        cJSON_Delete(entry);
        return -1;
    }

    for (size_t i = 0; i < 3; i++) {
        cJSON *s = cJSON_CreateString(TMPFS_OPTS[i]);
        if (!s || !cJSON_AddItemToArray(opts, s)) {
            cJSON_Delete(s);
            cJSON_Delete(entry);
            return -1;
        }
    }
    cJSON *size_str = cJSON_CreateString(size_opt);
    if (!size_str || !cJSON_AddItemToArray(opts, size_str)) {
        cJSON_Delete(size_str);
        cJSON_Delete(entry);
        return -1;
    }

    if (!cJSON_AddItemToArray(mounts, entry)) {
        cJSON_Delete(entry);
        return -1;
    }
    return 0;
}

int crun_config_add_env(cJSON *config, const char *key, const char *value)
{
    if (!config || !key || !value) return -1;

    cJSON *process = cJSON_GetObjectItemCaseSensitive(config, "process");
    if (!process) return -1;

    cJSON *env = cJSON_GetObjectItemCaseSensitive(process, "env");
    if (!env) {
        env = cJSON_CreateArray();
        if (!env) return -1;
        if (!cJSON_AddItemToObject(process, "env", env)) {
            cJSON_Delete(env);
            return -1;
        }
    }

    /* Format as "KEY=VALUE" */
    size_t klen = strlen(key);
    size_t vlen = strlen(value);
    char *entry = malloc(klen + 1 + vlen + 1);
    if (!entry) return -1;
    snprintf(entry, klen + 1 + vlen + 1, "%s=%s", key, value);

    cJSON *str = cJSON_CreateString(entry);
    free(entry);
    if (!str) return -1;

    if (!cJSON_AddItemToArray(env, str)) {
        cJSON_Delete(str);
        return -1;
    }
    return 0;
}

int crun_config_set_network_ns(cJSON *config, const char *ns_path)
{
    if (!config || !ns_path) return -1;

    cJSON *linux_obj = cJSON_GetObjectItemCaseSensitive(config, "linux");
    if (!linux_obj) return -1;

    cJSON *namespaces = cJSON_GetObjectItemCaseSensitive(linux_obj, "namespaces");
    if (!namespaces || !cJSON_IsArray(namespaces)) return -1;

    /* Find the network namespace entry and set its path */
    cJSON *ns;
    cJSON_ArrayForEach(ns, namespaces) {
        const cJSON *type = cJSON_GetObjectItemCaseSensitive(ns, "type");
        if (!cJSON_IsString(type)) continue;
        if (strcmp(type->valuestring, "network") != 0) continue;

        /* Found it — set or replace the path */
        cJSON *path = cJSON_GetObjectItemCaseSensitive(ns, "path");
        if (path) {
            cJSON *val = cJSON_CreateString(ns_path);
            if (!val) return -1;
            cJSON_ReplaceItemInObjectCaseSensitive(ns, "path", val);
        } else {
            if (!cJSON_AddStringToObject(ns, "path", ns_path)) return -1;
        }
        return 0;
    }

    /* Network namespace entry not found — shouldn't happen after crun_config_create */
    return -1;
}


