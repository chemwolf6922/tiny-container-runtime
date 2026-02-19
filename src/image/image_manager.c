#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "image_manager.h"

#include <tev/map.h>
#include <cjson/cJSON.h>

#include "common/list.h"
#include "common/utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Constants                                                                  */
/* -------------------------------------------------------------------------- */

#define IMAGES_DIRNAME      "images"
#define MOUNT_DIRNAME       "mnt"
#define RUNTIME_INFO_FILE   "image-runtime-info.json"
#define IMAGE_INFO_FILE     "image-info.json"
#define DEFAULT_TAG         "latest"
#define DEFAULT_REGISTRY    "docker.io/library/"

/* -------------------------------------------------------------------------- */
/*  Data structures                                                            */
/* -------------------------------------------------------------------------- */


struct image_s
{
    struct list_head list;

    /* persisted in image-runtime-info.json */
    char *sqfs_path;        /* absolute path to the .sqfs file */

    /* derived paths */
    char *uuid_dir;         /* <root>/images/<uuid>/                 */
    char *mount_path;       /* <root>/images/<uuid>/mnt/             */
    char *runtime_info_path;/* <root>/images/<uuid>/image-runtime-info.json */

    /* loaded from image-info.json inside the squashfs */
    char *id;             /* xxh64 hash of the digest, hex string */
    char *name;           /* "registry/repository" */
    char *tag;
    char *digest;
    char *arch;
    uint64_t created;

    bool mounted;
    char *loop_dev;       /* /dev/loopN when mounted, NULL otherwise */

    /* absolute path: <mount_path>/<bundle_path_from_json> */
    char *bundle_path;
};

struct image_manager_s
{
    char *root_path;
    char *images_dir;       /* <root>/images/ */

    struct list_head images;
    map_handle_t id_map;        /* id string -> struct image_s* */
    map_handle_t tag_map;       /* "name:tag" -> struct image_s* */
};

/* -------------------------------------------------------------------------- */
/*  Helpers — paths & strings                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Build a tag-map key: "name:tag".
 * Caller must free the returned string.
 */
static char *make_tag_key(const char *name, const char *tag, size_t *out_len)
{
    size_t ln = strlen(name);
    size_t lt = strlen(tag);
    size_t total = ln + 1 + lt;
    char *key = malloc(total + 1);
    if (!key) return NULL;
    snprintf(key, total + 1, "%s:%s", name, tag);
    *out_len = total;
    return key;
}

/** Create a directory if it does not already exist (non-recursive). */
static int mkdir_if_not_exist(const char *path)
{
    if (mkdir(path, 0755) == 0) return 0;
    if (errno == EEXIST)
    {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    }
    return -1;
}

/** Check if a path is currently a mount point using /proc/self/mountinfo. */
static bool is_mountpoint(const char *path)
{
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) return false;

    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) return false;

    char line[4096];
    bool found = false;
    while (fgets(line, sizeof(line), f))
    {
        /* mountinfo format: id parent_id major:minor root mount_point ... */
        unsigned id, parent_id;
        unsigned maj, min;
        char root[PATH_MAX], mpoint[PATH_MAX];
        if (sscanf(line, "%u %u %u:%u %s %s",
                   &id, &parent_id, &maj, &min, root, mpoint) >= 6)
        {
            if (strcmp(mpoint, resolved) == 0)
            {
                found = true;
                break;
            }
        }
    }
    fclose(f);
    return found;
}

/** Remove a directory if it is empty. */
static int rmdir_if_empty(const char *path)
{
    return rmdir(path);  /* fails with ENOTEMPTY if not empty, that's fine */
}

/* -------------------------------------------------------------------------- */
/*  Helpers — image lifecycle                                                  */
/* -------------------------------------------------------------------------- */

static void image_free(image img)
{
    if (!img) return;
    if (img->sqfs_path)        free(img->sqfs_path);
    if (img->uuid_dir)         free(img->uuid_dir);
    if (img->mount_path)       free(img->mount_path);
    if (img->runtime_info_path) free(img->runtime_info_path);
    if (img->loop_dev)         free(img->loop_dev);
    if (img->id)               free(img->id);
    if (img->name)             free(img->name);
    if (img->tag)              free(img->tag);
    if (img->digest)           free(img->digest);
    if (img->arch)             free(img->arch);
    if (img->bundle_path)      free(img->bundle_path);
    free(img);
}

/* -------------------------------------------------------------------------- */
/*  Loop device helpers                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Attach a regular file to a free loop device.
 * Returns a malloc'd string like "/dev/loop3" on success, NULL on failure.
 */
static char *setup_loop(const char *file_path)
{
    int ctl_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
    if (ctl_fd < 0) return NULL;

    int devnr = ioctl(ctl_fd, LOOP_CTL_GET_FREE);
    close(ctl_fd);
    if (devnr < 0) return NULL;

    char *dev = NULL;
    if (asprintf(&dev, "/dev/loop%d", devnr) < 0)
        return NULL;

    int loop_fd = open(dev, O_RDWR | O_CLOEXEC);
    if (loop_fd < 0) { free(dev); return NULL; }

    int file_fd = open(file_path, O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) { close(loop_fd); free(dev); return NULL; }

    if (ioctl(loop_fd, LOOP_SET_FD, file_fd) < 0)
    {
        close(file_fd);
        close(loop_fd);
        free(dev);
        return NULL;
    }

    /* set autoclear so the loop detaches on last close after umount */
    struct loop_info64 info;
    memset(&info, 0, sizeof(info));
    info.lo_flags = LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR;
    ioctl(loop_fd, LOOP_SET_STATUS64, &info);  /* best-effort */

    close(file_fd);
    close(loop_fd);
    return dev;
}

/** Detach a loop device explicitly (idempotent). */
static void detach_loop(char **loop_dev)
{
    if (!loop_dev || !*loop_dev) return;
    int fd = open(*loop_dev, O_RDWR | O_CLOEXEC);
    if (fd >= 0)
    {
        ioctl(fd, LOOP_CLR_FD, 0);
        close(fd);
    }
    free(*loop_dev);
    *loop_dev = NULL;
}

/** Write image-runtime-info.json to disk. */
static int write_runtime_info(const struct image_s *img)
{
    if (!img) return -1;

    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    cJSON_AddStringToObject(root, "sqfsPath", img->sqfs_path);
    cJSON_AddStringToObject(root, "id", img->id);
    cJSON_AddStringToObject(root, "digest", img->digest);
    cJSON_AddStringToObject(root, "name", img->name);
    if (img->tag)
        cJSON_AddStringToObject(root, "tag", img->tag);
    cJSON_AddStringToObject(root, "arch", img->arch ? img->arch : "");
    cJSON_AddNumberToObject(root, "created", (double)img->created);

    char *str = cJSON_Print(root);
    cJSON_Delete(root);
    if (!str) return -1;

    FILE *f = fopen(img->runtime_info_path, "w");
    if (!f) { free(str); return -1; }
    fputs(str, f);
    fclose(f);
    free(str);
    return 0;
}

/**
 * Parse image-info.json (inside the mounted squashfs) and fill image fields.
 * Expects img->mount_path to be valid.
 */
static int parse_image_info(image img)
{
    if (!img || !img->mount_path) return -1;

    char *info_path = path_join(img->mount_path, IMAGE_INFO_FILE);
    if (!info_path) return -1;

    cJSON *root = load_json_file(info_path);
    free(info_path);
    if (!root) return -1;

    cJSON *image_obj = cJSON_GetObjectItem(root, "image");
    if (!image_obj)
    {
        cJSON_Delete(root);
        return -1;
    }

    cJSON *j;

    j = cJSON_GetObjectItem(image_obj, "registry");
    if (!cJSON_IsString(j)) goto bad;
    const char *reg = j->valuestring;

    j = cJSON_GetObjectItem(image_obj, "repository");
    if (!cJSON_IsString(j)) goto bad;
    const char *repo = j->valuestring;

    if (asprintf(&img->name, "%s/%s", reg, repo) < 0)
        goto bad;

    j = cJSON_GetObjectItem(image_obj, "id");
    if (!cJSON_IsString(j)) goto bad;
    img->id = strdup(j->valuestring);

    j = cJSON_GetObjectItem(image_obj, "tag");
    if (!cJSON_IsString(j)) goto bad;
    img->tag = strdup(j->valuestring);

    j = cJSON_GetObjectItem(image_obj, "digest");
    if (!cJSON_IsString(j)) goto bad;
    img->digest = strdup(j->valuestring);

    j = cJSON_GetObjectItem(image_obj, "arch");
    if (!cJSON_IsString(j)) goto bad;
    img->arch = strdup(j->valuestring);

    j = cJSON_GetObjectItem(root, "bundlePath");
    if (!cJSON_IsString(j)) goto bad;
    img->bundle_path = path_join(img->mount_path, j->valuestring);

    j = cJSON_GetObjectItem(root, "created");
    if (!cJSON_IsNumber(j)) goto bad;
    img->created = (uint64_t)j->valuedouble;

    cJSON_Delete(root);
    return img->bundle_path ? 0 : -1;

bad:
    cJSON_Delete(root);
    return -1;
}

/**
 * Parse image-runtime-info.json (on disk, outside squashfs).
 * Fills sqfs_path and metadata fields so we know the image even when
 * unmounted.
 */
static int parse_runtime_info(image img)
{
    if (!img || !img->runtime_info_path) return -1;

    cJSON *root = load_json_file(img->runtime_info_path);
    if (!root) return -1;

    cJSON *j;

    j = cJSON_GetObjectItem(root, "sqfsPath");
    if (!cJSON_IsString(j)) goto bad;
    img->sqfs_path = strdup(j->valuestring);

    j = cJSON_GetObjectItem(root, "id");
    if (!cJSON_IsString(j)) goto bad;
    img->id = strdup(j->valuestring);

    j = cJSON_GetObjectItem(root, "digest");
    if (!cJSON_IsString(j)) goto bad;
    img->digest = strdup(j->valuestring);

    j = cJSON_GetObjectItem(root, "name");
    if (!cJSON_IsString(j)) goto bad;
    img->name = strdup(j->valuestring);

    j = cJSON_GetObjectItem(root, "tag");
    img->tag = cJSON_IsString(j) ? strdup(j->valuestring) : NULL;

    j = cJSON_GetObjectItem(root, "arch");
    if (!cJSON_IsString(j)) goto bad;
    img->arch = strdup(j->valuestring);

    j = cJSON_GetObjectItem(root, "created");
    if (!cJSON_IsNumber(j)) goto bad;
    img->created = (uint64_t)j->valuedouble;

    cJSON_Delete(root);
    return img->sqfs_path ? 0 : -1;

bad:
    cJSON_Delete(root);
    return -1;
}

/**
 * Register an image into the manager's maps and list.
 * Handles tag collision: if the same name+tag already exists,
 * the old image loses its tag (set to NULL) and is removed from the tag map.
 * Returns 0 on success, -1 on failure (e.g. OOM in map_add).
 */
static int manager_register_image(image_manager mgr, image img)
{
    if (!mgr || !img) return -1;

    /* add to id map */
    if (img->id && img->id[0])
    {
        void *ret = map_add(mgr->id_map, img->id, strlen(img->id), img);
        if (!ret) return -1;
    }

    /* add to tag map (may evict old tag holder) */
    if (img->tag && img->name)
    {
        size_t key_len;
        char *key = make_tag_key(img->name, img->tag, &key_len);
        if (!key)
        {
            /* roll back id map insertion */
            if (img->id && img->id[0])
                map_remove(mgr->id_map, img->id, strlen(img->id));
            return -1;
        }

        void *old = map_add(mgr->tag_map, key, key_len, img);
        if (!old)
        {
            /* OOM — roll back id map insertion */
            free(key);
            if (img->id && img->id[0])
                map_remove(mgr->id_map, img->id, strlen(img->id));
            return -1;
        }

        if (old != img)
        {
            /* old image with same tag loses its tag */
            image old_img = old;
            if (old_img->tag) free(old_img->tag);
            old_img->tag = NULL;
            /* update runtime info to reflect tag loss */
            write_runtime_info(old_img);
        }
        free(key);
    }

    /* add to linked list (cannot fail) */
    list_add_tail(&img->list, &mgr->images);
    return 0;
}

/** Unregister an image from the manager's maps and list. */
static void manager_unregister_image(image_manager mgr, image img)
{
    if (!mgr || !img) return;

    /* remove from id map */
    if (img->id && img->id[0])
    {
        map_remove(mgr->id_map, img->id, strlen(img->id));
    }

    /* remove from tag map */
    if (img->tag && img->name)
    {
        size_t key_len;
        char *key = make_tag_key(img->name, img->tag, &key_len);
        if (key)
        {
            /* only remove if we are still the current holder */
            void *cur = map_get(mgr->tag_map, key, key_len);
            if (cur == img)
                map_remove(mgr->tag_map, key, key_len);
            free(key);
        }
    }

    list_del(&img->list);
}

/* -------------------------------------------------------------------------- */
/*  Startup — scan existing images                                             */
/* -------------------------------------------------------------------------- */

/**
 * Scan <root>/images/ for existing UUID directories, rebuild in-memory state.
 * Looks for image-runtime-info.json in each UUID dir. If the mnt/ subdirectory
 * is a mountpoint, the image is considered mounted and image-info.json is also
 * parsed for bundle path info.
 */
static int manager_scan_existing(image_manager mgr)
{
    if (!mgr) return -1;

    DIR *d = opendir(mgr->images_dir);
    if (!d) return 0;   /* no images dir yet — that's fine */

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (ent->d_name[0] == '.') continue;

        char *uuid_dir = path_join(mgr->images_dir, ent->d_name);
        if (!uuid_dir) continue;

        /* must be a directory */
        struct stat st;
        if (stat(uuid_dir, &st) != 0 || !S_ISDIR(st.st_mode))
        {
            free(uuid_dir);
            continue;
        }

        char *ri_path = path_join(uuid_dir, RUNTIME_INFO_FILE);
        if (!ri_path) { free(uuid_dir); continue; }

        /* must have image-runtime-info.json */
        if (access(ri_path, F_OK) != 0)
        {
            free(ri_path);
            free(uuid_dir);
            continue;
        }

        image img = calloc(1, sizeof(*img));
        if (!img) { free(ri_path); free(uuid_dir); continue; }

        img->uuid_dir = uuid_dir;
        img->runtime_info_path = ri_path;
        img->mount_path = path_join(uuid_dir, MOUNT_DIRNAME);
        if (!img->mount_path) { image_free(img); continue; }

        /* parse runtime info for metadata + sqfs path */
        if (parse_runtime_info(img) != 0)
        {
            image_free(img);
            continue;
        }

        /* check if already mounted */
        img->mounted = is_mountpoint(img->mount_path);

        /* if mounted, also read image-info.json for bundle path */
        if (img->mounted)
        {
            /* parse_image_info fills bundle_path;
             * we already have metadata from runtime info, so only take
             * bundle info from image-info.json. But parse_image_info
             * overwrites all fields — let's just let it overwrite since
             * the squashfs data is authoritative when mounted. */
            char *saved_sqfs = img->sqfs_path;
            img->sqfs_path = NULL;

            /* free fields that parse_image_info will overwrite */
            if (img->name)   { free(img->name);   img->name = NULL; }
            if (img->tag)    { free(img->tag);    img->tag = NULL; }
            if (img->id)     { free(img->id);     img->id = NULL; }
            if (img->digest) { free(img->digest); img->digest = NULL; }
            if (img->arch)   { free(img->arch);   img->arch = NULL; }

            if (parse_image_info(img) != 0)
            {
                /* fall back to runtime info data — re-parse */
                img->sqfs_path = saved_sqfs;
                /* re-read runtime info to restore fields */
                if (parse_runtime_info(img) != 0)
                {
                    image_free(img);
                    continue;
                }
            }
            else
            {
                img->sqfs_path = saved_sqfs;
            }
        }
        else
        {
            /* not mounted — bundle path is unknown */
            img->bundle_path = NULL;
        }

        /* check for id collision (should not happen but be safe) */
        if (img->id && img->id[0] &&
            map_has(mgr->id_map, img->id, strlen(img->id)))
        {
            fprintf(stderr, "image_manager: duplicate id %s in %s, skipping\n",
                    img->id, ent->d_name);
            image_free(img);
            continue;
        }

        if (manager_register_image(mgr, img) != 0)
        {
            fprintf(stderr, "image_manager: failed to register image %s\n",
                    ent->d_name);
            image_free(img);
            continue;
        }
    }

    closedir(d);
    return 0;
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                 */
/* -------------------------------------------------------------------------- */

image_manager image_manager_new(const char *root_path)
{
    if (!root_path) return NULL;

    image_manager mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    list_head_init(&mgr->images);

    /* resolve to absolute path */
    char resolved[PATH_MAX];
    if (!realpath(root_path, resolved))
    {
        /* path may not exist yet — use as-is */
        mgr->root_path = strdup(root_path);
    }
    else
    {
        mgr->root_path = strdup(resolved);
    }
    if (!mgr->root_path) goto fail;

    mgr->images_dir = path_join(mgr->root_path, IMAGES_DIRNAME);
    if (!mgr->images_dir) goto fail;

    /* ensure directories exist */
    if (mkdir_if_not_exist(mgr->root_path) != 0) goto fail;
    if (mkdir_if_not_exist(mgr->images_dir) != 0) goto fail;

    /* create maps */
    mgr->id_map = map_create();
    mgr->tag_map = map_create();
    if (!mgr->id_map || !mgr->tag_map) goto fail;

    /* scan existing images */
    manager_scan_existing(mgr);

    return mgr;

fail:
    if (mgr->id_map) map_delete(mgr->id_map, NULL, NULL);
    if (mgr->tag_map) map_delete(mgr->tag_map, NULL, NULL);
    if (mgr->images_dir) free(mgr->images_dir);
    if (mgr->root_path)  free(mgr->root_path);
    free(mgr);
    return NULL;
}

void image_manager_free(image_manager manager, bool umount_all)
{
    if (!manager) return;
    image_manager mgr = manager;

    /* free all images */
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &mgr->images)
    {
        image img = list_entry(pos, struct image_s, list);
        if (umount_all && img->mounted)
        {
            umount2(img->mount_path, 0);
            detach_loop(&img->loop_dev);
            img->mounted = false;
        }
        list_del(&img->list);
        image_free(img);
    }

    map_delete(mgr->id_map, NULL, NULL);
    map_delete(mgr->tag_map, NULL, NULL);

    if (mgr->images_dir) free(mgr->images_dir);
    if (mgr->root_path)  free(mgr->root_path);
    free(mgr);
}

image image_manager_load(image_manager manager, const char *path)
{
    if (!manager || !path) return NULL;
    image_manager mgr = manager;

    /* resolve to absolute path */
    char resolved[PATH_MAX];
    if (!realpath(path, resolved))
    {
        fprintf(stderr, "image_manager: cannot resolve path: %s\n", path);
        return NULL;
    }

    /* verify file exists */
    struct stat st;
    if (stat(resolved, &st) != 0 || !S_ISREG(st.st_mode))
    {
        fprintf(stderr, "image_manager: not a regular file: %s\n", resolved);
        return NULL;
    }

    /* generate random hex string for the mount directory */
    unsigned char rand_bytes[16];
    char uuid_str[33];
    int urand_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (urand_fd < 0)
    {
        fprintf(stderr, "image_manager: cannot open /dev/urandom\n");
        return NULL;
    }
    ssize_t n = read(urand_fd, rand_bytes, sizeof(rand_bytes));
    close(urand_fd);
    if (n != (ssize_t)sizeof(rand_bytes))
    {
        fprintf(stderr, "image_manager: short read from /dev/urandom\n");
        return NULL;
    }
    for (int i = 0; i < 16; i++)
        snprintf(uuid_str + i * 2, 3, "%02x", rand_bytes[i]);

    /* set up paths */
    image img = calloc(1, sizeof(*img));
    if (!img) return NULL;

    img->sqfs_path = strdup(resolved);
    img->uuid_dir = path_join(mgr->images_dir, uuid_str);
    img->mount_path = path_join(img->uuid_dir, MOUNT_DIRNAME);
    img->runtime_info_path = path_join(img->uuid_dir, RUNTIME_INFO_FILE);

    if (!img->sqfs_path || !img->uuid_dir || !img->mount_path || !img->runtime_info_path)
        goto fail;

    /* create directories */
    if (mkdir_if_not_exist(img->uuid_dir) != 0)
    {
        fprintf(stderr, "image_manager: cannot create directory: %s\n", img->uuid_dir);
        goto fail;
    }
    if (mkdir_if_not_exist(img->mount_path) != 0)
    {
        fprintf(stderr, "image_manager: cannot create mount directory: %s\n", img->mount_path);
        goto fail_rmdir;
    }

    /* set up loop device and mount squashfs */
    img->loop_dev = setup_loop(img->sqfs_path);
    if (!img->loop_dev)
    {
        fprintf(stderr, "image_manager: failed to set up loop device for %s: %s\n",
                img->sqfs_path, strerror(errno));
        goto fail_rmdir;
    }
    if (mount(img->loop_dev, img->mount_path, "squashfs", MS_RDONLY, NULL) != 0)
    {
        fprintf(stderr, "image_manager: mount failed for %s: %s\n",
                img->sqfs_path, strerror(errno));
        detach_loop(&img->loop_dev);
        goto fail_rmdir;
    }
    img->mounted = true;

    /* parse image-info.json from the mounted squashfs */
    if (parse_image_info(img) != 0)
    {
        fprintf(stderr, "image_manager: failed to parse %s in %s\n",
                IMAGE_INFO_FILE, img->mount_path);
        goto fail_umount;
    }

    /* check for duplicate id */
    if (img->id && img->id[0] &&
        map_has(mgr->id_map, img->id, strlen(img->id)))
    {
        fprintf(stderr, "image_manager: image with id %s is already loaded\n",
                img->id);
        goto fail_umount;
    }

    /* write runtime info to disk */
    if (write_runtime_info(img) != 0)
    {
        fprintf(stderr, "image_manager: failed to write runtime info\n");
        goto fail_umount;
    }

    /* register in maps and list */
    if (manager_register_image(mgr, img) != 0)
    {
        fprintf(stderr, "image_manager: failed to register image (out of memory)\n");
        goto fail_umount;
    }
    return img;

fail_umount:
    umount2(img->mount_path, 0);
    detach_loop(&img->loop_dev);
    img->mounted = false;
fail_rmdir:
    rmdir_if_empty(img->mount_path);
    /* remove runtime info if it was written */
    unlink(img->runtime_info_path);
    rmdir_if_empty(img->uuid_dir);
fail:
    image_free(img);
    return NULL;
}

void image_manager_remove(image_manager manager, image img)
{
    if (!manager || !img) return;
    image_manager mgr = manager;
    image im = img;

    manager_unregister_image(mgr, im);

    if (im->mounted)
    {
        umount2(im->mount_path, 0);
        detach_loop(&im->loop_dev);
        im->mounted = false;
    }

    /* clean up on-disk state */
    unlink(im->runtime_info_path);
    rmdir_if_empty(im->mount_path);
    rmdir_if_empty(im->uuid_dir);

    image_free(im);
}

int image_manager_mount_image(image_manager manager, image img)
{
    if (!manager || !img) return -1;

    image im = img;
    if (im->mounted) return 0;

    if (!im->sqfs_path)
    {
        fprintf(stderr, "image_manager: no sqfs path for image\n");
        return -1;
    }

    /* ensure mount dir exists */
    if (mkdir_if_not_exist(im->mount_path) != 0) return -1;

    /* set up loop device */
    im->loop_dev = setup_loop(im->sqfs_path);
    if (!im->loop_dev)
    {
        fprintf(stderr, "image_manager: failed to set up loop device: %s\n", strerror(errno));
        return -1;
    }

    if (mount(im->loop_dev, im->mount_path, "squashfs", MS_RDONLY, NULL) != 0)
    {
        fprintf(stderr, "image_manager: mount failed: %s\n", strerror(errno));
        detach_loop(&im->loop_dev);
        return -1;
    }

    im->mounted = true;

    /* re-parse image-info.json — free old metadata that will be overwritten */
    if (im->id)          { free(im->id);          im->id = NULL; }
    if (im->name)        { free(im->name);        im->name = NULL; }
    if (im->tag)         { free(im->tag);         im->tag = NULL; }
    if (im->digest)      { free(im->digest);      im->digest = NULL; }
    if (im->arch)        { free(im->arch);        im->arch = NULL; }
    if (im->bundle_path) { free(im->bundle_path); im->bundle_path = NULL; }

    if (parse_image_info(im) != 0)
    {
        /* metadata was already loaded from runtime info, only bundle path is needed */
        im->bundle_path = path_join(im->mount_path, "bundle");
    }

    return 0;
}

void image_manager_umount_image(image_manager manager, image img)
{
    if (!manager || !img) return;

    image im = img;
    if (!im->mounted) return;

    umount2(im->mount_path, 0);
    detach_loop(&im->loop_dev);
    im->mounted = false;

    if (im->bundle_path) { free(im->bundle_path); im->bundle_path = NULL; }
}

int image_manager_foreach_safe(image_manager manager, image_manager_foreach_fn fn, void *user_data)
{
    if (!manager || !fn) return -1;
    image_manager mgr = manager;

    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &mgr->images)
    {
        image img = list_entry(pos, struct image_s, list);
        fn(img, user_data);
    }
    return 0;
}

image image_manager_find_by_id(image_manager manager, const char *id)
{
    if (!manager || !id) return NULL;
    image_manager mgr = manager;

    return map_get(mgr->id_map, (void *)id, strlen(id));
}

image image_manager_find_by_name(image_manager manager,
                                 const char *name,
                                 const char *tag)
{
    if (!manager || !name) return NULL;
    image_manager mgr = manager;

    if (!tag || !tag[0]) tag = DEFAULT_TAG;

    /* name is "registry/repository" (e.g. "docker.io/library/alpine").
     * The tag map key format is "registry/repository:tag". */
    size_t ln = strlen(name);
    size_t lt = strlen(tag);
    size_t key_len = ln + 1 + lt;
    char *key = malloc(key_len + 1);
    if (!key) return NULL;
    snprintf(key, key_len + 1, "%s:%s", name, tag);

    void *result = map_get(mgr->tag_map, key, key_len);
    free(key);
    if (result) return result;

    /* fallback: prepend default Docker registry to the name */
    size_t prefix_len = sizeof(DEFAULT_REGISTRY) - 1;
    size_t full_len = prefix_len + ln + 1 + lt;
    key = malloc(full_len + 1);
    if (!key) return NULL;
    snprintf(key, full_len + 1, "%s%s:%s", DEFAULT_REGISTRY, name, tag);

    result = map_get(mgr->tag_map, key, full_len);
    free(key);
    return result;
}

image image_manager_find_by_id_or_name(image_manager manager, const char *ref)
{
    if (!manager || !ref) return NULL;

    /* Try by id first */
    image img = image_manager_find_by_id(manager, ref);
    if (img) return img;

    /* Parse ref as name:tag */
    char *buf = strdup(ref);
    if (!buf) return NULL;

    char *colon = strrchr(buf, ':');
    const char *name = buf;
    const char *tag = NULL;
    if (colon)
    {
        *colon = '\0';
        tag = colon + 1;
    }

    img = image_manager_find_by_name(manager, name, tag);
    free(buf);
    return img;
}

/* -------------------------------------------------------------------------- */
/*  Image getters                                                              */
/* -------------------------------------------------------------------------- */

const char *image_get_name(const image img)
{
    return img ? img->name : NULL;
}

const char *image_get_tag(const image img)
{
    return img ? img->tag : NULL;
}

uint64_t image_get_created_at(const image img)
{
    return img ? img->created : 0;
}

const char *image_get_id(const image img)
{
    return img ? img->id : NULL;
}

const char *image_get_digest(const image img)
{
    return img ? img->digest : NULL;
}

bool image_get_mounted(const image img)
{
    return img ? img->mounted : false;
}

const char *image_get_bundle_path(const image img)
{
    if (!img) return NULL;
    return img->mounted ? img->bundle_path : NULL;
}


