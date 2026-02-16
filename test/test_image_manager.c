/**
 * @file test_image_manager.c
 * @brief Integration tests for the image manager.
 *
 * Must be run as root (mount/umount require privileges).
 * Requires a pre-built tcr squashfs image (from tcr-create-image.sh).
 *
 * Usage: sudo ./test_image_manager <path-to-image.sqfs>
 */
#define _GNU_SOURCE
#include "image_manager.h"
#include "test_util.h"

#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/* test_root is always /tmp/tcr_test_image_XXXXXX — well under 128 bytes */
static char test_root[128];
static const char *sqfs_path;   /* user-provided, not owned */

/** nftw callback for recursive delete. */
static int rm_cb(const char *path, const struct stat *st, int flag, struct FTW *ftw)
{
    (void)st; (void)flag; (void)ftw;
    return remove(path);
}

static void rm_rf(const char *path)
{
    nftw(path, rm_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* -------------------------------------------------------------------------- */
/*  Tests                                                                      */
/* -------------------------------------------------------------------------- */

static void test_new_and_free(void)
{
    printf("  test_new_and_free... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_basic", test_root);

    image_manager mgr = image_manager_new(root);
    CHECK(mgr != NULL, "image_manager_new should succeed");

    image_manager_free(mgr, true);
    free(root);
    printf("OK\n");
}

static void test_lock_exclusive(void)
{
    printf("  test_lock_exclusive... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_lock", test_root);

    image_manager mgr1 = image_manager_new(root);
    CHECK(mgr1 != NULL, "first manager should succeed");

    /* second manager on same root should fail */
    image_manager mgr2 = image_manager_new(root);
    CHECK(mgr2 == NULL, "second manager on same root should fail");

    image_manager_free(mgr1, true);

    /* after freeing, should be able to create again */
    image_manager mgr3 = image_manager_new(root);
    CHECK(mgr3 != NULL, "manager after free should succeed");
    image_manager_free(mgr3, true);

    free(root);
    printf("OK\n");
}

static void test_load_and_query(void)
{
    printf("  test_load_and_query... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_load", test_root);

    image_manager mgr = image_manager_new(root);
    CHECK(mgr != NULL, "manager creation");

    image img = image_manager_load(mgr, sqfs_path);
    CHECK(img != NULL, "load image should succeed");

    /* image-info.json fields should be populated */
    const char *name = image_get_name(img);
    const char *tag = image_get_tag(img);
    const char *digest = image_get_digest(img);
    CHECK(name != NULL && name[0] != '\0', "name should be set");
    CHECK(tag != NULL && tag[0] != '\0', "tag should be set");
    CHECK(digest != NULL && digest[0] != '\0', "digest should be set");
    CHECK(image_get_mounted(img) == true, "should be mounted after load");
    CHECK(image_get_bundle_path(img) != NULL, "bundle path should be set");
    CHECK(image_get_created_at(img) > 0, "created timestamp should be set");

    printf("(loaded %s:%s) ", name, tag);

    /* find by digest */
    image found = image_manager_find_by_digest(mgr, digest);
    CHECK(found == img, "find_by_digest should return same image");

    /* find by name / tag */
    found = image_manager_find_by_name(mgr, name, tag);
    CHECK(found == img, "find_by_name should return same image");

    /* find by name with NULL tag (should default to "latest") */
    if (strcmp(tag, "latest") == 0)
    {
        found = image_manager_find_by_name(mgr, name, NULL);
        CHECK(found == img, "find_by_name with NULL tag should default to latest");
    }

    /* find by short name (without docker.io/library/ prefix) */
    const char *docker_prefix = "docker.io/library/";
    size_t prefix_len = strlen(docker_prefix);
    if (strncmp(name, docker_prefix, prefix_len) == 0)
    {
        const char *short_name = name + prefix_len;
        found = image_manager_find_by_name(mgr, short_name, tag);
        CHECK(found == img, "find_by_name with short name should fallback to full name");
    }

    /* not found cases */
    found = image_manager_find_by_digest(mgr, "sha256:nonexistent_00000000");
    CHECK(found == NULL, "find nonexistent digest should return NULL");

    found = image_manager_find_by_name(mgr, name, "nonexistent_tag_00000000");
    CHECK(found == NULL, "find nonexistent tag should return NULL");

    image_manager_free(mgr, true);
    free(root);
    printf("OK\n");
}

static void test_duplicate_digest_rejected(void)
{
    printf("  test_duplicate_digest_rejected... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_dup", test_root);

    image_manager mgr = image_manager_new(root);
    CHECK(mgr != NULL, "manager creation");

    image img1 = image_manager_load(mgr, sqfs_path);
    CHECK(img1 != NULL, "first load should succeed");

    /* loading same sqfs again should fail (same digest) */
    image img2 = image_manager_load(mgr, sqfs_path);
    CHECK(img2 == NULL, "duplicate digest should be rejected");

    image_manager_free(mgr, true);
    free(root);
    printf("OK\n");
}

static void test_mount_umount(void)
{
    printf("  test_mount_umount... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_mnt", test_root);

    image_manager mgr = image_manager_new(root);
    CHECK(mgr != NULL, "manager creation");

    image img = image_manager_load(mgr, sqfs_path);
    CHECK(img != NULL, "load image");
    CHECK(image_get_mounted(img) == true, "mounted after load");

    /* unmount */
    image_manager_umount_image(mgr, img);
    CHECK(image_get_mounted(img) == false, "unmounted");
    CHECK(image_get_bundle_path(img) == NULL, "bundle path null when unmounted");

    /* re-mount */
    int rc = image_manager_mount_image(mgr, img);
    CHECK(rc == 0, "re-mount should succeed");
    CHECK(image_get_mounted(img) == true, "mounted again");
    CHECK(image_get_bundle_path(img) != NULL, "bundle path set after re-mount");

    /* mount already mounted — should be idempotent */
    rc = image_manager_mount_image(mgr, img);
    CHECK(rc == 0, "mount idempotent");

    image_manager_free(mgr, true);
    free(root);
    printf("OK\n");
}

static void test_remove(void)
{
    printf("  test_remove... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_rm", test_root);

    image_manager mgr = image_manager_new(root);
    CHECK(mgr != NULL, "manager creation");

    image img = image_manager_load(mgr, sqfs_path);
    CHECK(img != NULL, "load image");
    char *digest = strdup(image_get_digest(img));

    image_manager_remove(mgr, img);

    /* should no longer be findable */
    image found = image_manager_find_by_digest(mgr, digest);
    CHECK(found == NULL, "removed image should not be findable");
    free(digest);

    image_manager_free(mgr, true);
    free(root);
    printf("OK\n");
}

static int foreach_counter;
static void count_images(image img, void *user_data)
{
    (void)img;
    (void)user_data;
    foreach_counter++;
}

static void test_foreach(void)
{
    printf("  test_foreach... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_each", test_root);

    image_manager mgr = image_manager_new(root);
    CHECK(mgr != NULL, "manager creation");

    foreach_counter = 0;
    image_manager_foreach_safe(mgr, count_images, NULL);
    CHECK(foreach_counter == 0, "empty list");

    image img = image_manager_load(mgr, sqfs_path);
    CHECK(img != NULL, "load");

    foreach_counter = 0;
    image_manager_foreach_safe(mgr, count_images, NULL);
    CHECK(foreach_counter == 1, "one image");

    image_manager_free(mgr, true);
    free(root);
    printf("OK\n");
}

static void test_persistence(void)
{
    printf("  test_persistence... ");

    char *root = NULL;
    asprintf(&root, "%s/mgr_persist", test_root);
    char *saved_digest = NULL;

    /* first session: load image, leave mounted */
    {
        image_manager mgr = image_manager_new(root);
        CHECK(mgr != NULL, "manager creation (session 1)");

        image img = image_manager_load(mgr, sqfs_path);
        CHECK(img != NULL, "load image");
        saved_digest = strdup(image_get_digest(img));

        /* free without unmounting */
        image_manager_free(mgr, false);
    }

    /* second session: image should be rediscovered and still mounted */
    {
        image_manager mgr = image_manager_new(root);
        CHECK(mgr != NULL, "manager creation (session 2)");

        image found = image_manager_find_by_digest(mgr, saved_digest);
        CHECK(found != NULL, "image rediscovered");
        CHECK(image_get_mounted(found) == true, "image still mounted");
        CHECK(image_get_bundle_path(found) != NULL, "bundle path available");

        image_manager_free(mgr, true);
    }

    /* third session: after umount_all, image should exist but be unmounted */
    {
        /* the image's on-disk state (UUID dir + runtime info) persists
         * from session 1, even though session 2 unmounted it.  The new
         * manager should rediscover it in unmounted state. */
        image_manager mgr = image_manager_new(root);
        CHECK(mgr != NULL, "manager creation (session 3a)");

        image found = image_manager_find_by_digest(mgr, saved_digest);
        CHECK(found != NULL, "image rediscovered (session 3a)");
        CHECK(image_get_mounted(found) == false, "unmounted after umount_all");

        image_manager_free(mgr, false);

        /* new session should still find it unmounted */
        mgr = image_manager_new(root);
        CHECK(mgr != NULL, "manager creation (session 3b)");

        image found2 = image_manager_find_by_digest(mgr, saved_digest);
        CHECK(found2 != NULL, "unmounted image rediscovered");
        CHECK(image_get_mounted(found2) == false, "still unmounted");
        CHECK(image_get_bundle_path(found2) == NULL, "no bundle path when unmounted");

        /* can re-mount */
        int rc = image_manager_mount_image(mgr, found2);
        CHECK(rc == 0, "re-mount after restart");
        CHECK(image_get_mounted(found2) == true, "mounted again");

        image_manager_free(mgr, true);
    }

    free(saved_digest);
    free(root);
    printf("OK\n");
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                       */
/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <path-to-image.sqfs>\n", argv[0]);
        fprintf(stderr, "\nCreate a test image with:\n");
        fprintf(stderr, "  tcr-create-image.sh docker.io/library/alpine:latest\n");
        return 1;
    }

    if (geteuid() != 0)
    {
        fprintf(stderr, "error: test_image_manager must be run as root (mount requires privileges)\n");
        return 1;
    }

    sqfs_path = argv[1];

    /* verify the image file exists */
    struct stat st;
    if (stat(sqfs_path, &st) != 0 || !S_ISREG(st.st_mode))
    {
        fprintf(stderr, "error: not a regular file: %s\n", sqfs_path);
        return 1;
    }
    printf("Using test image: %s\n", sqfs_path);

    /* create temp test root — always short, well under 128 bytes */
    snprintf(test_root, sizeof(test_root), "/tmp/tcr_test_image_XXXXXX");
    if (!mkdtemp(test_root))
    {
        perror("mkdtemp");
        return 1;
    }
    printf("Test root: %s\n", test_root);

    printf("Running image_manager tests:\n");

    test_new_and_free();
    test_lock_exclusive();
    test_load_and_query();
    test_duplicate_digest_rejected();
    test_mount_umount();
    test_remove();
    test_foreach();
    test_persistence();

    printf("All image_manager tests passed!\n");

    rm_rf(test_root);
    return 0;
}
