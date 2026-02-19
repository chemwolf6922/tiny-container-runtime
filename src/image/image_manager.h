#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct image_manager_s* image_manager;

/**
 * @brief Create a new image manager with the given root path.
 * @warning DO NOT use nested image managers. That's not useful and asking for trouble.
 * 
 * @param root_path The root path for the image manager.
 * @return image_manager The created image manager. NULL if failed.
 */
image_manager image_manager_new(const char* root_path);

/**
 * @brief Free the given image manager.
 * 
 * @param manager The image manager to free.
 * @param umount_all Whether to unmount all images before freeing.
 */
void image_manager_free(image_manager manager, bool umount_all);

typedef struct image_s* image;

/**
 * @brief Load and mount an image from the given path.
 * @warning The image's path MUST be stable. Moving the image will cause undefined behavior.
 * @note The image is owned by the manager.
 * 
 * @param manager The image manager to use for loading the image.
 * @param path The path to the tcr image.
 * @return image A reference to the loaded image. NULL if failed.
 */
image image_manager_load(image_manager manager, const char* path);

/**
 * @brief Remove the given image from the manager.
 * @warning After this call. The image is no longer valid and should not be used.
 * 
 * @param manager The image manager to use for removing the image.
 * @param img The image to remove.
 */
void image_manager_remove(image_manager manager, image img);

/**
 * @brief Mount the given image if not.
 * 
 * @param manager The image manager to use for mounting the image.
 * @param img The image to mount.
 * @return int 0 if the image is already mounted or successfully mounted. -1 if failed.
 */
int image_manager_mount_image(image_manager manager, image img);

/**
 * @brief Unmount the given image if mounted.
 * 
 * @param manager The image manager to use for unmounting the image.
 * @param img The image to unmount.
 */
void image_manager_umount_image(image_manager manager, image img);

typedef void (*image_manager_foreach_fn)(image img, void* user_data);

/**
 * @brief Iterate over all images in the manager and call the given function for each image.
 * 
 * @param manager The image manager to iterate over.
 * @param fn The function to call for each image.
 * @param user_data User data to pass to the function.
 * @return int 0 on success, -1 if failed.
 */
int image_manager_foreach_safe(image_manager manager, image_manager_foreach_fn fn, void* user_data);

/**
 * @brief Find an image by its id (xxh64 hash of the digest in hex).
 * 
 * @param manager The image manager to use for finding the image.
 * @param id The id of the image to find.
 * @return image A reference to the found image. NULL if not found.
 */
image image_manager_find_by_id(image_manager manager, const char* id);

/**
 * @brief Find an image by its name and tag.
 * 
 * If tag is NULL, defaults to "latest".
 * If a direct name:tag match is not found, retries with "docker.io/library/" prefix
 * prepended to the name (since users commonly omit the default Docker registry).
 * 
 * @param manager The image manager to use for finding the image.
 * @param name The name of the image ("registry/repository", e.g. "docker.io/library/alpine").
 * @param tag The tag of the image to find. NULL defaults to "latest".
 * @return image A reference to the found image. NULL if not found.
 */
image image_manager_find_by_name(image_manager manager, const char* name, const char* tag);

/**
 * @brief Find an image by id or name:tag reference.
 *
 * First tries to find the image by id. If not found, parses the reference as
 * "name:tag" (defaulting tag to "latest" if omitted) and searches by name.
 *
 * @param manager The image manager to use for finding the image.
 * @param ref The image reference (id or "name:tag").
 * @return image A reference to the found image. NULL if not found.
 */
image image_manager_find_by_id_or_name(image_manager manager, const char* ref);

/**
 * @brief Get the name of the given image.
 * 
 * @param img The image to get the name from.
 * @return const char* The name of the image ("registry/repository", e.g. "docker.io/library/alpine").
 */
const char* image_get_name(const image img);

/**
 * @brief Get the tag of the given image.
 * 
 * @param img The image to get the tag from.
 * @return const char* The tag of the image. This could be NULL if the image's tag is replaced by a newer image.
 */
const char* image_get_tag(const image img);

/**
 * @brief Get the creation time of the given image.
 * 
 * @param img The image to get the creation time from.
 * @return uint64_t The creation time of the image.
 */
uint64_t image_get_created_at(const image img);

/**
 * @brief Get the id of the given image (xxh64 hash of the digest in hex).
 * 
 * @param img The image to get the id from.
 * @return const char* The id of the image.
 */
const char* image_get_id(const image img);

/**
 * @brief Get the digest of the given image.
 * 
 * @param img The image to get the digest from.
 * @return const char* The digest of the image.
 */
const char* image_get_digest(const image img);

/**
 * @brief Check if the given image is mounted.
 * 
 * @param img The image to check.
 * @return bool True if the image is mounted, false otherwise.
 */
bool image_get_mounted(const image img);

/**
 * @brief Get the bundle path of the given image.
 * 
 * @param img The image to get the bundle path from.
 * @return const char* The bundle path of the image. NULL if the image is not mounted.
 */
const char* image_get_bundle_path(const image img);
