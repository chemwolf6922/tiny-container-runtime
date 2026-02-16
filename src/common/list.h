/**
 * @file list.h
 * @brief Linux kernel-style intrusive doubly-linked list.
 *
 * Minimal subset of the kernel list API. Each struct that wants to be in a
 * list embeds a `struct list_head` member and uses `list_entry` /
 * `container_of` to recover the outer struct.
 */
#pragma once

#include <stddef.h>

struct list_head
{
    struct list_head *prev;
    struct list_head *next;
};

/* ── Initialisation ──────────────────────────────────────────────────────── */

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

/**
 * @brief Initialise a list head at runtime.
 *
 * @param head Pointer to the list head to initialise.
 */
static inline void list_head_init(struct list_head *head)
{
    head->prev = head;
    head->next = head;
}

/* ── Internal helpers ────────────────────────────────────────────────────── */

static inline void list__insert(struct list_head *entry,
                                struct list_head *prev,
                                struct list_head *next)
{
    next->prev = entry;
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
}

/* ── Add / delete ────────────────────────────────────────────────────────── */

/**
 * @brief Insert an entry immediately after head (stack / LIFO order).
 *
 * @param entry The new element to insert.
 * @param head  The list head to insert after.
 */
static inline void list_add(struct list_head *entry, struct list_head *head)
{
    list__insert(entry, head, head->next);
}

/**
 * @brief Insert an entry immediately before head (queue / FIFO order).
 *
 * @param entry The new element to insert.
 * @param head  The list head to insert before.
 */
static inline void list_add_tail(struct list_head *entry, struct list_head *head)
{
    list__insert(entry, head->prev, head);
}

/**
 * @brief Remove an entry from its list.
 * @warning The entry is left in an undefined state after removal.
 *
 * @param entry The element to remove.
 */
static inline void list_del(struct list_head *entry)
{
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;
    entry->prev = NULL;
    entry->next = NULL;
}

/* ── Queries ─────────────────────────────────────────────────────────────── */

/**
 * @brief Check whether a list is empty.
 *
 * @param head Pointer to the list head.
 * @return Non-zero if the list is empty, 0 otherwise.
 */
static inline int list_empty(const struct list_head *head)
{
    return head->next == head;
}

/* ── container_of / list_entry ───────────────────────────────────────────── */

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
#endif

/**
 * @brief Get the struct for this list node.
 *
 * @param ptr    Pointer to the struct list_head member.
 * @param type   Type of the enclosing struct.
 * @param member Name of the list_head member within @p type.
 */
#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

/* ── Iteration ───────────────────────────────────────────────────────────── */

/**
 * @brief Iterate over a list.
 *
 * @param pos  A struct list_head * used as loop cursor.
 * @param head Pointer to the list head.
 */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * @brief Iterate over a list, safe against removal of the current node.
 *
 * @param pos  A struct list_head * used as loop cursor.
 * @param tmp  Another struct list_head * used as temporary storage.
 * @param head Pointer to the list head.
 */
#define list_for_each_safe(pos, tmp, head) \
    for (pos = (head)->next, tmp = pos->next; \
         pos != (head); \
         pos = tmp, tmp = pos->next)
