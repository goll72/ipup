#ifndef MAP_H
#define MAP_H

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "xalloc.h"

#define MAP_LOAD_FACTOR 0.85

#define map_decl_ops(name, Th, Tk, Tv) \
struct map_ops_##name { \
    Th (*hash)(Tk key); \
    int (*compare)(Tk a, Tk b); \
    Tk (*key_alloc)(Tk key); \
    void (*key_free)(Tk key); \
    void (*val_free)(Tv val); \
}

#define map_bucket(name, Th, Tk, Tv) \
struct map_bucket_##name {    \
    uint8_t opts; \
    Tk key; \
    Tv val; \
    struct map_bucket_##name *next; \
    Th hash; \
}

#define map_struct(name, Th, Tk, Tv) \
struct map_##name { \
    size_t used, size; \
    struct map_ops_##name ops; \
    struct map_bucket_##name *buckets; \
}

#define MATCH(O, B, H, K) \
    (B->hash == H && ((O.compare && O.compare(B->key, K) == 0) || (B->key == K)))

#define map_decl(name, Th, Tk, Tv) \
map_decl_ops(name, Th, Tk, Tv); \
map_bucket(name, Th, Tk, Tv); \
map_struct(name, Th, Tk, Tv); \
\
static struct map_##name *map_new_##name(size_t size, struct map_ops_##name ops) \
{ \
    struct map_##name *map = xcalloc(1, sizeof *map); \
    \
    map->size = size; \
    map->ops = ops; \
    \
    map->buckets = xcalloc(size, sizeof *map->buckets); \
    \
    return map; \
} \
\
static struct map_bucket_##name *map_alloc_bucket_##name(struct map_bucket_##name *bucket) \
{ \
    struct map_bucket_##name *new = xcalloc(1, sizeof *new); \
    \
    while (bucket->next && bucket->next->opts) \
        bucket = bucket->next; \
    \
    return bucket->next = new; \
} \
\
static void map_free_buckets_##name(struct map_##name *map, bool deep_free) \
{ \
    for (size_t i = 0, j = 0; i < map->size && j < map->used; i++) { \
        struct map_bucket_##name *old = &map->buckets[i]; \
        \
        if (!old->opts) \
            continue; \
        \
        if (deep_free) {\
            if (map->ops.key_free) \
                map->ops.key_free(old->key); \
            if (map->ops.val_free) \
                map->ops.val_free(old->val); \
        } \
        \
        old = old->next; \
        j++; \
        \
        while (old) { \
            struct map_bucket_##name *tmp = old->next; \
            \
            if (deep_free) {\
                if (map->ops.key_free) \
                    map->ops.key_free(old->key); \
                if (map->ops.val_free) \
                    map->ops.val_free(old->val); \
            } \
            \
            free(old); \
            old = tmp; \
            j++; \
        } \
    } \
    \
    free(map->buckets); \
} \
\
static void map_free_##name(struct map_##name *map) \
{ \
    map_free_buckets_##name(map, true);  \
    free(map); \
} \
\
static bool map_get_##name(struct map_##name *map, Tk key, Tv *res) \
{ \
    uintmax_t hash = map->ops.hash ? (uintmax_t)map->ops.hash(key) : (uintmax_t)key; \
    struct map_bucket_##name *bucket = &map->buckets[hash % map->size]; \
    \
    while (bucket && bucket->opts) { \
        if (MATCH(map->ops, bucket, hash, key)) { \
            *res = bucket->val; \
            return true; \
        } \
        \
        bucket = bucket->next; \
    } \
    \
    return false; \
} \
\
static bool map_resize_##name(struct map_##name *map, size_t size) \
{ \
    struct map_bucket_##name *buckets = xcalloc(size, sizeof *buckets); \
 \
    for (size_t i = 0, j = 0; i < map->size && j < map->used; i++) { \
        struct map_bucket_##name *old = &map->buckets[i]; \
        struct map_bucket_##name *base = old; \
        \
        if (!old->opts) \
            continue; \
        \
        while (old) { \
            struct map_bucket_##name *new = &buckets[old->hash % size]; \
            \
            /* Need to allocate a new bucket */ \
            if (new->opts && !(new = map_alloc_bucket_##name(new))) { \
                map_free_buckets_##name(&(struct map_##name) { \
                    .size = size, \
                    .used = j, \
                    .buckets = buckets \
                }, false); \
                \
                return false; \
            } \
            \
            /* The keys are reused for the new entries */ \
            *new = *old; \
            new->next = NULL; \
            j++; \
            \
            struct map_bucket_##name *tmp = old->next; \
            if (old != base) \
                free(old); \
            old = tmp; \
        } \
    } \
    \
    free(map->buckets); \
    map->buckets = buckets; \
    map->size = size; \
    \
    return true; \
} \
\
static bool map_set_##name(struct map_##name *map, Tk key, Tv val) \
{ \
    if ((double)(map->used + 1)/map->size >= MAP_LOAD_FACTOR) \
        map_resize_##name(map, map->size * 2); \
    \
    uintmax_t hash = map->ops.hash ? (uintmax_t)map->ops.hash(key) : (uintmax_t)key; \
    struct map_bucket_##name *bucket = &map->buckets[hash % map->size]; \
    struct map_bucket_##name *prev = bucket; \
                                       \
    while (bucket->next && bucket->next->opts) { \
        if (MATCH(map->ops, bucket, hash, key)) { \
            bucket->val = val; \
            return true; \
        } \
        \
        prev = bucket; \
        bucket = bucket->next; \
    } \
    \
    if ((bucket->key || bucket == prev->next) && !(bucket = map_alloc_bucket_##name(bucket))) \
        return false; \
    \
    bucket->hash = hash; \
    bucket->val = val; \
    bucket->key = map->ops.key_alloc ? map->ops.key_alloc(key) : key; \
    bucket->opts = 1; \
    \
    map->used++; \
    return true; \
} \
\
static bool map_foreach_##name(struct map_##name *map, bool (*func)(Tk key, Tv val, void *arg), void *arg) \
{ \
    for (size_t i = 0; i < map->size; i++) { \
        struct map_bucket_##name *bucket = &map->buckets[i]; \
        \
        while (bucket && bucket->opts) { \
            if (!func(bucket->key, bucket->val, arg)) \
                return false; \
            \
            bucket = bucket->next; \
        } \
    } \
    \
    return true; \
} \
struct map_##name

#define map(name) struct map_##name
#define map_ops(name) struct map_ops_##name

#endif /* MAP_H */
