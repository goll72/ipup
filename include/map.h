#ifndef MAP_H
#define MAP_H

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint64_t hfunc_t(const char *, size_t);

struct map {
    size_t used, size;
    struct bucket *buckets;
    hfunc_t *hfunc;
};

struct bucket {
    uint64_t hash;
    struct key *key;
    void *data;
    struct bucket *next;
};

struct key {
    size_t len;
    char data[];
};

#define map_decl_bucket(Td) \
struct bucket_##Td { \
    uint64_t hash; \
    struct key *key; \
    Td *data; \
    struct bucket *next; \
};

#define MATCH(bucket, hash, key, len)   \
    ((bucket)->hash == (hash) &&        \
     (bucket)->key->len == (len) &&     \
     (memcmp((bucket)->key->data, (key), (len)) == 0))

#define LOAD_FACTOR 0.85

#define map_decl_funcs(Td) \
Td *map_get_##Td(struct map *map, const char *key, size_t len) \
{ \
    uint64_t hash = map->hfunc(key, len); \
    struct bucket *bucket = &map->buckets[hash % map->size]; \
 \
    while (bucket && bucket->key) { \
 \
        if (MATCH(bucket, hash, key, len)) \
            return bucket->data; \
 \
        bucket = bucket->next; \
    } \
 \
    return NULL; \
} \
 \
bool map_set_##Td(struct map *map, const char *key, size_t len, Td *elem) \
{ \
    if ((double)(map->used + 1)/map->size >= LOAD_FACTOR) \
        map_resize(map, map->size * 2); \
 \
    uint64_t hash = map->hfunc(key, len); \
    struct bucket *bucket = &map->buckets[hash % map->size]; \
    struct bucket *prev = bucket; \
 \
    while (bucket->next && bucket->next->key) { \
        if (MATCH(bucket, hash, key, len)) {  \
            bucket->data = elem; \
            return true; \
        } \
 \
        prev = bucket; \
        bucket = bucket->next; \
    } \
 \
    if ((bucket->key || bucket == prev->next) && !(bucket = alloc_bucket(bucket))) \
        return false; \
    bucket->hash = hash; \
    bucket->data = elem; \
    bucket->key = malloc(sizeof(struct key) + len); \
    bucket->key->len = len; \
    memcpy(bucket->key->data, key, len); \
 \
    map->used++; \
    return true; \
}

/* Allows for using a semicolon after the macro invocation */
#define map_decl(Td) \
    map_decl_bucket(Td) map_decl_funcs(Td) struct map

static inline struct bucket *alloc_bucket(struct bucket *bucket)
{
    struct bucket *new = calloc(1, sizeof(struct bucket));

    if (!new)
        return NULL;

    while (bucket->next && bucket->next->key)
        bucket = bucket->next;

    return bucket->next = new;
}

struct map *map_init(size_t, hfunc_t);
bool map_resize(struct map *, size_t);

#endif /* MAP_H */
