#include <string.h>
#include <stdlib.h>

#include "map.h"

struct map *map_init(size_t size, hfunc_t hfunc)
{
    if (size == 0 || !hfunc)
        return NULL;

    struct map *map = calloc(1, sizeof(struct map));

    if (!map)
        goto err_map;

    struct bucket *buckets = calloc(size, sizeof(struct bucket));

    if (!buckets)
        goto err_buckets;

    map->size = size;
    map->hfunc = hfunc;
    map->buckets = buckets;

    return map;

err_buckets:
    free(buckets);
err_map:
    free(map);

    return NULL;
}

struct bucket *alloc_bucket(struct bucket *bucket)
{
    struct bucket *new = calloc(1, sizeof(struct bucket));

    if (!new)
        return NULL;

    while (bucket->next && bucket->next->key)
        bucket = bucket->next;

    return bucket->next = new;
}

static void free_buckets(struct map *map, bool free_keys)
{
    for (size_t i = 0, j = 0; i < map->size && j < map->used; i++) {
        struct bucket *old = &map->buckets[i];

        if (!old->key)
            continue;

        if (free_keys)
            free(old->key);

        old = old->next;
        j++;

        while (old) {
            struct bucket *tmp = old->next;
            if (free_keys)
                free(old->key);
            free(old);
            old = tmp;
            j++;
        }
    }

    free(map->buckets);
}

void map_free(struct map *map)
{
    free_buckets(map, true);
    free(map);
}

bool map_resize(struct map *map, size_t size)
{
    struct bucket *buckets = calloc(size, sizeof(struct bucket));

    for (size_t i = 0, j = 0; i < map->size && j < map->used; i++) {
        struct bucket *old = &map->buckets[i];
        struct bucket *base = old;

        if (!old->key)
            continue;

        while (old) {
            struct bucket *new = &buckets[old->hash % size];

            // Need to allocate a new bucket
            if (new->key && !(new = alloc_bucket(new))) {
                free_buckets(&(struct map) {
                    .size = size,
                    .used = j,
                    .buckets = buckets
                }, false);

                return false;
            }

            // The keys are reused for the new entries
            *new = *old;
            new->next = NULL;
            j++;

            struct bucket *tmp = old->next;
            if (old != base)
                free(old);
            old = tmp;
        }
    }

    free(map->buckets);
    map->buckets = buckets;
    map->size = size;

    return true;
}

void *map_get(struct map *map, const char *key, size_t len)
{
    uint64_t hash = map->hfunc(key, len);
    struct bucket *bucket = &map->buckets[hash % map->size];

    while (bucket && bucket->key) {
        if (MATCH(bucket, hash, key, len))
            return bucket->data;

        bucket = bucket->next;
    }

    return NULL;
}

bool map_set(struct map *map, const char *key, size_t len, void *elem)
{
    if ((double)(map->used + 1)/map->size >= LOAD_FACTOR)
        map_resize(map, map->size * 2);

    uint64_t hash = map->hfunc(key, len);
    struct bucket *bucket = &map->buckets[hash % map->size];
    struct bucket *prev = bucket;

    while (bucket->next && bucket->next->key) {
        if (MATCH(bucket, hash, key, len)) {
            bucket->data = elem;
            return true;
        }

        prev = bucket;
        bucket = bucket->next;
    }

    if ((bucket->key || bucket == prev->next) && !(bucket = alloc_bucket(bucket)))
        return false;
    bucket->hash = hash;
    bucket->data = elem;
    bucket->key = malloc(sizeof(struct key) + len);
    bucket->key->len = len;
    memcpy(bucket->key->data, key, len);

    map->used++;
    return true;
}

bool map_remove(struct map *map, char *key, size_t len)
{
    uint64_t hash = map->hfunc(key, len);
    struct bucket *bucket = &map->buckets[hash % map->size];
    struct bucket *prev = bucket;

    while (bucket && bucket->key) {
        if (MATCH(bucket, hash, key, len)) {
            free(bucket->key);

            if (prev == bucket) {
                // If the bucket has another following it, copy the contents,
                // otherwise zero the bucket
                struct bucket *tmp = bucket->next;
                if (tmp && tmp->key) {
                    *bucket = *tmp;
                    free(tmp);
                } else {
                    memset(bucket, 0, sizeof(struct bucket));
                }
            } else {
                // Linked list bucket, simply adjust prev's next pointer
                prev->next = bucket->next;
                free(bucket);
            }

            return true;
        }

        bucket = bucket->next;
        prev = bucket;
    }

    return false;
}
