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

#define LOAD_FACTOR 0.85

#define MATCH(B, H, K, L)       \
    ((B)->hash == (H) &&        \
     (B)->key->len == (L) &&    \
     (memcmp((B)->key->data, (K), (L)) == 0))

#define map_decl(Td) \
static void map_foreach_##Td(struct map *map, bool (*func)(char *, size_t, Td *)) \
{ \
    for (size_t i = 0; i < map->size; i++) { \
       struct bucket *bucket = &map->buckets[i]; \
 \
        while (bucket && bucket->key) { \
            if (!func(bucket->key->data, bucket->key->len, bucket->data)) \
                return; \
            bucket = bucket->next; \
        } \
    } \
} \
\
static Td *map_get_set_##Td(struct map *map, const char *key, size_t len) \
{ \
    Td *value = map_get(map, key, len); \
 \
    if (value) \
        return value; \
 \
    value = calloc(1, sizeof(Td)); \
 \
    if (!value || !map_set(map, key, len, value)) \
        return NULL; \
 \
    return value; \
} struct map

struct map *map_init(size_t, hfunc_t);

void *map_get(struct map *, const char *, size_t);
bool map_set(struct map *, const char *, size_t, void *);

void map_free(struct map *);
bool map_resize(struct map *, size_t);

#endif /* MAP_H */
