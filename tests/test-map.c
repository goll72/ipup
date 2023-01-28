#include "common.h"

#include "map.h"
#include "hash.h"

map_decl(str, uint64_t, const char *, uint64_t);
map_decl(self, uint64_t, uint64_t, uint64_t);

map_ops(str) owning = {
    .key_alloc = (const char *(*)(const char *))strdup,
    .key_free = (void (*)(const char *))free,
    .compare = strcmp,
    .hash = murmurhash64a
};

uint64_t map_get_self_wrap(map(self) *map, uint64_t key)
{
    uint64_t res;
    bool found = map_get_self(map, key, &res);

    cr_assert(found, "Key not found in map");

    return res;
}

Test(map, new_entries_of_same_hash_override_previous) {
    map_ops(self) ops = {0};

    map(self) *map = map_new_self(16, ops);

    for (uint64_t i = 0; i < floor(16 * MAP_LOAD_FACTOR); i++)
        map_set_self(map, i, i);

    uint64_t used = 0;

    for (uint64_t i = 0; i < 2; i++) {
        for (uint64_t j = map->size * (i + 1); j < map->size * (i + 2); j++) {
            map_set_self(map, j, j % map->size);
            used++;
            map->used--;
        }
    }

    map_set_self(map, 63, 62);
    map_set_self(map, 31, 31);
    map_set_self(map, 24, 24);
    map_set_self(map, 63, 63);
    map_set_self(map, 0, 1);

    cr_assert(eq(u64, map_get_self_wrap(map, 63), 63));
    cr_assert(eq(u64, map_get_self_wrap(map, 31), 31));
    cr_assert(eq(u64, map_get_self_wrap(map, 24), 24));
    cr_assert(eq(u64, map_get_self_wrap(map, 0), 1));
    cr_assert(eq(u64, map_get_self_wrap(map, 54), 54 % map->size));
    cr_assert(eq(u64, map_get_self_wrap(map, 19), 19 % map->size));

    map->used += used;
    map_free_self(map);
}

#include <criterion/parameterized.h>

ParameterizedTestParameters(map, owning_map_works) {
    static size_t initial_size[] = { 1, 2, 4, 5, 8, 12, 16, 32 };
    size_t param_size = sizeof initial_size / sizeof initial_size[0];
    return cr_make_param_array(size_t, initial_size, param_size);
}

static void loop_gen_rnd(char *buf, pcg32_random_t *state)
{
    for (size_t j = 0; j < 24; j++) {
        uint64_t rand64 = pcg32_random_r(state);
        uint8_t *rand = (uint8_t *)&rand64;

        for (size_t k = 0; k < 8; k++)
            *buf++ = *rand++;
    }
}

ParameterizedTest(size_t *size, map, owning_map_works) {
    pcg32_random_t state = pcgstate;

    map(str) *map = map_new_str(*size, owning);

    for (size_t i = 0; i < 16; i++) {
        char *buf = (char[256]){0};

        uint64_t val = pcg32_random_r(&state);

        loop_gen_rnd(buf, &state);

        map_set_str(map, buf, val);
    }

    cr_assert(eq(sz, map->used, 16), "Wrong map size");

    state = pcgstate;

    for (size_t i = 0; i < 16; i++) {
        char *buf = (char[256]){0};

        uint64_t val = pcg32_random_r(&state);

        loop_gen_rnd(buf, &state);

        uint64_t res;
        bool found = map_get_str(map, buf, &res);

        cr_assert(found, "Key not found in map");
        cr_assert(eq(u64, val , res));
    }

    map_free_str(map);
}
