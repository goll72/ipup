#include <string.h>
#include <stdint.h>

static uint64_t murmurhash64a(const char *key)
{
    size_t len = strlen(key);

    const uint64_t m = 0xc6a4a7935bd1e995LLU;
    const int r = 47;

    uint64_t h = 0x73527d6e67f60a2cLLU ^ (len * m);

    const uint8_t *data = (const uint8_t *)key;
    const uint8_t *end = data + len - (len & 7);

    while (data != end) {
        uint64_t k;

        memcpy(&k, data, 8);

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;

        data += 8;
    }

    switch (len & 7) {
        case 7: h ^= (uint64_t)data[6] << 48;
        case 6: h ^= (uint64_t)data[5] << 40;
        case 5: h ^= (uint64_t)data[4] << 32;
        case 4: h ^= (uint64_t)data[3] << 24;
        case 3: h ^= (uint64_t)data[2] << 16;
        case 2: h ^= (uint64_t)data[1] << 8;
        case 1: h ^= (uint64_t)data[0];
        h *= m;
    }

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
}
