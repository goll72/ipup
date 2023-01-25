#include "common.h"

#include "conf.c"

Test(conf, str_to_time_duration_works_on_valid_inputs) {
    unsigned long long out = 0;

    expect(str_to_time_duration(&out, "1d 1h 1m 1s "));
    expect(eq(ullong, out, 86400 + 3600 + 60 + 1));

    expect(str_to_time_duration(&out, "     5s"));
    expect(eq(ullong, out, 5));

    expect(str_to_time_duration(&out, "300h 30000s"));
    expect(eq(ullong, out, 1080000 + 30000));
}

Test(conf, str_to_time_duration_bails_on_invalid_inputs) {
    unsigned long long out = 0;

    expect(not(str_to_time_duration(&out, "1")));
    expect(not(str_to_time_duration(&out, "2d3d")));
    expect(not(str_to_time_duration(&out, "1sss")));
    expect(not(str_to_time_duration(&out, "3g,")));
}

Test(conf, servconf_valid_is_valid) {
    struct map *map = map_init(4, murmurhash64a);

    assert(map);

    expect(handle_servconf(map, "server", "port", "1234"));
    expect(handle_servconf(map, "server", "key-algo", "hmac-sha1"));
    expect(handle_servconf(map, "server", "key-algo", "HMAC-SHA224"));
    expect(handle_servconf(map, "server", "max-retry", "0"));
    expect(handle_servconf(map, "server", "verify-update", "true"));

    servconf_t *servconf = map_get(map, "server", sizeof("server") - 1);

    assert(servconf);
    free_servconf("server", sizeof("server") - 1, servconf);
}
