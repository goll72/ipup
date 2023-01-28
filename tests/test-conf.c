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
