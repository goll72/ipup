#ifndef COMMON_H
#define COMMON_H

#include <criterion/criterion.h>
#include <criterion/new/assert.h>

#define expect(...) \
    cr_expect(__VA_ARGS__, #__VA_ARGS__)

#define assert(...) \
    cr_assert(__VA_ARGS__, #__VA_ARGS__)

#endif /* COMMON_H */
