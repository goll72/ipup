#ifndef UTIL_H
#define UTIL_H

#include <string.h>

static void *mempcpy(void *dest, const void *src, size_t n)
{
    return (char *)memcpy(dest, src, n) + n;
}

#define _STR(x) #x
#define STR(X) _STR(x)

#endif
