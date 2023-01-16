#ifndef XALLOC_H
#define XALLOC_H

#include <err.h>
#include <stdint.h>
#include <stdlib.h>

#define XALLOC(func, paramdecl, params)             \
    void *x##func(paramdecl)                        \
    {                                               \
        void *ret = func(params);                   \
                                                    \
        if (!ret)                                   \
            errx(2, "Failed to allocate memory");   \
                                                    \
        return ret;                                 \
    } struct ok


void *xmalloc(size_t);
void *xcalloc(size_t, size_t);
void *xrealloc(void *, size_t);
void *xreallocarray(void *, size_t, size_t);

#endif /* XALLOC_H */
