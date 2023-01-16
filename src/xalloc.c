#include <errno.h>

#include "xalloc.h"

#define PARAM(...) __VA_ARGS__

XALLOC(malloc, PARAM(size_t size), PARAM(size));
XALLOC(calloc, PARAM(size_t nmemb, size_t size), PARAM(nmemb, size));
XALLOC(realloc, PARAM(void *ptr, size_t size), PARAM(ptr, size));
