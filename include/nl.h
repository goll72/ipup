#ifndef NL_H
#define NL_H

// Forward declaration needed to silence warning
struct map;

struct nl_cache_mngr *nl_run(struct map *);
void nl_free(struct nl_cache_mngr *);

#endif /* NL_H */
