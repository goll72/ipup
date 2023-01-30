#ifndef NL_H
#define NL_H

// Forward declaration needed to silence warning
struct conf;

struct nl_cache_mngr *nl_sync(struct conf *);

void nl_run(struct nl_cache_mngr *);
void nl_free(struct nl_cache_mngr *);

#endif /* NL_H */
