#include <stdint.h>

#include <ldns/resolver.h>
#include <ini.h>

#define CONF_OPT_DELETE_EXISTING (1 << 0)
#define CONF_OPT_RESPECT_TTL     (1 << 1)
#define CONF_OPT_VERIFY_UPDATE   (1 << 2)

typedef struct conf {
    ldns_rdf *server;
    ldns_rdf *zone;
    ldns_rdf *record;
    ldns_resolver *resolv;
    ldns_tsig_credentials cred;
    uint32_t ttl;
    uint8_t opts;
} conf_t;

struct map *conf_read(FILE *, const char *);
void conf_free(struct map *);
