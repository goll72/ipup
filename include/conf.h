#include <stdint.h>

#include <ldns/resolver.h>
#include <ini.h>

#define CONF_OPT_SERVER_VERIFY_UPDATE  (1 << 0)

#define CONF_OPT_IFACE_DELETE_EXISTING (1 << 0)
#define CONF_OPT_IFACE_RESPECT_TTL     (1 << 1)

typedef struct conf_server {
    ldns_rdf *server;
    ldns_rdf *zone;
    ldns_rdf *record;
    ldns_resolver *resolv;
    ldns_tsig_credentials cred;
    uint8_t opts;
} servconf_t;

typedef struct conf_iface {
    struct conf_server *server;
    ldns_rdf *zone;
    ldns_rdf *record;
    uint32_t ttl;
    uint8_t opts;
} ifconf_t;

typedef struct conf {
    struct map *servers;
    struct map *ifaces;
} conf_t;

struct conf conf_read(FILE *, const char *);
void conf_free(struct conf);
