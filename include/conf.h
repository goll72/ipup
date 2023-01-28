#include <stdint.h>

#include <ldns/resolver.h>
#include <ini.h>

#include "map.h"

#define CONF_OPT_IFACE_DELETE_EXISTING (1 << 0)
#define CONF_OPT_IFACE_RESPECT_TTL     (1 << 1)

typedef struct conf_serv {
    ldns_rdf *server;
    ldns_rdf *zone;
    ldns_rdf *record;
    ldns_resolver *resolv;
    ldns_tsig_credentials cred;
    uint8_t opts;
} conf_serv;

typedef struct conf_if {
    conf_serv *server;
    ldns_rdf *zone;
    ldns_rdf *record;
    uint32_t ttl;
    uint8_t opts;
} conf_if;

struct conf {
    map(conf_serv) *servers;
    map(conf_if) *ifaces;
};

struct conf conf_read(FILE *, const char *);
void conf_free(struct conf);
