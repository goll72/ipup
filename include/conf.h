#include <stdint.h>

#include <ldns/ldns.h>
#include <ini.h>

enum rectype {
    REC_A,
    REC_AAAA,
    REC_BOTH
};

#define CONF_DELETE_EXISTING (1 << 1)
#define CONF_VERIFY_REACHABLE (1 << 2)
#define CONF_VERIFY_DUPLICATE (1 << 3)

typedef struct conf {
    char *server;
    uint16_t port;
    ldns_tsig_credentials cred;
    char *zone, *record;
    enum rectype rectype;
    uint8_t opts;
} conf_t;

struct map *readconf(FILE *conf, const char *filename);
