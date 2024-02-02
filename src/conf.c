#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "log.h"
#include "dns.h"
#include "map.h"
#include "hash.h"
#include "conf.h"
#include "xalloc.h"

map_decl(conf_serv, uint64_t, const char *, conf_serv *);
map_decl(conf_if, uint64_t, const char *, conf_if *);

#define BOOL_IS_TRUE(x)                 \
    (strcasecmp((x), "yes") == 0 ||     \
     strcasecmp((x), "true") == 0 ||    \
     strcasecmp((x), "1") == 0)

#define BOOL_IS_FALSE(x)                \
    (strcasecmp((x), "no") == 0 ||      \
     strcasecmp((x), "false") == 0 ||   \
     strcasecmp((x), "0") == 0)

#define BOOL_FLAG(x, var, flag)         \
    if (BOOL_IS_TRUE((x))) {            \
        (var) |= (flag);                \
    } else if (BOOL_IS_FALSE((x))) {    \
        (var) &= ~(flag);               \
    } else {                            \
        return 0;                       \
    }

#define TO_NUM_COND_MSG(out, x, cond, ...)    \
    char *end;                                \
    errno = 0;                                \
    (out) = strtoull((x), &end, 10);          \
                                              \
    if ((errno || *end != '\0') || !(cond)) { \
        log(LOG_NOTICE, __VA_ARGS__);         \
        return 0;                             \
    }

// Private, used to check if a server is
// not referenced by any other interface
#define CONF_OPT_SERVER_USED_BY_IFACE (1 << 7)

static bool str_to_time_duration(unsigned long long *out, const char *str)
{
    unsigned long long duration = 0;
    const char *orig = str;

    for (uint32_t mask = 0, prev = 0; ; prev = mask) {
        if (*str == '\0') {
            *out = duration;
            return true;
        }

        char *end;
        errno = 0;
        unsigned long long base = strtoull(str, &end, 10);

        if (errno || end == orig)
            return false;

        if (*end == 'd')
            base *= 86400;
        else if (*end == 'h')
            base *= 3600;
        else if (*end == 'm')
            base *= 60;
        else if (*end == 's' || *end == ' ' || *end == '\t')
            ;
        else
            return false;

        duration += base;
        str = end + 1;

        if (*end == ' ' || *end == '\t')
            continue;

        // Compares the specifier bitmask with the previous
        // one, if a bit that was set got unset a specifier
        // was repeated, making the sequence invalid
        uint32_t val = mask ^= (1 << (*end - 'd'));
        uint8_t bset, bsetprev;

        for (bset = 0; val; bset++)
            val &= val - 1;
        for (bsetprev = 0; prev; bsetprev++)
            prev &= prev - 1;

        if (bset - bsetprev != 1)
            return false;
    }
}

static int handle_servconf(struct conf *conf, const char *server,
        const char *name, const char *value)
{
    map(conf_serv) *map = conf->servers;
    conf_serv *servconf;

    if (!map_get_conf_serv(map, server, &servconf)) {
        servconf = xcalloc(1, sizeof(conf_serv));
        map_set_conf_serv(map, server, servconf);
    }

    if (!servconf->resolv)
        servconf->resolv = ldns_resolver_new();

    if (strcmp(name, "fqdn") == 0) {
        ldns_rdf *fqdn = ldns_dname_new_frm_str(value);
        dns_resolver_init_frm_dname(servconf->resolv, fqdn);
        ldns_resolver_set_domain(servconf->resolv, fqdn);

        ldns_rdf_deep_free(servconf->server);
        servconf->server = fqdn;
    } else if (strcmp(name, "port") == 0) {
        unsigned long long port;
        TO_NUM_COND_MSG(port, value, (port != 0 && port <= 65535),
                "Invalid port number: %s", value);

        ldns_resolver_set_port(servconf->resolv, port);
    } else if (strcmp(name, "key-name") == 0) {
        free((void *)servconf->cred.keyname);
        servconf->cred.keyname = strdup(value);
    } else if (strcmp(name, "key-secret") == 0) {
        free((void *)servconf->cred.keydata);
        servconf->cred.keydata = strdup(value);
    } else if (strcmp(name, "key-file") == 0) {
        free((void *)servconf->cred.keydata);

        FILE *keyfile = fopen(value, "r");

        if (!keyfile) {
            log(LOG_WARNING, "Could not read key file %s", value);
            return 0;
        }

        fseek(keyfile, 0L, SEEK_END);

        size_t keysize = ftell(keyfile);
        char *tmp = xmalloc(keysize);

        fseek(keyfile, 0L, SEEK_SET);

        fread(tmp, 1, keysize, keyfile);

        if (tmp[keysize - 1] == '\n')
            tmp[keysize - 1] = '\0';

        servconf->cred.keydata = tmp;
        fclose(keyfile);
    } else if (strcmp(name, "key-algo") == 0) {
        ldns_lookup_table *lt = ldns_signing_algorithms;
        bool algomatch = false;

        // XXX: Not all keys in the lookup table can work with TSIG, most likely
        while (lt->name) {
            if (strcasecmp(value, lt->name) == 0) {
                algomatch = true;

                // Lookup table entries look like "algorithm" but ldns expects "algorithm."
                size_t len = strlen(lt->name);
                char *tmp = xmalloc(len + 2);
                strcpy(tmp, lt->name);
                tmp[len] = '.';
                tmp[len + 1] = '\0';

                servconf->cred.algorithm = tmp;
                break;
            }

            lt++;

        }

        if (!algomatch)
            log(LOG_WARNING, "Unknown encryption key algorithm: %s", value);

        return algomatch;
    } else if (strcmp(name, "max-retry") == 0) {
        unsigned long long retry = strtoull(value, NULL, 10);
        TO_NUM_COND_MSG(retry, value, retry <= 255,
                "Invalid value for max-retry: %llu", retry)

        ldns_resolver_set_retry(servconf->resolv, retry);
    } else {
        return 0;
    }

    return 1;
}

static int handle_ifconf(struct conf *conf, const char *iface,
        const char *name, const char *value)
{
    map(conf_if) *map = conf->ifaces;
    conf_if *ifconf;

    if (!map_get_conf_if(map, iface, &ifconf)) {
        ifconf = xcalloc(1, sizeof(conf_if));
        map_set_conf_if(conf->ifaces, iface, ifconf);
    }

    if (strcmp(name, "server") == 0) {
        conf_serv *servconf;

        if (!map_get_conf_serv(conf->servers, value, &servconf)) {
            servconf = xcalloc(1, sizeof(conf_serv));
            map_set_conf_serv(conf->servers, value, servconf);
        }

        if (!servconf->resolv)
            servconf->resolv = ldns_resolver_new();

        ifconf->server = servconf;
    } else if (strcmp(name, "zone") == 0) {
        ldns_rdf_free(ifconf->zone);
        ifconf->zone = ldns_dname_new_frm_str(value);
    } else if (strcmp(name, "record") == 0) {
        ldns_rdf_free(ifconf->record);
        ifconf->record = ldns_dname_new_frm_str(value);
    } else if (strcmp(name, "delete-existing") == 0) {
        BOOL_FLAG(value, ifconf->opts, CONF_OPT_IFACE_DELETE_EXISTING);
    } else if (strcmp(name, "ttl") == 0) {
        unsigned long long ttl;

        // 7d, maximum TTL allowed by DNS
        if (!str_to_time_duration(&ttl, value) || ttl == 0 || ttl > 604800) {
            log(LOG_NOTICE, "Invalid TTL specified: %s", value);
            return 0;
        }

        ifconf->ttl = ttl;
    } else if (strcmp(name, "respect-ttl") == 0) {
        BOOL_FLAG(value, ifconf->opts, CONF_OPT_IFACE_RESPECT_TTL);
    } else {
        return 0;
    }

    return 1;
}

#undef BOOL_FLAG
#undef BOOL_IS_FALSE
#undef BOOL_IS_TRUE
#undef TO_NUM_COND_MSG

static int line_cb(void *user, const char *section, const char *name, const char *value)
{
    struct conf *conf = (struct conf *)user;

    const char *sep = strchr(section, '/');

    if (!sep) {
        log(LOG_NOTICE, "Unknown section: [%s]", section);
        return 0;
    }

    if (strncmp(section, "server", sep - section) == 0)
        return handle_servconf(conf, sep + 1, name, value);
    else if (strncmp(section, "iface", sep - section) == 0)
        return handle_ifconf(conf, sep + 1, name, value);

    return 0;
}

static bool validate_ifconf(const char *key, conf_if *ifconf, void *arg)
{
    (void)arg;

    conf_serv *servconf = ifconf->server;

    if (!servconf || !servconf->resolv)
        die(EX_DATAERR, "Invalid server specified for interface %s", key);

    if (!ifconf->zone || !ifconf->record) {
        if (!servconf->zone || !servconf->record)
            die(EX_DATAERR, "No zone/record specified for interface %s or its server", key);

        ldns_rdf_deep_free(ifconf->zone);
        ldns_rdf_deep_free(ifconf->zone);

        ifconf->zone = servconf->zone;
        ifconf->record = servconf->record;
    }

    if (!ldns_dname_is_subdomain(ifconf->record, ifconf->zone))
        ldns_dname_cat(ifconf->record, ifconf->zone);

    if (ifconf->opts & CONF_OPT_IFACE_RESPECT_TTL && ifconf->ttl != 0)
        die(EX_DATAERR, "The options respect-ttl and ttl cannot be specified simultaneously");

    servconf->opts |= CONF_OPT_SERVER_USED_BY_IFACE;

    return true;
}

static bool validate_servconf(const char *key, conf_serv *servconf, void *arg)
{
    (void)arg;

    ldns_status ret = dns_tsig_credentials_validate(servconf->cred);

    if (ret == LDNS_STATUS_INVALID_B64)
        die(EX_DATAERR, "Invalid key secret for server %s", key);
    else if (ret == LDNS_STATUS_CRYPTO_TSIG_BOGUS)
        die(EX_DATAERR, "Expected all or none of the key name, key secret "
                "and algorithm to be specified for server %s", key);
    else if (ret == LDNS_STATUS_OK)
        dns_resolver_set_tsig_credentials(servconf->resolv, servconf->cred);

    if (!(servconf->opts & CONF_OPT_SERVER_USED_BY_IFACE))
        log(LOG_NOTICE, "Server %s is not referenced by any interfaces", key);

    return true;
}

static void free_ifconf(conf_if *ifconf)
{
    conf_serv *servconf = ifconf->server;

    if (ifconf->zone != servconf->zone || ifconf->record != servconf->record) {
        ldns_rdf_deep_free(ifconf->zone);
        ldns_rdf_deep_free(ifconf->record);
    }

    free(ifconf);
}

static void free_servconf(conf_serv *servconf)
{
    ldns_rdf_deep_free(servconf->zone);
    ldns_rdf_deep_free(servconf->record);

    ldns_resolver_deep_free(servconf->resolv);

    free((void *)servconf->cred.algorithm);
    free((void *)servconf->cred.keyname);
    free((void *)servconf->cred.keydata);

    free(servconf);
}

struct conf conf_read(FILE *file, const char *filename)
{
    struct conf conf;

    map_ops(conf_if) ifops = {
        .compare = strcmp,
        .hash = murmurhash64a,
        .key_alloc = (const char *(*)(const char *))strdup,
        .key_free = (void (*)(const char *))free,
        .val_free = free_ifconf
    };

    map_ops(conf_serv) servops = {
        .compare = strcmp,
        .hash = murmurhash64a,
        .key_alloc = (const char *(*)(const char *))strdup,
        .key_free = (void (*)(const char *))free,
        .val_free = free_servconf
    };

    conf.ifaces = map_new_conf_if(4, ifops);
    conf.servers = map_new_conf_serv(4, servops);

    int ret = ini_parse_file(file, line_cb, &conf);

    if (ret < 0)
        die(EX_NOINPUT, "Could not load config file");
    else if (ret)
        die(EX_DATAERR, "Error in config file @ %s:%d", filename, ret);

    map_foreach_conf_if(conf.ifaces, validate_ifconf, NULL);
    map_foreach_conf_serv(conf.servers, validate_servconf, NULL);

    return conf;
}

void conf_free(struct conf conf)
{
    map_free_conf_if(conf.ifaces);
    map_free_conf_serv(conf.servers);
}
