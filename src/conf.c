#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <sysexits.h>

#include "dns.h"
#include "map.h"
#include "hash.h"
#include "conf.h"
#include "util.h"
#include "xalloc.h"

map_decl(conf_t);

static int line_cb(void *user, const char *section, const char *name, const char *value)
{
    struct map *map = (struct map *)user;
    size_t sectionlen = strlen(section);
    conf_t *conf = map_get(map, section, sectionlen);

    if (!conf) {
        conf = xcalloc(1, sizeof(conf_t));

        conf->ttl = (uint32_t)-1;
        conf->resolv = ldns_resolver_new();

        if (!map_set(map, section, sectionlen, conf))
            errx(EX_SOFTWARE, "Failed to allocate memory for hashmap");
    }

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
            (var) &= (flag);                \
        } else if (BOOL_IS_FALSE((x))) {    \
            (var) |= ~(flag);               \
        } else {                            \
            return 0;                       \
        }

    if (strcmp(name, "server") == 0) {
        ldns_rdf *server = ldns_dname_new_frm_str(value);
        dns_resolver_init_frm_dname(conf->resolv, server);
        ldns_resolver_set_domain(conf->resolv, server);

        ldns_rdf_deep_free(conf->server);
        conf->server = server;
    } else if (strcmp(name, "port") == 0) {
        errno = 0;
        unsigned long long port = strtoull(value, NULL, 10);

        if (errno || port == 0 || port > 65535) {
            warnx("Invalid port number: %s", value);
            return 0;
        }

        ldns_resolver_set_port(conf->resolv, port);
    } else if (strcmp(name, "key-name") == 0) {
        free((void *)conf->cred.keyname);
        conf->cred.keyname = strdup(value);
    } else if (strcmp(name, "key-secret") == 0) {
        free((void *)conf->cred.keydata);
        conf->cred.keydata = strdup(value);
    } else if (strcmp(name, "key-file") == 0) {
        free((void *)conf->cred.keydata);

        FILE *keyfile = fopen(value, "r");

        if (!keyfile) {
            warn("Could not read key file %s", value);
            return 0;
        }

        fseek(keyfile, 0L, SEEK_END);

        size_t keysize = ftell(keyfile);
        conf->cred.keydata = xmalloc(keysize);

        fseek(keyfile, 0L, SEEK_SET);

        fread((void *)conf->cred.keydata, 1, keysize, keyfile);
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

                conf->cred.algorithm = tmp;
                break;
            }

            lt++;

        }

        if (!algomatch)
            warnx("Unknown encryption key algorithm: %s", value);

        return algomatch;
    } else if (strcmp(name, "zone") == 0) {
        ldns_rdf_free(conf->zone);
        conf->zone = ldns_dname_new_frm_str(value);
    } else if (strcmp(name, "record") == 0) {
        ldns_rdf_free(conf->record);
        conf->record = ldns_dname_new_frm_str(value);
    } else if (strcmp(name, "delete-existing") == 0) {
        BOOL_FLAG(value, conf->opts, CONF_OPT_DELETE_EXISTING);
    } else if (strcmp(name, "ttl") == 0) {
        char *end;
        errno = 0;

        unsigned long long ttl = strtoull(value, &end, 10);

        switch (*end) {
            case 'd':
                ttl *= 86400;
                break;
            case 'h':
                ttl *= 360;
                break;
            case 'm':
                ttl *= 60;
                break;
        }

        // 7d, maximum TTL allowed by DNS
        if (errno || ttl > 604800) {
            warnx("Invalid TTL specified");
            return 0;
        }

        conf->ttl = ttl;
    } else if (strcmp(name, "retry-max") == 0) {
        errno = 0;
        unsigned long long retry = strtoull(value, NULL, 10);

        if (errno || retry > 255) {
            warnx("Invalid value for retry-max: %llu", retry);
            return 0;
        }

        ldns_resolver_set_retry(conf->resolv, retry);
    } else {
        return 0;
    }

    #undef BOOL_FLAG
    #undef BOOL_IS_FALSE
    #undef BOOL_IS_TRUE

    return 1;
}

static bool validate(char *key, size_t len, conf_t *conf)
{
    if (!conf->zone)
        errx(EX_DATAERR, "No zone specified for section [%s]", key);

    if (!conf->record)
        errx(EX_DATAERR, "No record specified for section [%s]", key);

    if (!ldns_dname_is_subdomain(conf->record, conf->zone))
        ldns_dname_cat(conf->record, conf->zone);

    if (conf->opts & CONF_OPT_RESPECT_TTL && conf->ttl != (uint32_t)-1)
        errx(EX_DATAERR, "The options respect-ttl and ttl cannot be specified simultaneously");

    ldns_status ret = dns_tsig_credentials_validate(conf->cred);

    if (ret == LDNS_STATUS_INVALID_B64)
        errx(EX_DATAERR, "Invalid key secret for section [%s]", key);
    else if (ret == LDNS_STATUS_CRYPTO_TSIG_BOGUS)
        errx(EX_DATAERR, "Expected all or none of the key name, key secret "
                "and algorithm to be specified for section [%s]", key);
    else if (ret == LDNS_STATUS_OK)
        dns_resolver_set_tsig_credentials(conf->resolv, conf->cred);

    return true;
}

struct map *conf_read(FILE *conf, const char *filename)
{
    struct map *map = map_init(4, murmurhash64a);

    int ret = ini_parse_file(conf, line_cb, map);

    if (ret < 0)
        errx(EX_NOINPUT, "Could not load config file");
    else if (ret)
        errx(EX_DATAERR, "Error on config file @ %s:%d", filename, ret);

    map_foreach_conf_t(map, validate);

    return map;
}

static bool free_section(char *key, size_t len, conf_t *conf)
{
    ldns_rdf_deep_free(conf->zone);
    ldns_rdf_deep_free(conf->record);

    free((void *)conf->cred.algorithm);
    free((void *)conf->cred.keyname);
    free((void *)conf->cred.keydata);

    ldns_resolver_deep_free(conf->resolv);

    free(conf);

    return true;
}

void conf_free(struct map *map)
{
    map_foreach_conf_t(map, free_section);
    map_free(map);
}
