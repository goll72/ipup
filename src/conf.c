#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "map.h"
#include "hash.h"
#include "conf.h"

#include <ldns/ldns.h>

map_decl(conf_t);

static int handler(void *user, const char *section, const char *name, const char *value)
{
    struct map *map = (struct map *)user;
    size_t sectionlen = strlen(section);
    conf_t *conf = map_get_conf_t(map, section, sectionlen);

    if (!conf) {
        conf = calloc(1, sizeof(conf_t));

        if (!conf)
            errx(2, "Failed to allocate memory");

        conf->opts = CONF_VERIFY_DUPLICATE;
        conf->rectype = REC_A;

        map_set_conf_t(map, section, sectionlen, conf);
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
        free((void *)conf->server);
        conf->server = strdup(value);
    } else if (strcmp(name, "port") == 0) {
        char *end = NULL;
        errno = 0;
        unsigned long long port = strtoull(value, &end, 10);

        if (errno || port > 65535) {
            warnx("Invalid port number: %s", value);
            return 0;
        }

        conf->port = port;
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
        conf->cred.keydata = malloc(keysize);

        if (!conf->cred.keydata)
            errx(2, "Failed to allocate memory");

        fseek(keyfile, 0L, SEEK_SET);

        fread((void *)conf->cred.keydata, 1, keysize, keyfile);
        fclose(keyfile);
    } else if (strcmp(name, "key-algo") == 0) {
        ldns_lookup_table *lt = ldns_signing_algorithms;
        bool algomatch = false;

        while (lt->name) {
            if (strcasecmp(value, lt->name) == 0) {
                algomatch = true;
                conf->cred.algorithm = lt->name;
                break;
            }

            lt++;
        }

        if (!algomatch)
            warnx("Unknown key encryption algorithm: %s", value);

        return algomatch;
    } else if (strcmp(name, "zone") == 0) {
        free(conf->zone);
        conf->zone = strdup(value);
    } else if (strcmp(name, "record") == 0) {
        free(conf->record);
        conf->record = strdup(value);
    } else if (strcmp(name, "record-type") == 0) {
        if (strcmp(value, "A") == 0)
            conf->rectype = REC_A;
        else if (strcmp(value, "AAAA") == 0)
            conf->rectype = REC_AAAA;
        else if (strcmp(value, "A/AAAA") == 0)
            conf->rectype = REC_BOTH;
        else
            return 0;
    } else if (strcmp(name, "delete-existing") == 0) {
        BOOL_FLAG(value, conf->opts, CONF_DELETE_EXISTING);
    } else if (strcmp(name, "verify-reachable") == 0) {
        BOOL_FLAG(value, conf->opts, CONF_VERIFY_REACHABLE);
    } else if (strcmp(name, "verify-duplicate") == 0) {
        BOOL_FLAG(value, conf->opts, CONF_VERIFY_DUPLICATE);
    } else {
        return 0;
    }

    #undef BOOL_FLAG
    #undef BOOL_IS_FALSE
    #undef BOOL_IS_TRUE

    return 1;
}

struct map *readconf(FILE *conf, const char *filename)
{
    struct map *map = map_init(4, murmurhash64a);

    int ret = ini_parse_file(conf, handler, map);

    if (ret < 0)
        errx(1, "Could not load config file");
    else if (ret)
        errx(1, "Error on config file %s:%d", filename, ret);

    return map;
}
