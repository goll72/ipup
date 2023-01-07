#include <err.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/stat.h>

#include "nl.h"
#include "util.h"
#include "conf.h"

int main(int argc, char * const *argv)
{
    int opt;
    char *confpath = NULL;

    while ((opt = getopt(argc, argv, "c:vh")) != -1) {
        switch (opt) {
            case 'c':
                confpath = optarg;
                break;
            case 'v':
                printf("%s v" STR(VERSION) " built on" __DATE__ "\n", argv[0]);
                return 0;
            case 'h': default:
                fprintf(stderr,
                        "Usage: %s [ -v | -h | -c <conf> ]\n"
                        "  -h    Shows this help menu\n"
                        "  -v    Version information\n"
                        "  -c    Specify configuration file path\n", argv[0]);
                return opt == 'h';
        }
    }

    const char *oconfpath = confpath;

    const char * const pref[] = {
        "/etc",
        getenv("XDG_CONFIG_HOME"),
        getenv("HOME")
    };

    const char * const suff[] = {
        "/ipup/conf",
        "/ipup/conf",
        "/.ipup.conf"
    };

    bool foundconf = confpath;

    if (!foundconf) {
        for (int i = 0; i < sizeof pref / sizeof pref[0]; i++) {
            if (!pref[i])
                continue;

            size_t preflen = strlen(pref[i]);
            size_t sufflen = strlen(suff[i]);

            char *tmp = realloc(confpath, preflen + sufflen + 1);

            if (!tmp)
                errx(2, "Failed to allocate memory");

            confpath = tmp;
            *(char *)mempcpy(mempcpy(confpath, pref[i], preflen), suff[i], sufflen) = 0;

            if (access(confpath, R_OK) != -1) {
                foundconf = true;
                break;
            }
        }
    }

    if (!foundconf)
        errx(1, "Could not find a config file");

    FILE *conf = fopen(confpath, "r");

    if (!conf)
        errx(1, "Config file specified not found");

    struct stat sb;
    fstat(fileno(conf), &sb);

    if ((sb.st_mode & S_IFMT) != S_IFREG)
        errx(1, "Invalid path, expected file");

    readconf(conf, confpath);

    if (confpath != oconfpath)
        free(confpath);

    fclose(conf);

    struct nl_cache_mngr *nl_mngr = nl_init();
}
