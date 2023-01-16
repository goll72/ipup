#include <unistd.h>
#include <stdbool.h>
#include <sysexits.h>

#include <sys/stat.h>

#include "nl.h"
#include "dns.h"
#include "util.h"
#include "conf.h"
#include "xalloc.h"

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
                printf("%s v" VERSION " built on " __TIME__ ", " __DATE__ "\n", argv[0]);
                return 0;
            case 'h': default:
                fprintf(stderr,
                        "Usage: %s [ -v | -h | -c <conf> ]\n"
                        "  -h    Shows this help menu\n"
                        "  -v    Version information\n"
                        "  -c    Specify configuration file path\n", argv[0]);
                return opt == 'h' ? EX_OK : EX_USAGE;
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

    // If no config file specified, try to find one concatenating
    // pref and suff and checking whether it exists
    if (!foundconf) {
        for (size_t i = 0; i < sizeof pref / sizeof pref[0]; i++) {
            if (!pref[i])
                continue;

            size_t preflen = strlen(pref[i]);
            size_t sufflen = strlen(suff[i]);

            confpath = xrealloc(confpath, preflen + sufflen + 1);
            concat(confpath, pref[i], preflen, suff[i], sufflen);

            if (access(confpath, R_OK) != -1) {
                foundconf = true;
                break;
            }
        }
    }

    if (!foundconf)
        errx(EX_NOINPUT, "Could not find a config file");

    FILE *conf = fopen(confpath, "r");

    if (!conf)
        errx(EX_NOINPUT, "Config file specified not found");

    // Check that it really is a file
    struct stat sb;
    fstat(fileno(conf), &sb);

    if ((sb.st_mode & S_IFMT) != S_IFREG)
        errx(EX_NOINPUT, "Invalid path, expected file");

    struct map *confmap = conf_read(conf, confpath);

    if (confpath != oconfpath)
        free(confpath);

    fclose(conf);

    struct nl_cache_mngr *nlmngr = nl_run(confmap);
}
