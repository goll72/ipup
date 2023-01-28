#include <libgen.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/stat.h>

#include "nl.h"
#include "log.h"
#include "dns.h"
#include "util.h"
#include "conf.h"
#include "xalloc.h"

int main(int argc, char * const *argv)
{
    int opt;
    char *confpath = NULL;
    enum log_mode logmode = LOG_MODE_DEFAULT;

    const char *progname = basename(argv[0]);

    while ((opt = getopt(argc, argv, "c:vsSh")) != -1) {
        switch (opt) {
            case 'c':
                confpath = optarg;
                break;
            case 'v':
                printf("%s v" VERSION " built on " __TIME__ ", " __DATE__ "\n", progname);
                return EX_OK;
            case 's':
                logmode = LOG_MODE_STDOUT;
                break;
            case 'S':
                logmode = LOG_MODE_SYSLOG;
                break;
            case 'h': default:
                fprintf(stderr,
                        "Usage: %s [ -v | -h | -c <conf> ]\n"
                        "  -h    Shows this help menu\n"
                        "  -v    Version information\n"
                        "  -s    Log to stdout\n"
                        "  -S    Log to syslog\n"
                        "  -c    Specify configuration file path\n", progname);
                return opt == 'h' ? EX_OK : EX_USAGE;
        }
    }

    log_init(progname, logmode);

    const char *oconfpath = confpath;

    const char * const pref[] = {
        SYSCONFDIR,
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
        die(EX_NOINPUT, "Could not find a config file");

    FILE *conf = fopen(confpath, "r");

    if (!conf)
        die(EX_NOINPUT, "Config file specified not found");

    // Check that it really is a file
    struct stat sb;
    fstat(fileno(conf), &sb);

    if ((sb.st_mode & S_IFMT) != S_IFREG)
        die(EX_NOINPUT, "Invalid path, expected file");

    struct conf confmap = conf_read(conf, confpath);

    if (confpath != oconfpath)
        free(confpath);

    fclose(conf);

    struct nl_cache_mngr *nlmngr = nl_run(&confmap);

    log_close();
    conf_free(confmap);
    nl_free(nlmngr);
    dns_free_sys_resolver();
}
