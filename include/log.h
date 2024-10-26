#ifndef LOG_H
#define LOG_H

#include <syslog.h>
#include <stdint.h>
#include <stdlib.h>

#include <sysexits.h>

enum log_mode {
    LOG_MODE_DEFAULT,
    LOG_MODE_STDOUT,
    LOG_MODE_SYSLOG
};

void log_init(const char *ident, enum log_mode mode);
void log_close(void);
void log_mask(uint8_t prio);

#define S_LOG_ERR     "ERR"
#define S_LOG_WARNING "WARN"
#define S_LOG_NOTICE  "NOTE"
#define S_LOG_INFO    "INFO"

void slog(int prio, const char *fmt, ...);

#define log(prio, ...) \
    slog(prio, "[" S_##prio "] " __VA_ARGS__)

#define die(code, ...)  \
    do {                \
        log(LOG_ERR, __VA_ARGS__);  \
        exit(code);                 \
    } while (0)

#endif /* LOG_H */
