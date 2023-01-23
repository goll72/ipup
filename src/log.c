// To appease glibc
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "log.h"

static struct log_state {
    enum log_mode mode;
    uint8_t mask;
} state;

void log_init(const char *ident, enum log_mode mode)
{
	if (mode == LOG_MODE_DEFAULT)
		mode = isatty(STDOUT_FILENO)
			? LOG_MODE_STDOUT
			: LOG_MODE_SYSLOG;

	if (mode == LOG_MODE_SYSLOG)
		openlog(ident, LOG_PID, LOG_DAEMON);

	state.mode = mode;
}

void log_close(void)
{
	if (state.mode == LOG_MODE_SYSLOG)
		closelog();
}

void log_mask(uint8_t prio)
{
	if (state.mode == LOG_MODE_STDOUT)
		state.mask = prio;
	else if (state.mask == LOG_MODE_SYSLOG)
		setlogmask(prio);
}

void slog(int prio, const char *fmt, ...)
{
    va_list ap;
	va_start(ap, fmt);

    if (state.mode == LOG_MODE_STDOUT) {
		if (state.mask & (1 << prio))
			return;

		vprintf(fmt, ap);
		putchar('\n');
	} else if (state.mode == LOG_MODE_SYSLOG) {
		vsyslog(prio, fmt, ap);
	}

	va_end(ap);
}
