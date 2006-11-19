/* includes */
#include <stdarg.h>
#include <sys/stat.h>

/* defines */
#define LOGSTRLEN LONGSRVBUFLEN 

struct _facility_map {
  char string[10];
  int num;
};

static const struct _facility_map facility_map[] = {
	{"auth", LOG_AUTH},
	{"mail", LOG_MAIL},
	{"daemon", LOG_DAEMON},
	{"kern", LOG_KERN},
	{"user", LOG_USER},
	{"local0", LOG_LOCAL0},
	{"local1", LOG_LOCAL1},
	{"local2", LOG_LOCAL2},
	{"local3", LOG_LOCAL3},
	{"local4", LOG_LOCAL4},
	{"local5", LOG_LOCAL5},
	{"local6", LOG_LOCAL6},
	{"local7", LOG_LOCAL7},
	{"-1", -1},
};

/* prototypes */
void Log(short int, char *, ...);
int parse_log_facility(const char *);
