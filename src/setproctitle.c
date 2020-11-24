/*
 * setproctitle()-related routines in this file are derived from Sendmail
 * 8.13.5 which is:
 *        
 * Copyright (c) 1998-2005 Sendmail, Inc. and its suppliers.
 *      All rights reserved.
 * Copyright (c) 1983, 1995-1997 Eric P. Allman.  All rights reserved.
 * Copyright (c) 1988, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the sendmail distribution.
 *
 */

#include "pmacct.h"

/*
 *  SETPROCTITLE -- set process title for ps
*/

#define SPT_NONE	0	/* don't use it at all */
#define SPT_REUSEARGV	1	/* cover argv with title information */
#define SPT_BUILTIN	2	/* use libc builtin */
#define SPT_PSTAT	3	/* use pstat(PSTAT_SETCMD, ...) */

#include "setproctitle.h"

#define MAXLINE (2*LONGLONGSRVBUFLEN)
#define SPACELEFT(x) (sizeof(x)-strlen(x))

#if defined PROGNAME && SPT_TYPE == SPT_REUSEARGV
extern char *__progname;
#endif

/*
 * NEWSTR -- Create a copy of a C string
 */

char *spt_newstr(s)
const char *s;
{
  size_t l;
  char *n;
  
  l = strlen(s);
  n = malloc(l + 1);
  strlcpy(n, s, l + 1);

  return n;
}

#ifndef SPT_TYPE
#  define SPT_TYPE	SPT_NONE
#endif /* ! SPT_TYPE */


#if SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN

#if SPT_TYPE == SPT_PSTAT
#  include <sys/pstat.h>
#endif /* SPT_TYPE == SPT_PSTAT */

#ifndef SPT_PADCHAR
#  define SPT_PADCHAR	' '
#endif /* ! SPT_PADCHAR */

#endif /* SPT_TYPE != SPT_NONE && SPT_TYPE != SPT_BUILTIN */

#ifndef SPT_BUFSIZE
#  define SPT_BUFSIZE	MAXLINE
#endif /* ! SPT_BUFSIZE */

/*
 *  Pointers for setproctitle.
 *	This allows "ps" listings to give more useful information.
 */

static char	**Argv = NULL;		/* pointer to argument vector */
static char	*LastArgv = NULL;	/* end of argv */

void
initsetproctitle(argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
	register int i;
	extern char **environ;

	/*
	**  Move the environment so setproctitle can use the space at
	**  the top of memory.
	*/

	if (envp != NULL)
	{
		for (i = 0; envp[i] != NULL; i++)
			continue;
		environ = (char **) malloc(sizeof (char *) * (i + 1));
		for (i = 0; envp[i] != NULL; i++)
			environ[i] = spt_newstr(envp[i]);
		environ[i] = NULL;
	}

	/*
	**  Save start and extent of argv for setproctitle.
	*/

	Argv = argv;

	/*
	**  Determine how much space we can use for setproctitle.
	**  Use all contiguous argv and envp pointers starting at argv[0]
	*/

	for (i = 0; i < argc; i++)
	{
		if (i == 0 || LastArgv + 1 == argv[i])
			LastArgv = argv[i] + strlen(argv[i]);
	}
	for (i = 0; LastArgv != NULL && envp != NULL && envp[i] != NULL; i++)
	{
		if (LastArgv + 1 == envp[i])
			LastArgv = envp[i] + strlen(envp[i]);
	}

#if defined PROGNAME && SPT_TYPE == SPT_REUSEARGV
	if (config.uacctd_group) __progname = uacctd_globstr; /* XXX: hack */
	else if (config.acct_type == ACCT_PM) __progname = pmacctd_globstr;
	else if (config.acct_type == ACCT_NF) __progname = nfacctd_globstr;
	else if (config.acct_type == ACCT_SF) __progname = sfacctd_globstr;
	else if (config.acct_type == ACCT_PMTELE) __progname = pmtele_globstr;
	else if (config.acct_type == ACCT_PMBGP) __progname = pmbgpd_globstr;
	else if (config.acct_type == ACCT_PMBMP) __progname = pmbmpd_globstr;
#endif
}

#if SPT_TYPE != SPT_BUILTIN

/*VARARGS1*/
static void
# ifdef __STDC__
setproctitle(const char *fmt, ...)
# else /* __STDC__ */
setproctitle(fmt, va_alist)
	const char *fmt;
	va_dcl
# endif /* __STDC__ */
{
# if SPT_TYPE != SPT_NONE
	register int i;
	register char *p;
	char buf[SPT_BUFSIZE];
	va_list ap;
#  if SPT_TYPE == SPT_PSTAT
	union pstun pst;
#  endif /* SPT_TYPE == SPT_PSTAT */

	memset(buf, 0, SPT_BUFSIZE);
	p = buf;
	va_start(ap, fmt);
	vsnprintf(p, SPACELEFT(buf), fmt, ap);
	va_end(ap);

	i = (int) strlen(buf);
	if (i < 0) return;

#  if SPT_TYPE == SPT_PSTAT
	pst.pst_command = buf;
	pstat(PSTAT_SETCMD, pst, i, 0, 0);
#  endif /* SPT_TYPE == SPT_PSTAT */
#  if SPT_TYPE == SPT_REUSEARGV
	if (LastArgv == NULL)
		return;

	if (i > (LastArgv - Argv[0]) - 2)
	{
		i = (LastArgv - Argv[0]) - 2;
		buf[i] = '\0';
	}
	(void) strlcpy(Argv[0], buf, i + 1);
	p = &Argv[0][i];
	while (p < LastArgv)
		*p++ = SPT_PADCHAR;
	Argv[1] = NULL;
#  endif /* SPT_TYPE == SPT_REUSEARGV */
# endif /* SPT_TYPE != SPT_NONE */
}

#endif /* SPT_TYPE != SPT_BUILTIN */
/*
 *  PM_SETPROCTITLE -- set process task and set process title for ps
 */

/*VARARGS2*/
void
#ifdef __STDC__
pm_setproctitle(const char *fmt, ...)
#else /* __STDC__ */
pm_setproctitle(fmt, va_alist)
  const char *fmt;
  va_dcl
#endif /* __STDC__ */
{
  char buf[SPT_BUFSIZE];
  char prefix[16];
  va_list ap;

  memset(prefix, 0, sizeof(prefix));
  memset(buf, 0, sizeof(buf));

  if (config.uacctd_group) strcpy(prefix, uacctd_globstr); /* XXX: hack */
  else if (config.acct_type == ACCT_PM) strcpy(prefix, pmacctd_globstr);
  else if (config.acct_type == ACCT_NF) strcpy(prefix, nfacctd_globstr);
  else if (config.acct_type == ACCT_SF) strcpy(prefix, sfacctd_globstr);
  else if (config.acct_type == ACCT_PMTELE) strcpy(prefix, pmtele_globstr);
  else if (config.acct_type == ACCT_PMBGP) strcpy(prefix, pmbgpd_globstr);
  else if (config.acct_type == ACCT_PMBMP) strcpy(prefix, pmbmpd_globstr);

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

#if SPT_TYPE != SPT_BUILTIN
  setproctitle("%s: %s", prefix, buf);
#else
  setproctitle("%s", buf);
#endif
}

