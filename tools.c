/*
 * snort2pfcd
 * Copyright (c) 2016 Samee Shahzada <onestsam@gmail.com>
 *
 * Based on snort2c
 * Copyright (c) 2005 Antonio Benojar <zz.stalker@gmail.com>
 * Copyright (c) 2002 Cedric Berger
 *
 * Expiretable functions from expiretable
 * Copyright (c) 2005 Henrik Gustafsson <henrik.gustafsson@fnord.se>
 *
 * s2c_parse_line based in pfctl code (pfctl_radix.c)
 * Copyright (c) Armin's Wolfermann
 *
 * s2c_pf_block functions are based
 * on Armin's Wolfermann pftabled-1.03 functions.
 *
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <libutil.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>

#include "defdata.h"
#include "tools.h"

void
daemonize()
{
	struct pidfh *pfh;
	pid_t otherpid;
	char *pidfile;

	pidfile = (char *)malloc(sizeof(char)*64);

	bzero(pidfile, 64);
	memset(&otherpid, 0x00, sizeof(pid_t));

	memcpy(pidfile, "/var/run/", 64);
	strlcat(pidfile,  __progname, 64);
	strlcat(pidfile, ".pid", 64);

	pfh = pidfile_open(pidfile, 0600, &otherpid);
	if (pfh == NULL) {
		if (errno == EEXIST)
			syslog(LOG_ERR | LOG_DAEMON, "Daemon already running, pid: %d.", otherpid);
		fprintf(stderr, "Cannot open or create pidfile");
	}

	if (daemon(0, 0) == -1) {
		fprintf(stderr, "Cannot daemonize");
		pidfile_remove(pfh);
		exit(EXIT_FAILURE);
	} else {
		openlog(__progname, LOG_CONS | LOG_PID, LOG_DAEMON);
		syslog(LOG_DAEMON | LOG_NOTICE, "%s started, pid: %d", __progname, getpid());
	}

	pidfile_write(pfh);
	free(pidfile);

	signal(SIGHUP,  sighup);
	signal(SIGTERM, sigterm);
	signal(SIGINT,  sigint);

	return;
}

int
optnum(char *opt, char *targ)
{
	char* endp = NULL;
	long l = -1;
        
	if (!targ || ((l=strtol(targ, &endp, 0)),(endp && *endp)))
		fprintf(stderr, "Argument for -%s must be a number.\n", opt);

	return (int)l;
}

void
usage()
{
	fprintf(stderr, "usage: %s [-h] [-e extif] [-w wfile] [-b bfile] [-a alertfile] [-l logfile] [-p priority] [-t expiretime]\n", __progname);
	fprintf(stderr, "wfile, bfile, logfile, alertfile: path to file, expiretime in seconds.");
	exit(EXIT_FAILURE);
}

void
sighup()
{
	syslog(LOG_ERR | LOG_DAEMON, "SIGHUP received - exiting");
	exit(EXIT_SUCCESS);
}

void
sigterm()
{
	syslog(LOG_ERR | LOG_DAEMON, "SIGTERM received - exiting");
	exit(EXIT_SUCCESS);
}

void
sigint()
{
	syslog(LOG_ERR | LOG_DAEMON, "SIGINT received - exiting");
	exit(EXIT_SUCCESS);
}

long
lmax(long a,long b) {
	return (a > b)?a:b;
}
 
long
lmin(long a,long b) {
	return (a < b)?a:b;
}

