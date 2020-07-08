/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * snort2pfcd
 * Copyright (c) 2020 Samee Shahzada <onestsam@gmail.com>
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
 * libcidr
 * Copyright (c) 1996 Matthew D. Fuller
 *
 * Packet Filter
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "defdata.h"

int
main(int argc, char **argv)
{
	loopdata_t *loopdata = NULL;

	if ((loopdata = (loopdata_t *)malloc(sizeof(loopdata_t))) == NULL) s2c_malloc_err();

	s2c_pre_init(loopdata);
	s2c_get_optargs(argc, argv, loopdata);
	s2c_init(loopdata);

	s2c_kevent_loop(loopdata);

	close(loopdata->dev);
	free(loopdata);
	s2c_pre_exit();

	return(0);
}

void
s2c_pre_init(loopdata_t *loopdata)
{
	wfile_monitor = 0;
	bfile_monitor = 0;
	afile_monitor = 0;
	pf_reset = 0;
	v = 0;
	C = 0;

	memset(loopdata, 0x00, sizeof(loopdata_t));

	loopdata->priority = S2C_SP_HIGH;
	loopdata->thr_max = THRMAX;
	loopdata->repeat_offenses = REPEATO;
	strlcpy(loopdata->tablename, __progname, PF_TABLE_NAME_SIZE);
	strlcpy(loopdata->tablename_static, loopdata->tablename, PF_TABLE_NAME_SIZE);
	strlcat(loopdata->tablename_static, "_static", PF_TABLE_NAME_SIZE);

	if (getuid() != 0) {
		fprintf(stderr, "%s %s - %s\n", LANG_ERR_ROOT, loopdata->tablename, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	return;
}

void
s2c_init(loopdata_t *loopdata)
{
	signal(SIGHUP,  sighandle);
	signal(SIGTERM, sighandle);
	signal(SIGINT,  sighandle);

	openlog(loopdata->tablename, LOG_CONS | LOG_PID, LOG_DAEMON);
	syslog(LOG_DAEMON | LOG_NOTICE, "%s %s, pid: %d", loopdata->tablename, LANG_START, getpid());

	if ((loopdata->dev = open(loopdata->nmpfdev, O_RDWR)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, loopdata->nmpfdev, LANG_EXIT);
		s2c_exit_fail();
	}

	s2c_mutex_init();
	s2c_log_init(loopdata);
	s2c_thr_init(loopdata);

	return;
}

void
s2c_daemonize(loopdata_t *loopdata)
{
	pid_t otherpid;

	memset(&otherpid, 0x00, sizeof(pid_t));
	memset(loopdata->randombuf, 0x00, BUFSIZ);
	strlcpy(loopdata->randombuf, PATH_RUN, BUFSIZ);
	strlcat(loopdata->randombuf,  __progname, BUFSIZ);
	strlcat(loopdata->randombuf, ".pid", BUFSIZ);

	if ((pfh = pidfile_open(loopdata->randombuf, 0600, &otherpid)) == NULL)
		fprintf(stderr, "%s", LANG_NO_PID);

	if (daemon(0, 0) == -1) {
		fprintf(stderr, "%s", LANG_NO_DAEMON);
		s2c_exit_fail();
	}

	pidfile_write(pfh);

	return;
}

void
s2c_get_optargs(int argc, char **argv, loopdata_t *loopdata)
{
	extern char *optarg;
	extern int optind;
	unsigned int F = 0, ch = 0, w = 0, b = 0, a = 0, l = 0, e = 0, d = 0, q = 0;

	while ((ch = getopt(argc, argv, "w:p:q:m:r:vWCDFBZb:a:l:e:t:d:h")) != -1)
		switch(ch) {
			case 'v': v = 1; break;
			case 'F': F = 1; break;
			case 'C': C = 1; break;
			case 'W': loopdata->W = 1; break;
			case 'B': loopdata->B = 1; break;
			case 'D': loopdata->D = 1; break;
			case 'Z': loopdata->Z = 1; break;
			case 'd': strlcpy(loopdata->nmpfdev, optarg, NMBUFSIZ); d = 1; break;
			case 'a': strlcpy(loopdata->alertfile, optarg, NMBUFSIZ); a = 1; break;
			case 'w': strlcpy(loopdata->wfile, optarg, NMBUFSIZ); w = 1; break;
			case 'b': strlcpy(loopdata->bfile, optarg, NMBUFSIZ); b = 1; break;
			case 'e': strlcpy(loopdata->extif, optarg, IFNAMSIZ); e = 1; break;
			case 'l': strlcpy(loopdata->logfile, optarg, NMBUFSIZ); l = 1; break;
			case 't': if (!(loopdata->t = strtol(optarg,NULL,0))) usage(); break;
			case 'p': if (!(loopdata->priority = (int)strtol(optarg,NULL,0))) usage(); break;
			case 'm': if (!(loopdata->thr_max = (int)strtol(optarg,NULL,0))) usage(); break;
			case 'r': if (!(loopdata->repeat_offenses = (int)strtol(optarg,NULL,0))) usage(); break;
			case 'q': if (!(q = (int)strtol(optarg,NULL,0))) usage(); break;
			case 'h': usage();
			case '?': usage();
			default: usage();
		}

	argc -= optind;
	argv += optind;

	if (!w) strlcpy(loopdata->wfile, PATH_WHITELIST, NMBUFSIZ);
	if (!b) strlcpy(loopdata->bfile, PATH_BLACKLIST, NMBUFSIZ);
	if (!a) strlcpy(loopdata->alertfile, PATH_ALERT, NMBUFSIZ);
	if (!d) strlcpy(loopdata->nmpfdev, PFDEVICE, NMBUFSIZ);
	if (!e) strlcpy(loopdata->extif, "all", IFNAMSIZ);
	if (!l) {
		strlcpy(loopdata->logfile, PATH_LOG, NMBUFSIZ);
		strlcat(loopdata->logfile,  __progname, NMBUFSIZ);
		strlcat(loopdata->logfile, ".log", NMBUFSIZ);
	}

	if(!F) s2c_daemonize(loopdata);
	if (q) sleep(q);

	return;
}

void
s2c_log_init(loopdata_t *loopdata)
{
	long timebuf = 0;

	s2c_check_file(loopdata->logfile);

	memset(loopdata->randombuf, 0x00, BUFSIZ);

	if (!C) timebuf = time(NULL);
	else timebuf = 0;
	sprintf(loopdata->randombuf, "\n<=== %s %s %s \n", loopdata->tablename, LANG_START, asctime(localtime(&timebuf)));
	s2c_write_file(loopdata->logfile, loopdata->randombuf);

	return;
}
