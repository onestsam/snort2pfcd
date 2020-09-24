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
 * s2cd_pf_expiretable functions from expiretable
 * s2cd_radix_ioctlfrom ioctl_helpers.c                    
 * s2cd_radix_get_astatsfrom ioctl_helpers.c                                    
 * s2cd_radix_del_addrs from ioctl_helpers.c
 * Copyright (c) 2005 Henrik Gustafsson <henrik.gustafsson@fnord.se>
 *
 * s2cd_parse_line from pfctl_radix.c 
 * s2cd_pf_block from pftabled-1.03
 * Copyright (c) Armin's Wolfermann
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

/* Global Vars Init */
struct pidfh *pfh = NULL;
int v = 0;
int C = 0;
int F = 0;
int pf_reset = 0;
int s2cd_threads = 1;
int afile_monitor = 0;
int pfile_monitor = 0;
int bfile_monitor = 0;
pthread_mutex_t log_mutex;
pthread_mutex_t dns_mutex;
pthread_mutex_t thr_mutex;
pthread_mutex_t pf_mutex;
pthread_mutex_t fm_mutex;

int main(int argc, char **argv) {

	struct loopdata_t *loopdata = NULL;

	if ((loopdata = (struct loopdata_t *)malloc(sizeof(struct loopdata_t))) == NULL) S2CD_MALLOC_ERR;

	s2cd_pre_init(loopdata);
	s2cd_get_optargs(argc, argv, loopdata);
	s2cd_init(loopdata);

	s2cd_kevent_loop(loopdata);

	close(loopdata->dev);
	free(loopdata);
	s2cd_pre_exit();

	return(0);

}   /* main */

void s2cd_pre_init(struct loopdata_t *loopdata) {

	memset((struct loopdata_t *)loopdata, 0x00, sizeof(struct loopdata_t));

	loopdata->priority = S2CD_SP_HIGH;
	loopdata->thr_max = S2CD_THRMAX;
	loopdata->repeat_offenses = S2CD_REPEATO;
	strlcpy(loopdata->tablename, __progname, PF_TABLE_NAME_SIZE);
	strlcpy(loopdata->tablename_static, loopdata->tablename, PF_TABLE_NAME_SIZE);
	strlcat(loopdata->tablename_static, "_static", PF_TABLE_NAME_SIZE);

	if (getuid() != 0) {
		fprintf(stderr, "%s %s - %s\n", S2CD_LANG_ERR_ROOT, loopdata->tablename, S2CD_LANG_EXIT);
		exit(EXIT_FAILURE);
	}   /* if (getuid() != 0) */

	return;

}   /* s2cd_pre_init */

void s2cd_init(struct loopdata_t *loopdata) {

	if (!C) loopdata->timebuf = time(NULL);
	else loopdata->timebuf = 0;

	s2cd_check_file(loopdata->logfile);
	memset(loopdata->randombuf, 0x00, BUFSIZ);
	sprintf(loopdata->randombuf, "\n<=== %s %s %s \n", loopdata->tablename, S2CD_LANG_START, asctime(localtime(&loopdata->timebuf)));
	s2cd_write_file(loopdata->logfile, loopdata->randombuf);

	if (!F) {
		openlog(loopdata->tablename, LOG_CONS | LOG_PID, LOG_DAEMON);
		syslog(LOG_DAEMON | LOG_NOTICE, "%s %s, pid: %d", loopdata->tablename, S2CD_LANG_START, getpid());
	} else fprintf(stderr, "%s %s, pid: %d\n", loopdata->tablename, S2CD_LANG_START, getpid());

	if ((loopdata->dev = open(loopdata->nmpfdev, O_RDWR)) == -1) s2cd_sw_switch_ef(S2CD_LANG_NO_OPEN, loopdata->nmpfdev, S2CD_LANG_EXIT);

	signal(SIGHUP,  s2cd_sighandle);
	signal(SIGTERM, s2cd_sighandle);
	signal(SIGINT,  s2cd_sighandle);

	s2cd_mutex_init();
	s2cd_thr_init(loopdata);

	return;

}   /* s2cd_init */

void s2cd_daemonize(struct loopdata_t *loopdata) {

	pid_t otherpid;

	memset((pid_t *)&otherpid, 0x00, sizeof(pid_t));
	memset((char *)loopdata->randombuf, 0x00, BUFSIZ);
	strlcpy(loopdata->randombuf, S2CD_PATH_RUN, BUFSIZ);
	strlcat(loopdata->randombuf,  __progname, BUFSIZ);
	strlcat(loopdata->randombuf, ".pid", BUFSIZ);

	if ((pfh = pidfile_open(loopdata->randombuf, 0600, &otherpid)) == NULL)
		fprintf(stderr, "%s\n", S2CD_LANG_NO_PID);

	if (daemon(0, 0) == -1) {
		fprintf(stderr, "%s\n", S2CD_LANG_NO_DAEMON);
		s2cd_exit_fail();
	}   /* if (daemon */

	pidfile_write(pfh);

	return;

}   /* s2cd_daemonize */

void s2cd_get_optargs(int argc, char **argv, struct loopdata_t *loopdata) {

	extern char *optarg;
	extern int optind;
	unsigned int ch = 0, w = 0, b = 0, a = 0, l = 0, e = 0, d = 0, q = 0;

	while ((ch = getopt(argc, argv, "w:p:q:m:r:vWCDFBZb:a:l:e:t:d:h")) != -1)
		switch(ch) {
			case 'v': v = 1; break;
			case 'F': F = 1; break;
			case 'C': C = 1; F = 1; break;
			case 'W': loopdata->W = 1; break;
			case 'B': loopdata->B = 1; break;
			case 'D': loopdata->D = 1; break;
			case 'Z': loopdata->Z = 1; break;
			case 'd': strlcpy(loopdata->nmpfdev, optarg, S2CD_NMBUFSIZ); d = 1; break;
			case 'a': strlcpy(loopdata->alertfile, optarg, S2CD_NMBUFSIZ); a = 1; break;
			case 'w': strlcpy(loopdata->pfile, optarg, S2CD_NMBUFSIZ); w = 1; break;
			case 'b': strlcpy(loopdata->bfile, optarg, S2CD_NMBUFSIZ); b = 1; break;
			case 'e': strlcpy(loopdata->extif, optarg, IFNAMSIZ); e = 1; break;
			case 'l': strlcpy(loopdata->logfile, optarg, S2CD_NMBUFSIZ); l = 1; break;
			case 't': if (!(loopdata->t = (time_t)strtol(optarg,NULL,0))) s2cd_usage(); break;
			case 'p': if (!(loopdata->priority = (int)strtol(optarg,NULL,0))) s2cd_usage(); break;
			case 'm': if (!(loopdata->thr_max = (int)strtol(optarg,NULL,0))) s2cd_usage(); break;
			case 'r': if (!(loopdata->repeat_offenses = (int)strtol(optarg,NULL,0))) s2cd_usage(); break;
			case 'q': if (!(q = (int)strtol(optarg,NULL,0))) s2cd_usage(); break;
			case 'h': s2cd_usage();
			case '?': s2cd_usage();
			default: s2cd_usage();
		}   /* switch(ch) */

	argc -= optind;
	argv += optind;

	if (!w) strlcpy(loopdata->pfile, S2CD_PATH_PASSLIST, S2CD_NMBUFSIZ);
	if (!b) strlcpy(loopdata->bfile, S2CD_PATH_BLOCKLIST, S2CD_NMBUFSIZ);
	if (!a) strlcpy(loopdata->alertfile, S2CD_PATH_ALERT, S2CD_NMBUFSIZ);
	if (!d) strlcpy(loopdata->nmpfdev, S2CD_PFDEVICE, S2CD_NMBUFSIZ);
	if (!e) strlcpy(loopdata->extif, "all", IFNAMSIZ);
	if (!l) {
		strlcpy(loopdata->logfile, S2CD_PATH_LOG, S2CD_NMBUFSIZ);
		strlcat(loopdata->logfile,  __progname, S2CD_NMBUFSIZ);
		strlcat(loopdata->logfile, ".log", S2CD_NMBUFSIZ);
	}   /* if (!l) */

	if (!F) s2cd_daemonize(loopdata);
	if (q) sleep(q);

	return;

}   /* s2cd_get_optargs */
