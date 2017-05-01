/*
 * snort2pfcd
 * Copyright (c) 2017 Samee Shahzada <onestsam@gmail.com>
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

#include "defdata.h"


int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int ch = 0, B = 0, W = 0, w = 0, b = 0, a = 0, l = 0, e = 0, d = 0;
	unsigned long t = 0;
	char *alertfile = NULL, *nmpfdev = NULL;
	wbhead_t *wbhead = NULL;
	loopdata_t *loopdata = NULL;

	if ((wfile = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((bfile = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((alertfile = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((nmpfdev = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((extif = (char *)malloc(sizeof(char)*IFNAMSIZ)) == NULL) s2c_malloc_err();
	if ((loopdata = (loopdata_t *)malloc(sizeof(loopdata_t))) == NULL) s2c_malloc_err();

	bzero(wfile, NMBUFSIZ);
	bzero(bfile, NMBUFSIZ);
	bzero(alertfile, NMBUFSIZ);
	bzero(nmpfdev, NMBUFSIZ);
	bzero(extif, IFNAMSIZ);
	memset(loopdata, 0x00, sizeof(loopdata_t));

	loopdata->D = 0;
	loopdata->priority = 1;
	loopdata->thr_max = THRMAX;
	strlcpy(loopdata->tablename, __progname, PF_TABLE_NAME_SIZE);
	pf_reset = 0;
	v = 0;
	
	while ((ch = getopt(argc, argv, "w:p:m:r:vWDBb:a:l:e:t:h")) != -1)
		switch(ch) {
			case 'w':
				strlcpy(wfile, optarg, NMBUFSIZ);
				w = 1;
				break;
			case 'W':
				W = 1;
				break;
			case 'b':
				strlcpy(bfile, optarg, NMBUFSIZ);
				b = 1;
				break;
			case 'B':
				B = 1;
				break;
			case 'D':
				loopdata->D = 1;
				break;
			case 'v':
				v = 1;
				break;
			case 'a':
				strlcpy(alertfile, optarg, NMBUFSIZ);
				a = 1;
				break;
			case 'd':
				strlcpy(nmpfdev, optarg, NMBUFSIZ);
				d = 1;
				break;
			case 'l':
				strlcpy(loopdata->logfile, optarg, NMBUFSIZ);
				l = 1;
				break;
			case 'e':
				strlcpy(extif, optarg, IFNAMSIZ);
				e = 1;
				break;
			case 't':
				t = optnum("t", optarg);
				if(t == -1) usage();
				break;
			case 'p':
				loopdata->priority = optnum("p", optarg);
				if(loopdata->priority == -1) usage();
				if(!loopdata->priority) loopdata->priority = 1;
				break;
			case 'r':
				loopdata->repeat_offenses = optnum("r", optarg);
				if(loopdata->repeat_offenses == -1) usage();
				break;
			case 'm':
				loopdata->thr_max = optnum("m", optarg);
				if(loopdata->thr_max == -1) usage();
				if(!loopdata->thr_max) loopdata->thr_max = THRMAX;
				break;
			case 'h':
				usage();
			case '?':
				usage();
			default:
				usage();
		}
	
	argc -= optind;
	argv += optind;

	if (!w) strlcpy(wfile, PATH_WHITELIST, NMBUFSIZ);
	if (!b) strlcpy(bfile, PATH_BLACKLIST, NMBUFSIZ);
	if (!a) strlcpy(alertfile, PATH_ALERT, NMBUFSIZ);
	if (!d) strlcpy(nmpfdev, PFDEVICE, NMBUFSIZ);
	if (!e) strlcpy(extif, "all", IFNAMSIZ);
	if (!l) {
		strlcpy(loopdata->logfile, PATH_LOG, NMBUFSIZ);
		strlcat(loopdata->logfile,  __progname, NMBUFSIZ);
		strlcat(loopdata->logfile, ".log", NMBUFSIZ);
	}

	s2c_daemonize();

	if ((loopdata->dev = open(nmpfdev, O_RDWR)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, nmpfdev, LANG_EXIT);
		closelog();
		exit(EXIT_FAILURE);
	}

	free(nmpfdev);

	if ((loopdata->fd = s2c_kevent_open(alertfile)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s alertfile - %s", LANG_NO_OPEN, LANG_EXIT);
		closelog();
		exit(EXIT_FAILURE);
	}

	s2c_mutexes_init();
	s2c_log_init(loopdata->logfile);

	if ((wbhead = (wbhead_t *)malloc(sizeof(wbhead_t))) == NULL) s2c_malloc_err();
	memset(wbhead, 0x00, sizeof(wbhead_t));

	s2c_db_init(loopdata->dev, B, W, loopdata->tablename, &wbhead->whead);
	s2c_spawn_expiretable(loopdata->dev, loopdata->t);

	while (1) {
		s2c_kevent_loop(loopdata, &wbhead->whead, &wbhead->bhead);

		s2c_parse_and_block_wl_clear(&wbhead->whead);
		s2c_parse_and_block_bl_clear(&wbhead->bhead);
		free(wbhead);
		pf_reset = 0;

		if ((wbhead = (wbhead_t *)malloc(sizeof(wbhead_t))) == NULL) s2c_malloc_err();
		memset(wbhead, 0x00, sizeof(wbhead_t));

		s2c_db_init(loopdata->dev, B, W, loopdata->tablename, &wbhead->whead);
	}

	free(loopdata);
	free(wbhead);
	free(wfile);
	free(bfile);
	free(extif);
	return(0);
}
