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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <syslog.h>
#include <pthread.h>

#include "defdata.h"
#include "spfc.h"
#include "parser.h"
#include "kevent.h"
#include "tools.h"
#include "version.h"

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int fd = 0, dev = 0, kq = 0, ch = 0, B = 0, priority = 1;
	unsigned long t = 0;
	long timebuf = 0;
	FILE *lfile = NULL;
	char *alertfile = NULL, *initmess = NULL, *logfile = NULL, *dyn_tablename = NULL, *static_tablename = NULL;
	struct wlist_head *whead = NULL;
	struct blist_head *bhead = NULL;
	thread_expt_t *expt_data = NULL;

	s2c_threads = 0;
	wfile = NULL;
	bfile = NULL;
	extif = NULL;

	fprintf(stdout, "%s version %s\n", __progname, VERSION);

	if (getuid() != 0) {
		fprintf(stderr, "%s %s - %s\n", LANG_ERR_ROOT, __progname, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	if((wfile = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();
	if((bfile = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();
	if((extif = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();
	if((alertfile = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();
	if((logfile = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();
	if((dyn_tablename = (char *)malloc(sizeof(char)*TBLNAMEMAX)) == NULL) s2c_malloc_err();
	if((static_tablename = (char *)malloc(sizeof(char)*TBLNAMEMAX)) == NULL) s2c_malloc_err();

	bzero(wfile, BUFMAX);
	bzero(bfile, BUFMAX);
	bzero(extif, BUFMAX);

	bzero(logfile, BUFMAX);
	bzero(alertfile, BUFMAX);
	bzero(dyn_tablename, TBLNAMEMAX);
	bzero(static_tablename, TBLNAMEMAX);

	strlcpy(wfile, PATH_WHITELIST, BUFMAX);
	strlcpy(bfile, PATH_BLACKLIST, BUFMAX);
	strlcpy(extif, "all", BUFMAX);
	strlcpy(alertfile, PATH_ALERT, BUFMAX);
	strlcpy(dyn_tablename, __progname, TBLNAMEMAX);
	strlcpy(static_tablename, __progname, TBLNAMEMAX);
	strlcat(static_tablename, "_static", TBLNAMEMAX);
	
	strlcpy(logfile, PATH_LOG, BUFMAX);
	strlcat(logfile,  __progname, BUFMAX);
	strlcat(logfile, ".log", BUFMAX);

	while ((ch = getopt(argc, argv, "w:p:Bb:a:l:e:t:h")) != -1)
		switch(ch) {
			case 'w':
				strlcpy(wfile, optarg, BUFMAX);
				break;
			case 'b':
				strlcpy(bfile, optarg, BUFMAX);
				break;
			case 'B':
				B = 1;
				break;
			case 'a':
				strlcpy(alertfile, optarg, BUFMAX);
				break;
			case 'l':
				strlcpy(logfile, optarg, BUFMAX);
				break;
			case 'e':
				strlcpy(extif, optarg, BUFMAX);
				break;
			case 't':
				t = optnum("t", optarg);
				if(t == -1) usage();
				break;
			case 'p':
				priority = optnum("p", optarg);
				if(priority == -1) usage();
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

	daemonize();
	checkfile(bfile);
	checkfile(wfile);
	checkfile(alertfile);
	checkfile(logfile);

	if ((dev = open(PFDEVICE, O_RDWR)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, PFDEVICE, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KQ_ERROR, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	if ((fd = s2c_kevent_open(alertfile)) == -1) {  
		syslog(LOG_ERR | LOG_DAEMON, "%s alertfile - %s", LANG_NO_OPEN, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	free(alertfile);
	
	if (s2c_kevent_set(fd, kq) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_ERROR, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	if((whead = (struct wlist_head *)malloc(sizeof(struct wlist_head))) == NULL) s2c_malloc_err();
	if((bhead = (struct blist_head *)malloc(sizeof(struct blist_head))) == NULL) s2c_malloc_err();

	memset(whead, 0x00, sizeof(struct wlist_head));
	memset(bhead, 0x00, sizeof(struct blist_head));

	s2c_mutexes_init();

	s2c_parse_load_wl(whead);

	while (s2c_pf_ruleadd(dev, dyn_tablename)) {
		syslog(LOG_ERR | LOG_DAEMON, "%s ruletable - %s", LANG_NO_OPEN, LANG_WARN);
		sleep(1);
	}

	if (!B) if (s2c_parse_load_bl(dev, static_tablename, whead, bhead))
		syslog(LOG_ERR | LOG_DAEMON, "%s blacklist file - %s", LANG_NO_OPEN, LANG_WARN);

	if((expt_data = (thread_expt_t *)malloc(sizeof(thread_expt_t))) == NULL) s2c_malloc_err();

	memset(expt_data, 0x00, sizeof(thread_expt_t));

	expt_data->t = t;
	expt_data->dev = dev;
	memcpy(expt_data->tablename, dyn_tablename, TBLNAMEMAX);
	s2c_spawn_thread(s2c_pf_expiretable, expt_data);

	if((initmess = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();

	bzero(initmess, BUFMAX);
	timebuf = time(NULL);

	sprintf(initmess, "\n<======= %s %s %s \n", __progname, LANG_START, asctime(localtime(&timebuf)));

	lfile = fopen(logfile, "a");
	flockfile(lfile);
	fputs(initmess, lfile);
	funlockfile(lfile);
	fclose(lfile);
	free(initmess);

	s2c_kevent_loop(t, fd, dev, priority, kq, logfile, dyn_tablename, whead, bhead);

	return(0);
}
