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
	int fd, dev, kq, ch, B, t = 0;
	int priority = 1;
	char *wfile     = "/usr/local/etc/snort/rules/iplists/default.whitelist";
	char *bfile     = "/usr/local/etc/snort/rules/iplists/default.blacklist";
	char *alertfile = "/var/log/snort/alert";
	char *extif = "all";
	char logfile[LOGMAX];
	char dyn_tablename[TBLMAX];
	char static_tablename[TBLMAX];
	struct wlist_head *whead;
	thread_expt_t *expt_data;

	if (getuid() != 0) {
		fprintf(stderr, "Error: must be root to run %s - exit\n", __progname);
		exit(EXIT_FAILURE);
	}

	whead = (struct wlist_head *)malloc(sizeof(struct wlist_head));

	if(whead == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error E01 - exit");
		s2c_exit_fail();
	}

	expt_data = (thread_expt_t *)malloc(sizeof(thread_expt_t));

	if(expt_data == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error E02 - exit");
		s2c_exit_fail();
	}

	bzero(logfile, LOGMAX);
	bzero(dyn_tablename, TBLMAX);
	bzero(static_tablename, TBLMAX);
	memset(whead, 0x00, sizeof(struct wlist_head));
	memset(expt_data, 0x00, sizeof(thread_expt_t));

	strlcpy(dyn_tablename, __progname, TBLMAX);
	strlcpy(static_tablename, __progname, TBLMAX);
	strlcat(static_tablename, "_static", TBLMAX);

	fprintf(stdout, "%s version %s\n", __progname, VERSION);
	
	memcpy(logfile, "/var/log/", LOGMAX);
	strlcat(logfile,  __progname, LOGMAX);
	strlcat(logfile, ".log", LOGMAX);

	while ((ch = getopt(argc, argv, "w:p:Bb:a:l:e:t:h")) != -1)
		switch(ch) {
			case 'w':
				wfile = optarg;
				break;
			case 'b':
				bfile = optarg;
				break;
			case 'B':
				B = 1;
				break;
			case 'a':
				alertfile = optarg;
				break;
			case 'l':
				memcpy(logfile, optarg, 64);
				break;
			case 'e':
				extif = optarg;
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

	dev = open(PFDEVICE, O_RDWR);
	if (dev == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to open /dev/pf device - exit");
		exit(EXIT_FAILURE);
	}

	kq = kqueue();
	if (kq == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "kqueue init error - exit");
		exit(EXIT_FAILURE);
	}

	fd = s2c_kevent_open(alertfile);
	if (fd == -1) {  
		syslog(LOG_ERR | LOG_DAEMON, "unable to open alertfile - exit");
		exit(EXIT_FAILURE);
	}	
	
	if (s2c_kevent_set(fd, kq) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to set kevent structure - exit");
		exit(EXIT_FAILURE);
	}

	if (s2c_parse_load_wl(wfile, extif, whead) == -1)
		syslog(LOG_ERR | LOG_DAEMON, "unable to load whitelist file - warning");

	if (s2c_pf_ruleadd(dev, dyn_tablename) == 1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to add ruletable - exit");
		exit(EXIT_FAILURE);
	}

	if (!B) if (s2c_parse_load_bl(dev, static_tablename, bfile, whead) == -1)
		syslog(LOG_ERR | LOG_DAEMON, "unable to load blacklist file - warning");

	expt_data->t = t;
	expt_data->dev = dev;
	memcpy(expt_data->tablename, dyn_tablename, PF_TABLE_NAME_SIZE);
	s2c_spawn_thread(s2c_pf_expiretable, expt_data);

	s2c_mutexes_init();
	s2c_kevent_loop(fd, dev, priority, kq, logfile, dyn_tablename, whead);

	return(0);
}

