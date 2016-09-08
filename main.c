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
#include <sys/param.h>
#include <libutil.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>

#include "spfc.h"
#include "parser.h"
#include "kevent.h"
#include "version.h"

void usage();
void sighup();
void sigterm();
void sigint();

int
main(int argc, char **argv)
{	
	int fd, dev, kq, ch, i, t = 0;
	char *wfile     = "/usr/local/etc/snort/rules/iplists/default.whitelist"; 
	char *alertfile = "/var/log/snort/alert";
	char *extif = "all";
	char pidfile[32];
	char logfile[32];
	char tablename[32];
	struct wlist_head whead;
	struct pidfh *pfh;
	pid_t otherpid;
	pthread_t expt_thr;
	thread_expt_t expt_data;

	bzero(tablename, 32);
	bzero(pidfile, 32);
	bzero(logfile, 32);
	memset(&whead, 0x00, sizeof(struct wlist_head));
	memset(&expt_thr, 0x00, sizeof(pthread_t));
	memset(&expt_data, 0x00, sizeof(thread_expt_t));
	memset(&otherpid, 0x00, sizeof(pid_t));

	strlcpy(tablename, __progname, 32);

	if (getuid() != 0) {
		fprintf(stderr, "Error: must be root to run %s - exit\n", tablename);
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "%s version %s\n", tablename, VERSION);
	
	memcpy(pidfile, "/var/run/", 32);
	strlcat(pidfile,  tablename, 32);
	strlcat(pidfile, ".pid", 32);

	memcpy(logfile, "/var/log/", 32);
	strlcat(logfile,  tablename, 32);
	strlcat(logfile, ".log", 32);

	while ((ch = getopt(argc, argv, "hw:a:e:t:l:")) != -1)
		switch(ch) {
			case 'w':
				wfile = optarg;
				break;
			case 'a':
				alertfile = optarg;
				break;
			case 'l':
				memcpy(&logfile, &optarg, sizeof(logfile));
				break;
			case 'e':
				extif = optarg;
				break;
			case 't':
				t = atoi(optarg);
				break;
			case 'h':
			case '?':
			default:
				usage();
		}
	
	argc -= optind;
	argv += optind;

	pfh = pidfile_open(pidfile, 0600, &otherpid);
	if (pfh == NULL) {
	     if	(errno == EEXIST)
		syslog(LOG_ERR | LOG_DAEMON, "Daemon already running, pid: %d.", otherpid);
		fprintf(stderr, "Cannot open or create pidfile");
	}

	if (daemon(0, 0) == -1) {
		fprintf(stderr, "Cannot daemonize");
		pidfile_remove(pfh);
		exit(EXIT_FAILURE);
	} else {
		openlog(tablename, LOG_CONS | LOG_PID, LOG_DAEMON);
		syslog(LOG_DAEMON | LOG_NOTICE, "%s started, pid: %d", tablename, getpid());
	}

	pidfile_write(pfh);

	signal(SIGHUP,  sighup);
	signal(SIGTERM, sigterm);
	signal(SIGINT,  sigint);
	
	/* kqueue init */	
	kq = s2c_kevent_init();
	if (kq == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "kqueue init error - exit");
		exit(EXIT_FAILURE);
	}

	fd = s2c_kevent_open(alertfile);
	if (fd == -1) {  
		syslog(LOG_ERR | LOG_DAEMON, "unable to open alertfile - exit");
		exit(EXIT_FAILURE);
	}	
	
	i = s2c_kevent_set(fd, kq);
	if (i == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to set kevent structure - exit");
		exit(EXIT_FAILURE);
	}

	/* pf init */	
	dev = s2c_pf_init();
	if (dev == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to open /dev/pf device - exit");
		exit(EXIT_FAILURE);
	}

	/* wlist init */	
	i = s2c_parse_load_wl(wfile, extif, &whead);
	if (i == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to load a whitelist file - warning");
	}

	/* initrule mode */
	i = s2c_pf_ruleadd(dev, tablename);
	if (i == 1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to add ruletable - exit");
		exit(EXIT_FAILURE);
	}

	/* incorporate expiretable as threaded async process */
	expt_data.t = t;
	expt_data.dev = dev;
	memcpy(expt_data.tablename, tablename, PF_TABLE_NAME_SIZE);

	if((i = pthread_create(&expt_thr, NULL, s2c_pf_expiretable, &expt_data)))
		syslog(LOG_ERR | LOG_DAEMON, "unable to expire entries from ruletable - warning");

	s2c_kevent_loop(fd, dev, kq, logfile, tablename, whead);

	return(0);
}

void 
usage()
{
	fprintf(stderr, "usage: %s [-h] [-e extif] [-w wfile] [-a alertfile] [-l logfile] [-t expiretime]\n", __progname);
	fprintf(stderr, "wfile, logfile, alertfile: path to file, expiretime in seconds.");
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
