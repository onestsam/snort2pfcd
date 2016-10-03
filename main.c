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
#include <ctype.h>
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
	int fd, dev, kq, ch, t = 0;
	int priority = 1;
	char *wfile     = "/usr/local/etc/snort/rules/iplists/default.whitelist";
	char *bfile     = "/usr/local/etc/snort/rules/iplists/default.blacklist";
	char *alertfile = "/var/log/snort/alert";
	char *extif = "all";
	char pidfile[32];
	char logfile[32];
	char dyn_tablename[32];
	char static_tablename[32];
	struct wlist_head whead;
	struct pidfh *pfh;
	pid_t otherpid;
	thread_expt_t *expt_data;

	expt_data = (thread_expt_t *)malloc(sizeof(thread_expt_t));

	bzero(pidfile, 32);
	bzero(logfile, 32);
	bzero(dyn_tablename, 32);
	bzero(static_tablename, 32);
	memset(&whead, 0x00, sizeof(struct wlist_head));
	memset(&otherpid, 0x00, sizeof(pid_t));
	memset(expt_data, 0x00, sizeof(thread_expt_t));

	strlcpy(dyn_tablename, __progname, 32);
	strlcpy(static_tablename, __progname, 32);
	strlcat(static_tablename, "_static", 32);

	if (getuid() != 0) {
		fprintf(stderr, "Error: must be root to run %s - exit\n", __progname);
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "%s version %s\n", __progname, VERSION);
	
	memcpy(pidfile, "/var/run/", 32);
	strlcat(pidfile,  __progname, 32);
	strlcat(pidfile, ".pid", 32);

	memcpy(logfile, "/var/log/", 32);
	strlcat(logfile,  __progname, 32);
	strlcat(logfile, ".log", 32);

	while ((ch = getopt(argc, argv, "hw:a:b:e:t:p:l:")) != -1)
		switch(ch) {
			case 'w':
				wfile = optarg;
				break;
			case 'b':
				bfile = optarg;
				break;
			case 'a':
				alertfile = optarg;
				break;
			case 'l':
				memcpy(&logfile, optarg, sizeof(logfile));
				break;
			case 'e':
				extif = optarg;
				break;
			case 't':
				if(isdigit(*optarg)){
					t = atoi(optarg);
				} else {
					fprintf(stderr, " Argument for -t must be a number.");
					usage();
				}
				break;
			case 'p':
				if(isdigit(*optarg)){
					priority = atoi(optarg);
				} else {
					fprintf(stderr, " Argument for -p must be a number.");
					usage();
				}
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
		openlog(__progname, LOG_CONS | LOG_PID, LOG_DAEMON);
		syslog(LOG_DAEMON | LOG_NOTICE, "%s started, pid: %d", __progname, getpid());
	}

	pidfile_write(pfh);

	signal(SIGHUP,  sighup);
	signal(SIGTERM, sigterm);
	signal(SIGINT,  sigint);
	
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

	dev = open(PFDEVICE, O_RDWR);
	if (dev == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to open /dev/pf device - exit");
		exit(EXIT_FAILURE);
	}

	if (s2c_parse_load_wl(wfile, extif, &whead) == -1)
		syslog(LOG_ERR | LOG_DAEMON, "unable to load whitelist file - warning");

	if (s2c_pf_ruleadd(dev, dyn_tablename) == 1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to add ruletable - exit");
		exit(EXIT_FAILURE);
	}

        if (s2c_pf_ruleadd(dev, static_tablename) == 1) {
                syslog(LOG_ERR | LOG_DAEMON, "unable to add ruletable - exit");
                exit(EXIT_FAILURE);
        }

	if (s2c_parse_load_bl(dev, static_tablename, bfile, &whead) == -1)
		syslog(LOG_ERR | LOG_DAEMON, "unable to load blacklist file - warning");

	expt_data->t = t;
	expt_data->dev = dev;
	memcpy(expt_data->tablename, dyn_tablename, PF_TABLE_NAME_SIZE);
	s2c_spawn_expt_thread(expt_data);

	s2c_kevent_loop(fd, dev, priority, kq, logfile, dyn_tablename, whead);

	return(0);
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
