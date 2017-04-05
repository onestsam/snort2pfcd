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
#include <sys/param.h>
#include <sys/stat.h>
#include <libutil.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>

#include "defdata.h"
#include "tools.h"

void
s2c_check_file(char *namefile)
{
	struct stat *info = NULL;

	if((info = (struct stat *)malloc(sizeof(struct stat))) == NULL) s2c_malloc_err();

	memset(info, 0x00, sizeof(struct stat));
	lstat(namefile, info);

	if (info->st_mode & S_IFDIR) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_FILE_ERROR, namefile, LANG_EXIT);
		s2c_exit_fail();
	}

	free(info);
	return;
}

void
s2c_write_file(char *namefile, char *message)
{
	FILE *lfile = NULL;

	if((lfile = fopen(namefile, "a")) == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, namefile, LANG_EXIT);
		s2c_exit_fail();
	}
	flockfile(lfile);
	fputs(message, lfile);
	funlockfile(lfile);
	fclose(lfile);
}

void
s2c_daemonize()
{
	struct pidfh *pfh = NULL;
	pid_t otherpid;
	char *pidfile = NULL;

	if((pidfile = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();

	bzero(pidfile, BUFMAX);
	memset(&otherpid, 0x00, sizeof(pid_t));

	memcpy(pidfile, PATH_RUN, BUFMAX);
	strlcat(pidfile,  __progname, BUFMAX);
	strlcat(pidfile, ".pid", BUFMAX);
	
	if ((pfh = pidfile_open(pidfile, 0600, &otherpid)) == NULL) {
		if (errno == EEXIST)
			syslog(LOG_ERR | LOG_DAEMON, "%s, pid: %d.", LANG_DAEMON_RUNNING, otherpid);
		fprintf(stderr, "%s", LANG_NO_PID);
	}

	if (daemon(0, 0) == -1) {
		fprintf(stderr, "%s", LANG_NO_DAEMON);
		pidfile_remove(pfh);
		exit(EXIT_FAILURE);
	} else {
		openlog(__progname, LOG_CONS | LOG_PID, LOG_DAEMON);
		syslog(LOG_DAEMON | LOG_NOTICE, "%s %s, pid: %d", __progname, LANG_START, getpid());
	}

	pidfile_write(pfh);
	free(pidfile);

	signal(SIGHUP,  sighup);
	signal(SIGTERM, sighup);
	signal(SIGINT,  sighup);

	return;
}

void
s2c_mutexes_init()
{
	s2c_threads = 1;
	memset(&dns_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&thr_mutex, 0x00, sizeof(pthread_mutex_t));

	if (pthread_mutex_init(&dns_mutex, NULL) != 0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	if (pthread_mutex_init(&thr_mutex, NULL) != 0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	return;
}

void
s2c_spawn_thread(void *(*func) (void *), void *data)
{
	typedef struct _twisted_t {
		pthread_t thr;
		pthread_attr_t attr;
	} twisted_t;

	twisted_t *yarn = NULL;
 
	if((yarn = (twisted_t *)malloc(sizeof(twisted_t))) == NULL) s2c_malloc_err();

	memset(yarn, 0x00, sizeof(twisted_t));
 
	if(pthread_attr_init(&yarn->attr)) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_INIT_THR, LANG_WARN);
 
	} else if(pthread_attr_setdetachstate(&yarn->attr, PTHREAD_CREATE_DETACHED)) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_SET_THR, LANG_WARN);
 
	} else if(pthread_create(&yarn->thr, &yarn->attr, func, data))
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_LAUNCH_THR, LANG_WARN);

	free(yarn);
	return;
}

void
s2c_pf_block_log_check()
{
	int threadcheck = 0;

	pthread_mutex_lock(&thr_mutex);
	threadcheck = s2c_threads;
	pthread_mutex_unlock(&thr_mutex);

	while(!(threadcheck < THRMAX)){
		sleep(10);
		pthread_mutex_lock(&thr_mutex);
		threadcheck = s2c_threads;
		pthread_mutex_unlock(&thr_mutex);  
	}

	return;
}

void
s2c_malloc_err()
{
	syslog(LOG_DAEMON | LOG_ERR, "%s - %s", LANG_MALLOC_ERROR, LANG_EXIT);
	s2c_exit_fail();
}

void
s2c_ioctl_err(char *ioctl_err_flag)
{
	syslog(LOG_DAEMON | LOG_ERR, "%s - %s - %s", ioctl_err_flag, LANG_IOCTL_ERROR, LANG_EXIT);
	s2c_exit_fail();
}

void
s2c_exit_fail()
{
	if(s2c_threads > 0) {
		pthread_mutex_destroy(&dns_mutex);
		pthread_mutex_destroy(&thr_mutex);
	}

	exit(EXIT_FAILURE);
}

int
optnum(char *opt, char *targ)
{
	char* endp = NULL;
	long l = -1;
        
	if (!targ || ((l=strtol(targ, &endp, 0)),(endp && *endp)))
		fprintf(stderr, "%s -%s %s.\n", LANG_ARG, opt, LANG_NUM);

	return (int)l;
}

void
usage()
{
	fprintf(stderr, "%s: %s [-h] [-e extif] [-w wfile] [-B] [-b bfile] [-a alertfile] [-l logfile] [-p priority] [-t expiretime]\n", LANG_USE, __progname);
	fprintf(stderr, "%s %s %s.", LANG_MAN, __progname, LANG_DETAILS);
	exit(EXIT_FAILURE);
}

void
sighup()
{
	syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_RECEXIT);
	if(s2c_threads > 0) {
		pthread_mutex_destroy(&dns_mutex);
		pthread_mutex_destroy(&thr_mutex);
	}
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

