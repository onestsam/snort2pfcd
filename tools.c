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


void
s2c_check_file(char *namefile)
{
	struct stat *info = NULL;

	if ((info = (struct stat *)malloc(sizeof(struct stat))) == NULL) s2c_malloc_err();
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

	pthread_mutex_lock(&log_mutex);

	if ((lfile = fopen(namefile, "a")) == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, namefile, LANG_EXIT);
		s2c_exit_fail();
	}

	flockfile(lfile);
	fputs(message, lfile);
	funlockfile(lfile);
	fclose(lfile);

	pthread_mutex_unlock(&log_mutex);
	return;
}

int
s2c_open_pf(char *nmpfdev)
{
	int dev = 0;

	if ((dev = open(nmpfdev, O_RDWR)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, nmpfdev, LANG_EXIT);
		s2c_exit_fail();
	}
	free(nmpfdev);
	return(dev);
}

int
s2c_open_file(char *file)
{
	int fd = 0;

	if ((fd = s2c_kevent_open(file)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s alertfile - %s", LANG_NO_OPEN, LANG_EXIT);
		s2c_exit_fail();
	}
	free(file);
	return(fd);
}

void
s2c_wbhead_reset(wbhead_t *wbhead)
{
	s2c_parse_and_block_wl_clear(&wbhead->whead);
	s2c_parse_and_block_bl_clear(&wbhead->bhead);
	free(wbhead);

	pthread_mutex_lock(&pf_mutex);
	pf_reset = 0;
	pthread_mutex_unlock(&pf_mutex);

	if ((wbhead = (wbhead_t *)malloc(sizeof(wbhead_t))) == NULL) s2c_malloc_err();
	memset(wbhead, 0x00, sizeof(wbhead_t));

	return;
}

void
s2c_init()
{
	wfile_monitor = 0;
	bfile_monitor = 0;
	s2c_threads = 0;
	pf_reset = 0;
	v = 0;

	if (getuid() != 0) {
		fprintf(stderr, "%s %s - %s\n", LANG_ERR_ROOT, __progname, LANG_EXIT);
		exit(EXIT_FAILURE);
	}

	s2c_mutex_init();

	signal(SIGHUP,  sighandle);
	signal(SIGTERM, sighandle);
	signal(SIGINT,  sighandle);

	return;
}

void
s2c_daemonize()
{
	struct pidfh *pfh = NULL;
	pid_t otherpid;
	char *pidfile = NULL;

	if ((pidfile = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	memset(&otherpid, 0x00, sizeof(pid_t));
	bzero(pidfile, NMBUFSIZ);

	memcpy(pidfile, PATH_RUN, NMBUFSIZ);
	strlcat(pidfile,  __progname, NMBUFSIZ);
	strlcat(pidfile, ".pid", NMBUFSIZ);
	
	if ((pfh = pidfile_open(pidfile, 0600, &otherpid)) == NULL)
		fprintf(stderr, "%s", LANG_NO_PID);

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
	return;
}

void
s2c_log_init(char *logfile)
{
	long timebuf = 0;
	char *initmess = NULL;

	s2c_check_file(logfile);
	if ((initmess = (char *)malloc(sizeof(char)*BUFSIZ)) == NULL) s2c_malloc_err();

	bzero(initmess, BUFSIZ);
	timebuf = time(NULL);

	sprintf(initmess, "\n<======= %s %s %s \n", __progname, LANG_START, asctime(localtime(&timebuf)));
	s2c_write_file(logfile, initmess);

	free(initmess);
	return;
}

void
s2c_db_init(loopdata_t *loopdata, struct wlist_head *whead)
{
	lineproc_t *lineproc = NULL;

	s2c_check_file(bfile);
	s2c_check_file(wfile);

	if ((lineproc = (lineproc_t *)malloc(sizeof(lineproc_t))) == NULL) s2c_malloc_err();

	if (!loopdata->W) s2c_parse_load_wl(loopdata->Z, lineproc, whead);
	s2c_pf_ruleadd(loopdata->dev, loopdata->tablename);
	if (!loopdata->B) s2c_parse_load_bl_static(loopdata->dev, lineproc, loopdata->tablename, whead);
	if (v) syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_CON_EST);

	free(lineproc);
	return;
}

void
s2c_mutex_init()
{
	s2c_threads = 1;
	memset(&log_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&dns_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&thr_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&pf_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&fm_mutex, 0x00, sizeof(pthread_mutex_t));

	if (pthread_mutex_init(&log_mutex, NULL) != 0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
		closelog();
		exit(EXIT_FAILURE);
	}

	if (pthread_mutex_init(&dns_mutex, NULL) != 0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
		closelog();
		exit(EXIT_FAILURE);
	}

	if (pthread_mutex_init(&thr_mutex, NULL) != 0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
		closelog();
		exit(EXIT_FAILURE);
	}

	if (pthread_mutex_init(&pf_mutex, NULL) != 0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
		closelog();
		exit(EXIT_FAILURE);
	}

	if (pthread_mutex_init(&fm_mutex, NULL) != 0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
		closelog();
		exit(EXIT_FAILURE);
	}

	return;
}

void
s2c_thr_init(loopdata_t *loopdata){

	s2c_spawn_expiretable(loopdata->dev, loopdata->t, loopdata->logfile);
	s2c_spawn_file_monitor(&wfile_monitor, wfile);
	s2c_spawn_file_monitor(&bfile_monitor, bfile);

	return;
}

void
s2c_spawn_file_monitor(int *notifaddr, char *filename)
{
	thread_fm_t *fm_data = NULL;

	if ((fm_data = (thread_fm_t *)malloc(sizeof(thread_fm_t))) == NULL) s2c_malloc_err();

	memset(fm_data, 0x00, sizeof(thread_fm_t));

	fm_data->file_monitor = notifaddr;
	strlcpy(fm_data->file, filename, NMBUFSIZ);
	s2c_spawn_thread(s2c_kevent_file_monitor, fm_data);

	return;
}

void
s2c_spawn_expiretable(int dev, int t, char *logfile)
{
	thread_expt_t *expt_data = NULL;

	if ((expt_data = (thread_expt_t *)malloc(sizeof(thread_expt_t))) == NULL) s2c_malloc_err();

	memset(expt_data, 0x00, sizeof(thread_expt_t));

	expt_data->t = t;
	expt_data->dev = dev;
	strlcpy(expt_data->logfile, logfile, NMBUFSIZ);
	strlcpy(expt_data->tablename, __progname, PF_TABLE_NAME_SIZE);
	s2c_spawn_thread(s2c_pf_expiretable, expt_data);

	return;
}

void
s2c_spawn_block_log(int D, int thr_max, char *logip, char *logfile)
{
	thread_log_t *log_data = NULL;

	if ((log_data = (thread_log_t *)malloc(sizeof(thread_log_t))) == NULL) s2c_malloc_err();

	memset(log_data, 0x00, sizeof(thread_log_t));

	s2c_pf_block_log_check(thr_max);

	log_data->D = D;
	strlcpy(log_data->logfile, logfile, NMBUFSIZ);
	strlcpy(log_data->logip, logip, BUFSIZ);
	s2c_spawn_thread(s2c_pf_block_log, log_data);

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
 
	if ((yarn = (twisted_t *)malloc(sizeof(twisted_t))) == NULL) s2c_malloc_err();

	memset(yarn, 0x00, sizeof(twisted_t));
 
	if (pthread_attr_init(&yarn->attr)) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_INIT_THR, LANG_WARN);
 
	} else if (pthread_attr_setdetachstate(&yarn->attr, PTHREAD_CREATE_DETACHED)) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_SET_THR, LANG_WARN);
 
	} else if (pthread_create(&yarn->thr, &yarn->attr, func, data))
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_LAUNCH_THR, LANG_WARN);

	free(yarn);
	return;
}

void
s2c_malloc_err()
{
	syslog(LOG_DAEMON | LOG_ERR, "%s - %s", LANG_MALLOC_ERROR, LANG_EXIT);
	s2c_exit_fail();
}

void
s2c_ioctl_wait(char *ioctl_wait_flag)
{
	if (v) syslog(LOG_DAEMON | LOG_ERR, "%s - %s - %s", ioctl_wait_flag, LANG_IOCTL_WAIT, LANG_WARN);
	sleep(3);
	return;
}

void
s2c_exit_fail()
{
	s2c_mutex_destroy();
	closelog();
	exit(EXIT_FAILURE);
}

void
s2c_mutex_destroy(){
	int s2c_local_threads = 0;

	pthread_mutex_lock(&thr_mutex);
	s2c_local_threads = s2c_threads;
	pthread_mutex_unlock(&thr_mutex);

	if (s2c_local_threads > 0) {
		pthread_mutex_destroy(&log_mutex);
		pthread_mutex_destroy(&dns_mutex);
		pthread_mutex_destroy(&thr_mutex);
		pthread_mutex_destroy(&pf_mutex);
		pthread_mutex_destroy(&fm_mutex);
	}
	return;
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
	fprintf(stderr, "%s: %s [-h] [-v] [-e extif] [-w wfile] [-W] [-b bfile] [-B] [-D] [-F] [-Z] [-a alertfile] [-d pf_device] [-l logfile] [-p priority] [-t expiretime] [-q wait_time] [-m thr_max] [-r repeat_offenses]\n", LANG_USE, __progname);
	fprintf(stderr, "%s %s %s.", LANG_MAN, __progname, LANG_DETAILS);
	s2c_exit_fail();
}

void
sighandle()
{
	syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_RECEXIT);
	s2c_mutex_destroy();
	closelog();
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
