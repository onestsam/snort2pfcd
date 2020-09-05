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
 * s2cd_parse_line based in pfctl code (pfctl_radix.c)
 * Copyright (c) Armin's Wolfermann
 *
 * s2cd_pf_block functions are based
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
#include "version.h"

void s2cd_check_file(char *namefile) {

	struct stat *info = NULL;

	if ((info = (struct stat *)malloc(sizeof(struct stat))) == NULL) s2cd_malloc_err();
	memset(info, 0x00, sizeof(struct stat));
	lstat(namefile, info);

	if (info->st_mode & S_IFDIR) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", S2CD_LANG_FILE_ERROR, namefile, S2CD_LANG_EXIT);
		else fprintf(stderr, "%s %s - %s\n", S2CD_LANG_FILE_ERROR, namefile, S2CD_LANG_EXIT);
		s2cd_exit_fail();
	}   /* if (info->st_mode */

	free(info);

	return;

} /* s2cd_check_file */

void s2cd_write_file(char *namefile, char *message) {

	FILE *lfile = NULL;

	pthread_mutex_lock(&log_mutex);

	if ((lfile = fopen(namefile, "a")) == NULL) {
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", S2CD_LANG_NO_OPEN, namefile, S2CD_LANG_EXIT);
		else fprintf(stderr, "%s %s - %s\n", S2CD_LANG_NO_OPEN, namefile, S2CD_LANG_EXIT);
		s2cd_exit_fail();
	}   /* if ((lfile */

	flockfile(lfile);
	fputs(message, lfile);
	funlockfile(lfile);
	fclose(lfile);

	pthread_mutex_unlock(&log_mutex);

	return;

} /* s2cd_write_file */

void s2cd_mutex_init() {

	memset(&log_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&dns_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&thr_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&pf_mutex, 0x00, sizeof(pthread_mutex_t));
	memset(&fm_mutex, 0x00, sizeof(pthread_mutex_t));

	if (pthread_mutex_init(&log_mutex, NULL) == 0)
	if (pthread_mutex_init(&dns_mutex, NULL) == 0)
	if (pthread_mutex_init(&thr_mutex, NULL) == 0)
	if (pthread_mutex_init(&pf_mutex, NULL) == 0)
	if (pthread_mutex_init(&fm_mutex, NULL) == 0)
		return;

	if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", S2CD_LANG_MUTEX_ERROR, S2CD_LANG_EXIT);
	else fprintf(stderr, "%s - %s\n", S2CD_LANG_MUTEX_ERROR, S2CD_LANG_EXIT);
	s2cd_exit_fail();

	return;

} /* s2cd_mutex_init */

void s2cd_thr_init(loopdata_t *loopdata) {

	if (v) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %d", S2CD_LANG_PRIB, loopdata->priority);
		else fprintf(stderr, "%s - %d\n", S2CD_LANG_PRIB, loopdata->priority);
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %d", S2CD_LANG_THRS, loopdata->thr_max);
		else fprintf(stderr, "%s - %d\n", S2CD_LANG_THRS, loopdata->thr_max);
	}   /* if (v) */

	s2cd_spawn_expiretable(loopdata);
	s2cd_spawn_file_monitor(&pfile_monitor, S2CD_MONITOR_ONLY, S2CD_ID_PF, loopdata);
	s2cd_spawn_file_monitor(&bfile_monitor, S2CD_MONITOR_ONLY, S2CD_ID_BF, loopdata);
	s2cd_spawn_file_monitor(&afile_monitor, S2CD_MONITOR_READ, S2CD_ID_AF, loopdata);

	return;

} /* s2cd_thr_init */

void s2cd_spawn_file_monitor(int *notifaddr, int fileread, int fid, loopdata_t *loopdata) {

	thread_fm_t *fm_data = NULL;

	if ((fm_data = (thread_fm_t *)malloc(sizeof(thread_fm_t))) == NULL) s2cd_malloc_err();
	memset(fm_data, 0x00, sizeof(thread_fm_t));

	fm_data->file_monitor = notifaddr;
	fm_data->fileread = fileread;
	fm_data->fid = fid;
	memcpy(&fm_data->loopdata, loopdata, sizeof(loopdata_t));
	s2cd_spawn_thread(s2cd_kevent_file_monitor, fm_data);

	return;

} /* s2cd_spawn_file_monitor */

void s2cd_spawn_expiretable(loopdata_t *loopdata) {

	thread_expt_t *expt_data = NULL;

	if ((expt_data = (thread_expt_t *)malloc(sizeof(thread_expt_t))) == NULL) s2cd_malloc_err();
	memset(expt_data, 0x00, sizeof(thread_expt_t));

	expt_data->t = loopdata->t;
	expt_data->dev = loopdata->dev;
	strlcpy(expt_data->logfile, loopdata->logfile, S2CD_NMBUFSIZ);
	strlcpy(expt_data->nmpfdev, loopdata->nmpfdev, S2CD_NMBUFSIZ);
	strlcpy(expt_data->tablename, loopdata->tablename, PF_TABLE_NAME_SIZE);
	s2cd_spawn_thread(s2cd_pf_expiretable, expt_data);

	return;

} /* s2cd_spawn_expiretable */

void s2cd_spawn_block_log(int D, char *logip, char *logfile) {

	thread_log_t *log_data = NULL;

	if ((log_data = (thread_log_t *)malloc(sizeof(thread_log_t))) == NULL) s2cd_malloc_err();

	memset(log_data, 0x00, sizeof(thread_log_t));

	log_data->D = D;
	strlcpy(log_data->logfile, logfile, S2CD_NMBUFSIZ);
	strlcpy(log_data->logip, logip, BUFSIZ);
	s2cd_spawn_thread(s2cd_pf_block_log, log_data);

	return;

} /* s2cd_spawn_block_log */

void s2cd_spawn_thread(void *(*func) (void *), void *data) {

	typedef struct _twisted_t {
		pthread_t thr;
		pthread_attr_t attr;
	} twisted_t;

	twisted_t *yarn = NULL;
 
	if ((yarn = (twisted_t *)malloc(sizeof(twisted_t))) == NULL) s2cd_malloc_err();

	memset(yarn, 0x00, sizeof(twisted_t));
 
	if (pthread_attr_init(&yarn->attr)) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", S2CD_LANG_INIT_THR, S2CD_LANG_WARN);
		else fprintf(stderr, "%s - %s\n", S2CD_LANG_INIT_THR, S2CD_LANG_WARN);
 
	} else if (pthread_attr_setdetachstate(&yarn->attr, PTHREAD_CREATE_DETACHED)) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", S2CD_LANG_SET_THR, S2CD_LANG_WARN);
		else fprintf(stderr, "%s - %s\n", S2CD_LANG_SET_THR, S2CD_LANG_WARN);
 
	} else if (pthread_create(&yarn->thr, &yarn->attr, func, data)) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", S2CD_LANG_LAUNCH_THR, S2CD_LANG_WARN);
		else fprintf(stderr, "%s - %s\n", S2CD_LANG_LAUNCH_THR, S2CD_LANG_WARN);
	}   /* if (pthread */

	free(yarn);

	return;

} /* s2cd_spawn_thread */

void s2cd_malloc_err() {

	if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s - %s", S2CD_LANG_MALLOC_ERROR, S2CD_LANG_EXIT);
	else fprintf(stderr, "%s - %s\n", S2CD_LANG_MALLOC_ERROR, S2CD_LANG_EXIT);
	s2cd_exit_fail();

	return;

} /* s2cd_malloc_err */

void s2cd_pre_exit() {

	s2cd_mutex_destroy();
	pidfile_remove(pfh);
	closelog();

	return;

} /* s2cd_pre_exit */

void s2cd_exit_fail() {

	s2cd_pre_exit();
	exit(EXIT_FAILURE);

	return;

} /* s2cd_exit_fail */

void s2cd_mutex_destroy() {

	int s2cd_threads_check = 0;
	
	pthread_mutex_lock(&thr_mutex);
	s2cd_threads_check = s2cd_threads;
	pthread_mutex_unlock(&thr_mutex);

	if (s2cd_threads_check > 0) {
		pthread_mutex_destroy(&log_mutex);
		pthread_mutex_destroy(&dns_mutex);
		pthread_mutex_destroy(&thr_mutex);
		pthread_mutex_destroy(&pf_mutex);
		pthread_mutex_destroy(&fm_mutex);
	}   /* if (s2cd_threads_check */

	return;

} /* s2cd_mutex_destroy */

void s2cd_usage() {

	fprintf(stderr, "%s: %s [-h] [-v] [-e extif] [-w pfile] [-W] [-b bfile] [-B] [-C] [-D] [-F] [-Z] [-a alertfile] [-d pf_device] [-l logfile] [-p priority] [-t expiretime] [-q wait_time] [-m thr_max] [-r repeat_offenses]\n", S2CD_LANG_USE, __progname);
	fprintf(stderr, "%s %s %s.\n", S2CD_LANG_MAN, __progname, S2CD_LANG_DETAILS);
	s2cd_exit_fail();

	return;

} /* s2cd_usage */

void s2cd_sighandle() {

	if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s", S2CD_LANG_RECEXIT);
	else fprintf(stderr, "%s\n", S2CD_LANG_RECEXIT);
	s2cd_pre_exit();
	exit(EXIT_SUCCESS);

	return;

} /* s2cd_sighandle */

time_t s2cd_lmin(time_t a, time_t b) {

	return (a < b)?a:b;

} /* s2cd_lmin */
