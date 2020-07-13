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
#include "version.h"

void
s2c_check_file(char *namefile)
{
	struct stat *info = NULL;

	if ((info = (struct stat *)malloc(sizeof(struct stat))) == NULL) s2c_malloc_err();
	memset(info, 0x00, sizeof(struct stat));
	lstat(namefile, info);

	if (info->st_mode & S_IFDIR) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_FILE_ERROR, namefile, LANG_EXIT);
		else fprintf(stderr, "%s %s - %s", LANG_FILE_ERROR, namefile, LANG_EXIT);
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
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, namefile, LANG_EXIT);
		else fprintf(stderr, "%s %s - %s", LANG_NO_OPEN, namefile, LANG_EXIT);
		s2c_exit_fail();
	}

	flockfile(lfile);
	fputs(message, lfile);
	funlockfile(lfile);
	fclose(lfile);

	pthread_mutex_unlock(&log_mutex);

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

	if (pthread_mutex_init(&log_mutex, NULL) == 0)
	if (pthread_mutex_init(&dns_mutex, NULL) == 0)
	if (pthread_mutex_init(&thr_mutex, NULL) == 0)
	if (pthread_mutex_init(&pf_mutex, NULL) == 0)
	if (pthread_mutex_init(&fm_mutex, NULL) == 0)
		return;

	if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
	else fprintf(stderr, "%s - %s", LANG_MUTEX_ERROR, LANG_EXIT);
	s2c_exit_fail();

	return;
}

void
s2c_thr_init(loopdata_t *loopdata)
{
	if (v) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %d", LANG_PRIB, loopdata->priority);
		else fprintf(stderr, "%s - %d", LANG_PRIB, loopdata->priority);
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %d", LANG_THRS, loopdata->thr_max);
		else fprintf(stderr, "%s - %d", LANG_THRS, loopdata->thr_max);
	}

	s2c_spawn_expiretable(loopdata);
	s2c_spawn_file_monitor(&wfile_monitor, 0, ID_WF, loopdata);
	s2c_spawn_file_monitor(&bfile_monitor, 0, ID_BF, loopdata);
	s2c_spawn_file_monitor(&afile_monitor, 1, ID_AF, loopdata);

	return;
}

void
s2c_spawn_file_monitor(int *notifaddr, int fileread, int fid, loopdata_t *loopdata)
{
	thread_fm_t *fm_data = NULL;

	if ((fm_data = (thread_fm_t *)malloc(sizeof(thread_fm_t))) == NULL) s2c_malloc_err();
	memset(fm_data, 0x00, sizeof(thread_fm_t));

	fm_data->file_monitor = notifaddr;
	fm_data->fileread = fileread;
	fm_data->fid = fid;
	memcpy(&fm_data->loopdata, loopdata, sizeof(loopdata_t));
	s2c_spawn_thread(s2c_kevent_file_monitor, fm_data);

	return;
}

void
s2c_spawn_expiretable(loopdata_t *loopdata)
{
	thread_expt_t *expt_data = NULL;

	if ((expt_data = (thread_expt_t *)malloc(sizeof(thread_expt_t))) == NULL) s2c_malloc_err();
	memset(expt_data, 0x00, sizeof(thread_expt_t));

	expt_data->t = loopdata->t;
	expt_data->dev = loopdata->dev;
	strlcpy(expt_data->logfile, loopdata->logfile, NMBUFSIZ);
	strlcpy(expt_data->nmpfdev, loopdata->nmpfdev, NMBUFSIZ);
	strlcpy(expt_data->tablename, loopdata->tablename, PF_TABLE_NAME_SIZE);
	s2c_spawn_thread(s2c_pf_expiretable, expt_data);

	return;
}

void
s2c_spawn_block_log(int D, char *logip, char *logfile)
{
	thread_log_t *log_data = NULL;

	if ((log_data = (thread_log_t *)malloc(sizeof(thread_log_t))) == NULL) s2c_malloc_err();

	memset(log_data, 0x00, sizeof(thread_log_t));

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
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_INIT_THR, LANG_WARN);
		else fprintf(stderr, "%s - %s", LANG_INIT_THR, LANG_WARN);
 
	} else if (pthread_attr_setdetachstate(&yarn->attr, PTHREAD_CREATE_DETACHED)) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_SET_THR, LANG_WARN);
		else fprintf(stderr, "%s - %s", LANG_SET_THR, LANG_WARN);
 
	} else if (pthread_create(&yarn->thr, &yarn->attr, func, data)) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_LAUNCH_THR, LANG_WARN);
		else fprintf(stderr, "%s - %s", LANG_LAUNCH_THR, LANG_WARN);
	}

	free(yarn);

	return;
}

void
s2c_malloc_err()
{
	if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s - %s", LANG_MALLOC_ERROR, LANG_EXIT);
	else fprintf(stderr, "%s - %s", LANG_MALLOC_ERROR, LANG_EXIT);
	s2c_exit_fail();

	return;
}

void
s2c_pre_exit()
{
	s2c_mutex_destroy();
	pidfile_remove(pfh);
	closelog();

	return;
}

void
s2c_exit_fail()
{
	s2c_pre_exit();
	exit(EXIT_FAILURE);

	return;
}

void
s2c_mutex_destroy()
{
	int s2c_threads_check = 0;
	
	pthread_mutex_lock(&thr_mutex);
	s2c_threads_check = s2c_threads;
	pthread_mutex_unlock(&thr_mutex);

	if (s2c_threads_check > 0) {
		pthread_mutex_destroy(&log_mutex);
		pthread_mutex_destroy(&dns_mutex);
		pthread_mutex_destroy(&thr_mutex);
		pthread_mutex_destroy(&pf_mutex);
		pthread_mutex_destroy(&fm_mutex);
	}

	return;
}

void
usage()
{
	fprintf(stderr, "%s: %s [-h] [-v] [-e extif] [-w wfile] [-W] [-b bfile] [-B] [-C] [-D] [-F] [-Z] [-a alertfile] [-d pf_device] [-l logfile] [-p priority] [-t expiretime] [-q wait_time] [-m thr_max] [-r repeat_offenses]\n", LANG_USE, __progname);
	fprintf(stderr, "%s %s %s.", LANG_MAN, __progname, LANG_DETAILS);
	s2c_exit_fail();

	return;
}

void
sighandle()
{
	if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_RECEXIT);
	else fprintf(stderr, "%s", LANG_RECEXIT);
	s2c_pre_exit();
	exit(EXIT_SUCCESS);

	return;
}

long
lmin(long a,long b) {
	return (a < b)?a:b;
}
