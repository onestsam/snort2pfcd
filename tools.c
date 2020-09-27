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
 * s2cd_radix_ioctl from ioctl_helpers.c                    
 * s2cd_radix_get_astats from ioctl_helpers.c                                    
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
#include "version.h"

void s2cd_sw_s(const char *lsw, const char *lsw2, const char *lsw3, const char *lsw4) {

	if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", lsw, lsw2, lsw3, lsw4);
	else fprintf(stderr, "%s %s %s - %s\n", lsw, lsw2, lsw3, lsw4);

	return;

}   /* s2cd_sw_s */

void s2cd_sw_sf(const char *lsw, const char *lsw2, const char *lsw3, const char *lsw4) {

	s2cd_sw_s(lsw, lsw2, lsw3, lsw4);
	s2cd_exit_fail();

	return;

}   /* s2cd_sw_sf */

void s2cd_check_file(char *namefile, struct stat *info) {

	memset((struct stat *)info, 0x00, sizeof(struct stat));
	lstat(namefile, info);

	if (info->st_mode & S_IFDIR) s2cd_sw_sf("", S2CD_LANG_FILE_ERROR, namefile, S2CD_LANG_EXIT);

	return;

}   /* s2cd_check_file */

void s2cd_write_file(char *namefile, const char *message) {

	FILE *lfile = NULL;

	pthread_mutex_lock(&log_mutex);

	if ((lfile = fopen(namefile, "a")) == NULL) s2cd_sw_sf("", S2CD_LANG_NO_OPEN, namefile, S2CD_LANG_EXIT);

	flockfile(lfile);
	fputs(message, lfile);
	funlockfile(lfile);
	fclose(lfile);

	pthread_mutex_unlock(&log_mutex);

	return;

}   /* s2cd_write_file */

void s2cd_mutex_init() {

	memset((pthread_mutex_t *)&log_mutex, 0x00, sizeof(pthread_mutex_t));
	memset((pthread_mutex_t *)&dns_mutex, 0x00, sizeof(pthread_mutex_t));
	memset((pthread_mutex_t *)&thr_mutex, 0x00, sizeof(pthread_mutex_t));
	memset((pthread_mutex_t *)&pf_mutex, 0x00, sizeof(pthread_mutex_t));
	memset((pthread_mutex_t *)&fm_mutex, 0x00, sizeof(pthread_mutex_t));

	if (pthread_mutex_init(&log_mutex, NULL) == 0)
	if (pthread_mutex_init(&dns_mutex, NULL) == 0)
	if (pthread_mutex_init(&thr_mutex, NULL) == 0)
	if (pthread_mutex_init(&pf_mutex, NULL) == 0)
	if (pthread_mutex_init(&fm_mutex, NULL) == 0)
		return;

	s2cd_sw_sf("", "", S2CD_LANG_MUTEX_ERROR, S2CD_LANG_EXIT);

	return;

}   /* s2cd_mutex_init */

void s2cd_thr_init(struct lpdt_t *lpdt) {

	if (lpdt->v) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %d", S2CD_LANG_PRIB, lpdt->priority);
		else fprintf(stderr, "%s - %d\n", S2CD_LANG_PRIB, lpdt->priority);
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %d", S2CD_LANG_THRS, lpdt->thr_max);
		else fprintf(stderr, "%s - %d\n", S2CD_LANG_THRS, lpdt->thr_max);
	}   /* if (lpdt->v) */

	if (s2cd_spawn_expiretable(lpdt)) s2cd_sw_s("", "", S2CD_LANG_PTRHR_ERROR, S2CD_LANG_EXIT);
	else if (s2cd_spawn_file_monitor(&pfile_monitor, S2CD_MONITOR_ONLY, S2CD_ID_PF, lpdt)) s2cd_sw_s("", "", S2CD_LANG_PTRHR_ERROR, S2CD_LANG_EXIT);
	else if (s2cd_spawn_file_monitor(&bfile_monitor, S2CD_MONITOR_ONLY, S2CD_ID_BF, lpdt)) s2cd_sw_s("", "", S2CD_LANG_PTRHR_ERROR, S2CD_LANG_EXIT);
	else if (s2cd_spawn_file_monitor(&afile_monitor, S2CD_MONITOR_READ, S2CD_ID_AF, lpdt)) s2cd_sw_s("", "", S2CD_LANG_PTRHR_ERROR, S2CD_LANG_EXIT);
	else return;

	s2cd_exit_fail();

	return;

}   /* s2cd_thr_init */

int s2cd_spawn_file_monitor(int *notifaddr, int fileread, int fid, struct lpdt_t *lpdt) {

	struct thread_fm_t *fm_data = NULL;

	if ((fm_data = (struct thread_fm_t *)malloc(sizeof(struct thread_fm_t))) == NULL) S2CD_MALLOC_ERR;
	memset((struct thread_fm_t *)fm_data, 0x00, sizeof(struct thread_fm_t));

	fm_data->file_monitor = notifaddr;
	fm_data->fileread = fileread;
	fm_data->fid = fid;
	memcpy(&fm_data->lpdt, lpdt, sizeof(struct lpdt_t));

	return(s2cd_spawn_thread(s2cd_kevent_file_monitor, fm_data));

}   /* s2cd_spawn_file_monitor */

int s2cd_spawn_expiretable(struct lpdt_t *lpdt) {

	struct thread_expt_t *expt_data = NULL;

	if ((expt_data = (struct thread_expt_t *)malloc(sizeof(struct thread_expt_t))) == NULL) S2CD_MALLOC_ERR;
	memset((struct thread_expt_t *)expt_data, 0x00, sizeof(struct thread_expt_t));

	expt_data->t = lpdt->t;
	expt_data->v = lpdt->v;
	expt_data->C = lpdt->C;
	expt_data->dev = lpdt->dev;
	strlcpy(expt_data->logfile, lpdt->logfile, S2CD_NMBUFSIZ);
	strlcpy(expt_data->nmpfdev, lpdt->nmpfdev, S2CD_NMBUFSIZ);
	strlcpy(expt_data->tblnm, lpdt->tblnm, PF_TABLE_NAME_SIZE);

	return(s2cd_spawn_thread(s2cd_pf_expiretable, expt_data));

}   /* s2cd_spawn_expiretable */

int s2cd_spawn_block_log(int C, int D, char *logip, char *logfile) {

	struct thread_log_t *log_data = NULL;

	if ((log_data = (struct thread_log_t *)malloc(sizeof(struct thread_log_t))) == NULL) S2CD_MALLOC_ERR;
	memset((struct thread_log_t *)log_data, 0x00, sizeof(struct thread_log_t));

	log_data->C = C;
	log_data->D = D;
	strlcpy(log_data->logfile, logfile, S2CD_NMBUFSIZ);
	strlcpy(log_data->logip, logip, BUFSIZ);

	return(s2cd_spawn_thread(s2cd_pf_block_log, log_data));

}   /* s2cd_spawn_block_log */

int s2cd_spawn_thread(void *(*func) (void *), void *data) {

	int thr_check = 1;
	struct twisted_t {
		pthread_t thr;
		pthread_attr_t attr;
	};

	struct twisted_t yarn; 
	memset((struct twisted_t *)&yarn, 0x00, sizeof(struct twisted_t));
 
	if (pthread_attr_init(&yarn.attr)) s2cd_sw_s("", "", S2CD_LANG_INIT_THR, S2CD_LANG_WARN);
	else if (pthread_attr_setdetachstate(&yarn.attr, PTHREAD_CREATE_DETACHED)) s2cd_sw_s("", "", S2CD_LANG_SET_THR, S2CD_LANG_WARN);
	else if (pthread_create(&yarn.thr, &yarn.attr, func, data)) s2cd_sw_s("", "", S2CD_LANG_LAUNCH_THR, S2CD_LANG_WARN);
	else thr_check = 0;

	return(thr_check);

}   /* s2cd_spawn_thread */

void s2cd_pre_exit() {

	s2cd_mutex_destroy();
	pidfile_remove(pfh);
	closelog();

	return;

}   /* s2cd_pre_exit */

void s2cd_exit_fail() {

	s2cd_pre_exit();
	exit(EXIT_FAILURE);

	return;

}   /* s2cd_exit_fail */

void s2cd_mutex_destroy() {

	int s2cd_threads_check = (S2CD_BASE_THR + 1);

	while (s2cd_threads_check > S2CD_BASE_THR) {	
		pthread_mutex_lock(&thr_mutex);
		s2cd_threads_check = s2cd_threads;
		pthread_mutex_unlock(&thr_mutex);
		if (s2cd_threads_check > S2CD_BASE_THR) {
			s2cd_sw_s("", "", "", S2CD_LANG_THR_WAIT);
			sleep(5);
		}   /* if (s2cd_threads_check */
	}   /* while (s2cd_threads_check */

	pthread_mutex_destroy(&log_mutex);
	pthread_mutex_destroy(&dns_mutex);
	pthread_mutex_destroy(&thr_mutex);
	pthread_mutex_destroy(&pf_mutex);
	pthread_mutex_destroy(&fm_mutex);

	return;

}   /* s2cd_mutex_destroy */

void s2cd_usage() {

	fprintf(stderr, "%s: %s %s\n", S2CD_LANG_USE, __progname, S2CD_OPTIONS);
	fprintf(stderr, "%s %s %s.\n", S2CD_LANG_MAN, __progname, S2CD_LANG_DETAILS);
	s2cd_exit_fail();

	return;

}   /* s2cd_usage */

void s2cd_sighandle() {

	s2cd_sw_s("", "", S2CD_LANG_RECEXIT, S2CD_LANG_EXIT);
	s2cd_pre_exit();
	exit(EXIT_SUCCESS);

	return;

}   /* s2cd_sighandle */

time_t s2cd_lmin(time_t a, time_t b) {

	return (a < b)?a:b;

}   /* s2cd_lmin */
