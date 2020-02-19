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

void
*s2c_kevent_file_monitor(void *arg){
	thread_fm_t *data = (thread_fm_t *)arg;
	struct kevent trigger;
	char local_fn[NMBUFSIZ];
	int fid = 0, fr = 0, pf_reset_check = 0, *fm = NULL;
	loopdata_t *loopdata = NULL;
	unsigned long age = EXPTIME, last_time = 0, this_time = 0;
	lineproc_t *lineproc = NULL;

	if ((loopdata = (loopdata_t *)malloc(sizeof(loopdata_t))) == NULL) s2c_malloc_err();
	memcpy(loopdata, &data->loopdata, sizeof(loopdata_t));
	fid = data->fid;
	fr = data->fileread;
	fm = data->file_monitor;
	free(data);

	if (fid == ID_AF) strlcpy(local_fn, loopdata->alertfile, NMBUFSIZ);
	if (fid == ID_BF) strlcpy(local_fn, loopdata->bfile, NMBUFSIZ);
	if (fid == ID_WF) strlcpy(local_fn, loopdata->wfile, NMBUFSIZ);

	if (v) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_MON, local_fn);

	if(fr) {
		if (loopdata->t > 0) age = loopdata->t;
		if ((lineproc = (lineproc_t *)malloc(sizeof(lineproc_t))) == NULL) s2c_malloc_err();
		if(!loopdata->W) s2c_check_file(loopdata->wfile);
		if(!loopdata->B) s2c_check_file(loopdata->bfile);
	}

	while (1) {
		if (fr) {
			memset(lineproc, 0x00, sizeof(lineproc_t));

			if (regcomp(&lineproc->expr, REG_ADDR, REG_EXTENDED) != 0) {
				syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_ERR_REGEX, LANG_EXIT);
				s2c_exit_fail();
			}

			s2c_pf_ruleadd(loopdata->dev, loopdata->tablename);
			if (v) syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_CON_EST);

			pthread_mutex_lock(&fm_mutex);

			if(!loopdata->W) {
				s2c_kevent_wlf_reload(loopdata, lineproc);
				wfile_monitor = 0;
			}

			if(!loopdata->B) {
				s2c_parse_load_file(loopdata, lineproc, loopdata->bfile, &loopdata->wbhead.whead, NULL, ID_BF);
				bfile_monitor = 0;
			}

			pthread_mutex_unlock(&fm_mutex);

			this_time = last_time = time(NULL);
			pf_reset_check = 0;
		}

		while (!pf_reset_check) {

			if (fr) {
				this_time = time(NULL);

				if ((last_time + age) < (this_time + 1)) {
					last_time = this_time;
					s2c_parse_and_block_list_timeout(age, this_time, &loopdata->wbhead.bhead);
				}
			}

			s2c_kevent_open(&loopdata->kq, &loopdata->fd, local_fn);
			memset(&trigger, 0x00, sizeof(struct kevent));
			if (kevent(loopdata->kq, NULL, 0, &trigger, 1, NULL) == -1) {
				syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
				s2c_exit_fail();

			} else {
				if(fr) {
					if (s2c_kevent_read(loopdata, lineproc, trigger.data) == -1)
						syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_READ_ERROR, LANG_WARN);

					pthread_mutex_lock(&fm_mutex);

					if(wfile_monitor) {
						if(!loopdata->W) {
							s2c_kevent_wlf_reload(loopdata, lineproc);
							if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, loopdata->wfile, LANG_RELOAD);
						}
						wfile_monitor = 0;
					}

					if(bfile_monitor) {
						if(!loopdata->B) {
							s2c_pf_tbldel(loopdata->dev, loopdata->tablename_static);
							s2c_parse_load_file(loopdata, lineproc, loopdata->bfile, &loopdata->wbhead.whead, NULL, ID_BF);
							if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, loopdata->bfile, LANG_RELOAD);
						}
						bfile_monitor = 0;
					}

					pthread_mutex_unlock(&fm_mutex);

				}
				pthread_mutex_lock(&fm_mutex);
				*fm = 1;
				pthread_mutex_unlock(&fm_mutex);
			}

			if (fr) {
				pthread_mutex_lock(&pf_mutex);
				pf_reset_check = pf_reset;
				pf_reset = 0;
				pthread_mutex_unlock(&pf_mutex);
			}
		close(loopdata->kq);
		}

		if (fr)
			s2c_parse_and_block_list_clear(&loopdata->wbhead.bhead);
		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, LANG_PF, LANG_RELOAD);
	}

	if (fr) free(lineproc);

	free(local_fn);
	close(loopdata->fd);

	pthread_exit(NULL);
}

int
s2c_fd_open(char *file)
{
	int fd = 0;

	if ((fd = open(file, O_RDONLY)) == -1) return(-1);
	if (lseek(fd, 0, SEEK_END) == -1) return(-1);

	return(fd);
}

void
s2c_kevent_open(int *kq, int *fd, char *file)
{
	struct kevent change;

	if ((*kq = kqueue()) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KQ_ERROR, LANG_EXIT);
		s2c_exit_fail();
        }

	if ((*fd = s2c_fd_open(file)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, file, LANG_EXIT);
		s2c_exit_fail();
	}

	memset(&change, 0x00, sizeof(struct kevent));
	EV_SET(&change, *fd, EVFILT_VNODE, EV_ADD | EV_ENABLE, NOTE_EXTEND | NOTE_WRITE, 0, NULL);

	if (kevent(*kq, &change, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	return;
}

void
s2c_kevent_wlf_reload(loopdata_t *loopdata, lineproc_t *lineproc)
{
	s2c_parse_and_block_list_clear(&loopdata->wbhead.whead);
	s2c_parse_load_wl(loopdata, loopdata->wfile, lineproc, &loopdata->wbhead.whead);
	if (v) s2c_parse_print_list(&loopdata->wbhead.whead);

	return;
}

void
s2c_kevent_loop(loopdata_t *loopdata)
{
	unsigned int pf_reset_check = 0, pf_tbl_state_init = 0, pf_tbl_state_current = 0;
	pftbl_t pftbl;

	pf_tbl_state_init = pf_tbl_state_current = s2c_pf_tbl_get(loopdata->dev, loopdata->tablename, &pftbl);

	while (1) {
		sleep(10);
		pf_tbl_state_current = s2c_pf_tbl_get(loopdata->dev, loopdata->tablename, &pftbl);

		pthread_mutex_lock(&fm_mutex);

		if (wfile_monitor)
			pf_reset_check = 1;

		if (bfile_monitor)
			pf_reset_check = 1;
		
		pthread_mutex_unlock(&fm_mutex);

		if (pf_tbl_state_current < pf_tbl_state_init)
			pf_reset_check = 1;

		if (pf_reset_check) {
			pf_reset_check = 0;
			pthread_mutex_lock(&pf_mutex);
			pf_reset = 1;
			pthread_mutex_unlock(&pf_mutex);
			s2c_write_file(loopdata->alertfile, " ");
		}

		pf_tbl_state_init = pf_tbl_state_current;
	}

	return;
}

int
s2c_kevent_read(loopdata_t *loopdata, lineproc_t *lineproc, int nbytes)
{
	int i = 0, r = 0, total = 0;

	do  {
		for (i = 0; i < BUFSIZ; i++) {
			if((r = read(loopdata->fd, &lineproc->cad[i], sizeof(char))) <= 0) return(r);
			if (lineproc->cad[i] == '\n') {
				lineproc->cad[i] = '\0';
				break;
			}
		}

		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_READ, lineproc->cad);
		s2c_parse_and_block(loopdata, lineproc);
		total += i;

	} while (i > 0 && total < nbytes);

	return(total);
}
