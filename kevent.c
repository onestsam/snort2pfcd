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
 * s2cd_pf_expiretable from expiretable
 * s2cd_radix_ioctlfrom ioctl_helpers.c
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

void *s2cd_kevent_file_monitor(void *arg) {

	thread_fm_t *data = (thread_fm_t *)arg;
	struct kevent *trigger = NULL;
	char local_fn[S2CD_NMBUFSIZ];
	loopdata_t *loopdata = NULL;
	int fid = data->fid, fr = data->fileread, pf_reset_check = 0, F = 0, *fm = data->file_monitor;
	time_t age = S2CD_EXPTIME, last_time = 0, this_time = 0;
	lineproc_t *lineproc = NULL;

	if ((trigger = (struct kevent *)malloc(sizeof(struct kevent))) == NULL) S2CD_MALLOC_ERR;
	if ((loopdata = (loopdata_t *)malloc(sizeof(loopdata_t))) == NULL) S2CD_MALLOC_ERR;
	memset(loopdata, 0x00, sizeof(loopdata_t));
	memcpy(loopdata, &data->loopdata, sizeof(loopdata_t));
	F = loopdata->F;
	free(data);

	if (fid == S2CD_ID_AF) strlcpy(local_fn, loopdata->alertfile, S2CD_NMBUFSIZ);
	else if (fid == S2CD_ID_BF) strlcpy(local_fn, loopdata->bfile, S2CD_NMBUFSIZ);
	else if (fid == S2CD_ID_PF) strlcpy(local_fn, loopdata->pfile, S2CD_NMBUFSIZ);
	else s2cd_sw_switch_f(F, S2CD_LANG_ERR_ID, S2CD_LANG_EXIT);

	if (loopdata->v) s2cd_sw_switch(F, S2CD_LANG_MON, local_fn);

	if (fr) {
		if (loopdata->t > 0) age = loopdata->t;
		if ((lineproc = (lineproc_t *)malloc(sizeof(lineproc_t))) == NULL) S2CD_MALLOC_ERR;
		if (!loopdata->W) s2cd_check_file(F, loopdata->pfile);
		if (!loopdata->B) s2cd_check_file(F, loopdata->bfile);
	}   /* if (fr) */

	while (1) {
		if (fr) {
			memset(lineproc, 0x00, sizeof(lineproc_t));

			if (regcomp(&lineproc->expr, S2CD_REG_ADDR, REG_EXTENDED) != 0) s2cd_sw_switch_f(F, S2CD_LANG_ERR_REGEX, S2CD_LANG_EXIT);

			if (s2cd_pf_rule_add(loopdata->dev, loopdata->v, loopdata->F, loopdata->tablename) < 0)
			if (loopdata->v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, "s2cd_kevent_file_monitor");
			if (loopdata->v) s2cd_sw_switch(F, S2CD_LANG_CON_EST, "");

			pthread_mutex_lock(&fm_mutex);
			if (!loopdata->W) {
				s2cd_kevent_plf_reload(loopdata, lineproc);
				pfile_monitor = 0;
			}   /* if (!loopdata->W) */

			if (!loopdata->B) {
				s2cd_parse_load_file(loopdata, lineproc, loopdata->bfile, &loopdata->pbhead.phead, NULL, S2CD_ID_BF);
				bfile_monitor = 0;
			}   /* if (!loopdata->B) */
			pthread_mutex_unlock(&fm_mutex);

			this_time = last_time = loopdata->timebuf;
			pf_reset_check = 0;
		}   /* if (fr) */

		while (!pf_reset_check) {

			if (fr) {
				if (!loopdata->C) this_time = time(NULL);
				else this_time = 1;

				if ((last_time + age) < (this_time + 1)) {
					last_time = this_time;
					s2cd_parse_and_block_list_timeout(age, this_time, &loopdata->pbhead.bhead);
				}   /* if ((last_time */
			}   /* if (fr) */

			s2cd_kevent_open(F, &loopdata->kq, &loopdata->fd, local_fn);
			memset(trigger, 0x00, sizeof(struct kevent));
			if (kevent(loopdata->kq, NULL, 0, trigger, 1, NULL) == -1) s2cd_sw_switch_f(F, S2CD_LANG_KE_REQ_ERROR, S2CD_LANG_EXIT);
			else {
				if (fr) {
					if (s2cd_kevent_read(loopdata, lineproc, trigger->data) == -1) s2cd_sw_switch(F, S2CD_LANG_KE_READ_ERROR, S2CD_LANG_WARN);

					pthread_mutex_lock(&fm_mutex);
					if (pfile_monitor) {
						if (!loopdata->W) {
							s2cd_kevent_plf_reload(loopdata, lineproc);
							if (loopdata->v) s2cd_sw_switch_e(F, S2CD_LANG_STATE_CHANGE, loopdata->pfile, S2CD_LANG_RELOAD);
						}   /* if (!loopdata->W) */
						pfile_monitor = 0;
					}   /* if (pfile_monitor) */
					if (bfile_monitor) {
						if (!loopdata->B) {
							s2cd_pf_tbl_del(loopdata->dev, loopdata->v, F, loopdata->tablename_static);
							s2cd_parse_load_file(loopdata, lineproc, loopdata->bfile, &loopdata->pbhead.phead, NULL, S2CD_ID_BF);
							if (loopdata->v) s2cd_sw_switch_e(F, S2CD_LANG_STATE_CHANGE, loopdata->bfile, S2CD_LANG_RELOAD);
						}   /* if (!loopdata->B) */
						bfile_monitor = 0;
					}   /* if (bfile_monitor) */
					pthread_mutex_unlock(&fm_mutex);

				}   /* if (fr) */
				pthread_mutex_lock(&fm_mutex);
				*fm = 1;
				pthread_mutex_unlock(&fm_mutex);
			}   /* else if (kevent */

			if (fr) {
				pthread_mutex_lock(&pf_mutex);
				pf_reset_check = pf_reset;
				pf_reset = 0;
				pthread_mutex_unlock(&pf_mutex);
			}   /* if (fr) */

		close(loopdata->kq);

		}   /* while (!pf_reset_check) */

		if (fr) s2cd_parse_and_block_list_clear(&loopdata->pbhead.bhead);
		if (loopdata->v) s2cd_sw_switch_e(F, S2CD_LANG_STATE_CHANGE, S2CD_LANG_PF, S2CD_LANG_RELOAD);

	}   /* while (1) */

	if (fr) free(lineproc);

	close(loopdata->fd);
	free(loopdata);
	free(local_fn);

	pthread_exit(NULL);

}   /* s2cd_kevent_file_monitor */

int s2cd_fd_open(char *file) {
	int fd = 0;

	if ((fd = open(file, O_RDONLY)) == -1) return(-1);
	if (lseek(fd, 0, SEEK_END) == -1) return(-1);

	return(fd);

}   /* s2cd_fd_open */

void s2cd_kevent_open(int F, int *kq, int *fd, char *file) {

	struct kevent *change;

	if ((*kq = kqueue()) == -1) s2cd_sw_switch_f(F, S2CD_LANG_KQ_ERROR, S2CD_LANG_EXIT);
	if ((*fd = s2cd_fd_open(file)) == -1) s2cd_sw_switch_ef(F, S2CD_LANG_NO_OPEN, file, S2CD_LANG_EXIT);

	if ((change = (struct kevent *)malloc(sizeof(struct kevent))) == NULL) S2CD_MALLOC_ERR;
	memset(change, 0x00, sizeof(struct kevent));
	EV_SET(change, *fd, EVFILT_VNODE, EV_ADD | EV_ENABLE, NOTE_EXTEND | NOTE_WRITE, 0, NULL);

	if (kevent(*kq, change, 1, NULL, 0, NULL) == -1) s2cd_sw_switch_f(F, S2CD_LANG_KE_REQ_ERROR, S2CD_LANG_EXIT);

	free(change);

	return;

}   /* s2cd_kevent_open */

void s2cd_kevent_plf_reload(loopdata_t *loopdata, lineproc_t *lineproc) {

	s2cd_parse_and_block_list_clear(&loopdata->pbhead.phead);
	s2cd_parse_load_pl(loopdata, loopdata->pfile, lineproc, &loopdata->pbhead.phead);
	if (loopdata->v) s2cd_parse_print_list(loopdata->F, &loopdata->pbhead.phead);

	return;

}   /* s2cd_kevent_plf_reload */

void s2cd_kevent_loop(loopdata_t *loopdata) {

	unsigned int pf_reset_check = 0, pf_tbl_state_init = 0, pf_tbl_state_current = 0;
	pftbl_t *pftbl;
	int F = loopdata->F;

	if ((pftbl = (pftbl_t *)malloc(sizeof(pftbl_t))) == NULL) S2CD_MALLOC_ERR;
	memset(pftbl, 0x00, sizeof(pftbl_t));

	if ((pf_tbl_state_init = pf_tbl_state_current = s2cd_pf_tbl_get(loopdata->dev, loopdata->v, loopdata->F, loopdata->tablename, pftbl)) < 0)
	if (loopdata->v) s2cd_sw_switch(loopdata->F, S2CD_LANG_IOCTL_ERROR, "s2cd_kevent_loop");

	while (1) {
		if ((pf_tbl_state_current = s2cd_pf_tbl_get(loopdata->dev, loopdata->v, loopdata->F, loopdata->tablename, pftbl)) < 0)
		if (loopdata->v) s2cd_sw_switch(loopdata->F, S2CD_LANG_IOCTL_ERROR, "s2cd_kevent_loop");

		/* I always have problems with && and || operators */
		pthread_mutex_lock(&fm_mutex);
		if (pfile_monitor) pf_reset_check = 1;
		if (bfile_monitor) pf_reset_check = 1;
		pthread_mutex_unlock(&fm_mutex);

		if (pf_tbl_state_current < pf_tbl_state_init) pf_reset_check = 1;
		pf_tbl_state_init = pf_tbl_state_current;

		if (pf_reset_check) {
			pf_reset_check = 0;
			pthread_mutex_lock(&pf_mutex);
			pf_reset = 1;
			pthread_mutex_unlock(&pf_mutex);
			s2cd_write_file(loopdata->F, loopdata->alertfile, " ");
		} else {
			if (!loopdata->C) sleep(S2CD_PF_POLLING_FREQ);
			if (loopdata->v) if (loopdata->F) fprintf(stderr, "%s\n", S2CD_LANG_KE_WAIT);
		}   /* else */
	}   /* while (1) */

	free(pftbl);

	return;

}   /* s2cd_kevent_loop */

int s2cd_kevent_read(loopdata_t *loopdata, lineproc_t *lineproc, int nbytes) {

	register int i = 0;
	int r = 0, total = 0;

	do  {
		for (i = 0; i < BUFSIZ; i++) {
			if ((r = read(loopdata->fd, &lineproc->cad[i], sizeof(char))) <= 0) return(r);
			if (lineproc->cad[i] == '\n') {
				lineproc->cad[i] = '\0';
				break;
			}   /* if (lineproc */
		}   /* for (i */

		if (loopdata->v) s2cd_sw_switch(loopdata->F, S2CD_LANG_KE_READ, lineproc->cad);
		s2cd_parse_and_block(loopdata, lineproc);
		total += i;

	} while (i > 0 && total < nbytes);

	return(total);

}   /* s2cd_kevent_read */
