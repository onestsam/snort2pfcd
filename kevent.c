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

void *s2cd_kevent_file_monitor(void *arg) {

	struct evdp_t {
		struct kevent trigger;
		struct lpdt_t lpdt;
		struct lnpc_t lnpc;
		struct pftbl_t pftbl;
		struct stat fstat;
	};

	struct thread_fm_t *data = (struct thread_fm_t *)arg;
	time_t age = S2CD_EXPTIME, last_time = 0, this_time = 0;
	int fid = 0, fr = 0, pf_reset_check = 0, *fm = NULL;
	struct evdp_t *evdp = NULL;
	char lfn[S2CD_NMBUFSIZ];

	if ((evdp = (struct evdp_t *)malloc(sizeof(struct evdp_t))) == NULL) S2CD_MALLOC_ERR;
	memset((struct evdp_t *)evdp, 0x00, sizeof(struct evdp_t));
	memcpy(&evdp->lpdt, &data->lpdt, sizeof(struct lpdt_t));
	fid = data->fid;
	fr = data->fileread;
	fm = data->file_monitor;
	free(data);

	if (fid == S2CD_ID_AF) strlcpy(lfn, evdp->lpdt.alertfile, S2CD_NMBUFSIZ);
	else if (fid == S2CD_ID_BF) strlcpy(lfn, evdp->lpdt.bfile, S2CD_NMBUFSIZ);
	else if (fid == S2CD_ID_PF) strlcpy(lfn, evdp->lpdt.pfile, S2CD_NMBUFSIZ);
	else s2cd_sw_switch_f(S2CD_LANG_ERR_ID, S2CD_LANG_EXIT);

	if (evdp->lpdt.v) s2cd_sw_switch(S2CD_LANG_MON, lfn);

	if (fr) {
		if (evdp->lpdt.t > 0) age = evdp->lpdt.t;
		if (!evdp->lpdt.W) s2cd_check_file(evdp->lpdt.pfile, &evdp->fstat);
		if (!evdp->lpdt.B) s2cd_check_file(evdp->lpdt.bfile, &evdp->fstat);
	}   /* if (fr) */

	while (1) {
		if (fr) {
			memset((struct lnpc_t *)&evdp->lnpc, 0x00, sizeof(struct lnpc_t));

			if (regcomp(&evdp->lnpc.expr, S2CD_REG_ADDR, REG_EXTENDED) != 0) s2cd_sw_switch_f(S2CD_LANG_ERR_REGEX, S2CD_LANG_EXIT);

			s2cd_pf_rule_add(evdp->lpdt.dev, evdp->lpdt.v, evdp->lpdt.tablename, &evdp->pftbl);
			if (evdp->lpdt.v) s2cd_sw_switch(S2CD_LANG_CON_EST, "");

			pthread_mutex_lock(&fm_mutex);

			if (!evdp->lpdt.W) {
				s2cd_kevent_plf_reload(&evdp->pftbl, &evdp->lpdt, &evdp->lnpc);
				pfile_monitor = 0;
			}   /* if (!evdp->lpdt.W) */

			if (!evdp->lpdt.B) {
				s2cd_parse_load_file(&evdp->pftbl, &evdp->lpdt, &evdp->lnpc, evdp->lpdt.bfile, &evdp->lpdt.pbhead.phead, NULL, S2CD_ID_BF);
				bfile_monitor = 0;
			}   /* if (!evdp->lpdt.B) */

			pthread_mutex_unlock(&fm_mutex);

			this_time = last_time = evdp->lpdt.timebuf;
			pf_reset_check = 0;
		}   /* if (fr) */

		while (!pf_reset_check) {

			if (fr) {
				if (!evdp->lpdt.C) this_time = time(NULL);
				else this_time = 1;

				if ((last_time + age) < (this_time + 1)) {
					last_time = this_time;
					s2cd_parse_and_block_list_timeout(age, this_time, &evdp->lpdt.pbhead.bhead);
				}   /* if ((last_time */
			}   /* if (fr) */

			s2cd_kevent_open(&evdp->trigger, &evdp->lpdt.kq, &evdp->lpdt.fd, lfn);
			memset((struct kevent *)&evdp->trigger, 0x00, sizeof(struct kevent));
			if (kevent(evdp->lpdt.kq, NULL, 0, &evdp->trigger, 1, NULL) == -1) s2cd_sw_switch_f(S2CD_LANG_KE_REQ_ERROR, S2CD_LANG_EXIT);
			else {
				if (fr) {
					if (s2cd_kevent_read(&evdp->lpdt, &evdp->lnpc, &evdp->pftbl, evdp->trigger.data) == -1)
						s2cd_sw_switch(S2CD_LANG_KE_READ_ERROR, S2CD_LANG_WARN);

					pthread_mutex_lock(&fm_mutex);

					if (pfile_monitor) {
						if (!evdp->lpdt.W) {
							s2cd_kevent_plf_reload(&evdp->pftbl, &evdp->lpdt, &evdp->lnpc);
							if (evdp->lpdt.v) s2cd_sw_switch_e(S2CD_LANG_STATE_CHANGE, evdp->lpdt.pfile, S2CD_LANG_RELOAD);
						}   /* if (!lpdt->W) */
						pfile_monitor = 0;
					}   /* if (pfile_monitor) */

					if (bfile_monitor) {
						if (!evdp->lpdt.B) {
							s2cd_pf_tbl_del(evdp->lpdt.dev, evdp->lpdt.v, evdp->lpdt.tablename_static, &evdp->pftbl);
							s2cd_parse_load_file(&evdp->pftbl, &evdp->lpdt, &evdp->lnpc, evdp->lpdt.bfile, &evdp->lpdt.pbhead.phead, NULL, S2CD_ID_BF);
							if (evdp->lpdt.v) s2cd_sw_switch_e(S2CD_LANG_STATE_CHANGE, evdp->lpdt.bfile, S2CD_LANG_RELOAD);
						}   /* if (!evdp->lpdt.B) */
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

		close(evdp->lpdt.kq);

		}   /* while (!pf_reset_check) */

		if (fr) s2cd_parse_and_block_list_clear(&evdp->lpdt.pbhead.bhead);
		if (evdp->lpdt.v) s2cd_sw_switch_e(S2CD_LANG_STATE_CHANGE, S2CD_LANG_PF, S2CD_LANG_RELOAD);

	}   /* while (1) */

	close(evdp->lpdt.fd);
	free(evdp);

	pthread_exit(NULL);

}   /* s2cd_kevent_file_monitor */

int s2cd_fd_open(char *file) {
	int fd = 0;

	if ((fd = open(file, O_RDONLY)) == -1) return(-1);
	if (lseek(fd, 0, SEEK_END) == -1) return(-1);

	return(fd);

}   /* s2cd_fd_open */

void s2cd_kevent_open(struct kevent *change, int *kq, int *fd, char *file) {

	if ((*kq = kqueue()) == -1) s2cd_sw_switch_f(S2CD_LANG_KQ_ERROR, S2CD_LANG_EXIT);
	if ((*fd = s2cd_fd_open(file)) == -1) s2cd_sw_switch_ef(S2CD_LANG_NO_OPEN, file, S2CD_LANG_EXIT);

	memset((struct kevent *)change, 0x00, sizeof(struct kevent));
	EV_SET(change, *fd, EVFILT_VNODE, EV_ADD | EV_ENABLE, NOTE_EXTEND | NOTE_WRITE, 0, NULL);

	if (kevent(*kq, change, 1, NULL, 0, NULL) == -1) s2cd_sw_switch_f(S2CD_LANG_KE_REQ_ERROR, S2CD_LANG_EXIT);

	return;

}   /* s2cd_kevent_open */

void s2cd_kevent_plf_reload(struct pftbl_t *pftbl, struct lpdt_t *lpdt, struct lnpc_t *lnpc) {

	s2cd_parse_and_block_list_clear(&lpdt->pbhead.phead);
	s2cd_parse_load_pl(pftbl, lpdt, lpdt->pfile, lnpc, &lpdt->pbhead.phead);
	if (lpdt->v) s2cd_parse_print_list(&lpdt->pbhead.phead);

	return;

}   /* s2cd_kevent_plf_reload */

void s2cd_kevent_loop(struct lpdt_t *lpdt) {

	unsigned int pf_reset_check = 0, pf_tbl_state_init = 0, pf_tbl_state_current = 0;
	struct pftbl_t pftbl;

	pf_tbl_state_init = pf_tbl_state_current = s2cd_pf_tbl_get(lpdt->dev, lpdt->v, lpdt->tablename, &pftbl);

	while (1) {
		pf_tbl_state_current = s2cd_pf_tbl_get(lpdt->dev, lpdt->v, lpdt->tablename, &pftbl);

		/* I always have problems with && and || operators */
		pthread_mutex_lock(&fm_mutex);
		if (pfile_monitor) pf_reset_check = 1;
		if (bfile_monitor) pf_reset_check = 1;
		pthread_mutex_unlock(&fm_mutex);

		if (pf_tbl_state_current < pf_tbl_state_init)
			pf_reset_check = 1;
		pf_tbl_state_init = pf_tbl_state_current;

		if (pf_reset_check) {
			pf_reset_check = 0;
			pthread_mutex_lock(&pf_mutex);
			pf_reset = 1;
			pthread_mutex_unlock(&pf_mutex);
			s2cd_write_file(lpdt->alertfile, " ");
		} else {
			if (!lpdt->C) sleep(S2CD_PF_POLLING_FREQ);
			if (lpdt->v) if (F) fprintf(stderr, "%s\n", S2CD_LANG_KE_WAIT);
		}   /* else */
	}   /* while (1) */

	return;

}   /* s2cd_kevent_loop */

int s2cd_kevent_read(struct lpdt_t *lpdt, struct lnpc_t *lnpc, struct pftbl_t *pftbl, int nbytes) {

	register int i = 0;
	int r = 0, total = 0;

	do  {
		for (i = 0; i < BUFSIZ; i++) {
			if ((r = read(lpdt->fd, &lnpc->cad[i], sizeof(char))) <= 0) return(r);
			if (lnpc->cad[i] == '\n') {
				lnpc->cad[i] = '\0';
				break;
			}   /* if (lnpc */
		}   /* for (i */

		if (lpdt->v) s2cd_sw_switch(S2CD_LANG_KE_READ, lnpc->cad);
		s2cd_parse_and_block(lpdt, lnpc, pftbl);
		total += i;

	} while (i > 0 && total < nbytes);

	return(total);

}   /* s2cd_kevent_read */
