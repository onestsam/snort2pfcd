/*
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
*s2c_kevent_file_monitor(void *arg){
	thread_fm_t *data = (thread_fm_t *)arg;
	struct kevent trigger;
	int fid = 0, fr = 0, pf_reset_check = 0, *fm = NULL;
	loopdata_t *loopdata = NULL;
	unsigned long age = EXPTIME, last_time = 0, this_time = 0;
	lineproc_t *lineproc = NULL;
	wbhead_t *wbhead = NULL;

	if ((loopdata = (loopdata_t *)malloc(sizeof(loopdata_t))) == NULL) s2c_malloc_err();
	memcpy(loopdata, &data->loopdata, sizeof(loopdata_t));
	fid = data->fid;
	fr = data->fileread;
	fm = data->file_monitor;
	free(data);

	if (fid == ID_AF) s2c_kevent_open(&loopdata->kq, &loopdata->fd, loopdata->alertfile);
	if (fid == ID_BF) s2c_kevent_open(&loopdata->kq, &loopdata->fd, loopdata->bfile);
	if (fid == ID_WF) s2c_kevent_open(&loopdata->kq, &loopdata->fd, loopdata->wfile);

	if(fr) {
		if (loopdata->t > 0) age = loopdata->t;
		if ((wbhead = (wbhead_t *)malloc(sizeof(wbhead_t))) == NULL) s2c_malloc_err();
		if ((lineproc = (lineproc_t *)malloc(sizeof(lineproc_t))) == NULL) s2c_malloc_err();

		memset((regex_t*)&lineproc->expr, 0x00, sizeof(regex_t));
		if (regcomp(&lineproc->expr, REG_ADDR, REG_EXTENDED) != 0) {
			syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_ERR_REGEX, LANG_EXIT);
			s2c_exit_fail();
		}
	}

	while (1) {
		if (fr) {
			memset(wbhead, 0x00, sizeof(wbhead_t));
			memset(lineproc, 0x00, sizeof(lineproc_t));

			s2c_pf_ruleadd(loopdata->dev, loopdata->tablename);
			if (v) syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_CON_EST);

			this_time = last_time = time(NULL);
			pf_reset_check = 0;
		}

		while (!pf_reset_check) {

			if (fr) {
				this_time = time(NULL);

				if ((last_time + age) < (this_time + 1)) {
					last_time = this_time;
					s2c_parse_and_block_bl_del(age, this_time, &wbhead->bhead);
				}
			}

			memset(&trigger, 0x00, sizeof(struct kevent));
			if (kevent(loopdata->kq, NULL, 0, &trigger, 1, NULL) == -1) {
				syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
				s2c_exit_fail();

			} else {
				if(fr) {
					if (s2c_kevent_read(loopdata, wbhead, lineproc, trigger.data) == -1)
						syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_READ_ERROR, LANG_WARN);

					pthread_mutex_lock(&fm_mutex);

					if(wfile_monitor) {
						wfile_monitor = 0;
						if(!loopdata->W) {
							s2c_kevent_wlf_load(loopdata, lineproc, wbhead);
							if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, loopdata->wfile, LANG_RELOAD);
						}
					}

					if(bfile_monitor) {
						bfile_monitor = 0;
						if(!loopdata->B) {
							s2c_kevent_blf_load(loopdata, lineproc, wbhead);
							if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, loopdata->bfile, LANG_RELOAD);
						}
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
		}

		if (fr) {
			close(loopdata->dev);
			if ((loopdata->dev = open(loopdata->nmpfdev, O_RDWR)) == -1) {
				syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, loopdata->nmpfdev, LANG_EXIT);
				s2c_exit_fail();
			}

			s2c_kevent_wlf_load(loopdata, lineproc, wbhead);
			s2c_kevent_blf_load(loopdata, lineproc, wbhead);
			s2c_parse_and_block_bl_clear(&wbhead->bhead);
		}
		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, LANG_PF, LANG_RELOAD);
	}

	if (fr) {
		free(wbhead);
		free(lineproc);
	}

	close(loopdata->kq);
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
		syslog(LOG_ERR | LOG_DAEMON, "%s alertfile - %s", LANG_NO_OPEN, LANG_EXIT);
		s2c_exit_fail();
	}

	memset(&change, 0x00, sizeof(struct kevent));
	EV_SET(&change, *fd, EVFILT_VNODE | EVFILT_READ, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXTEND | NOTE_WRITE, 0, 0);

	if (kevent(*kq, &change, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	return;
}

void
s2c_kevent_wlf_load(loopdata_t *loopdata, lineproc_t *lineproc, wbhead_t *wbhead)
{
	s2c_check_file(loopdata->wfile);
	s2c_parse_and_block_wl_clear(&wbhead->whead);
	s2c_parse_load_wl(loopdata->Z, loopdata->extif, loopdata->wfile, lineproc, &wbhead->whead);
	return;
}

void
s2c_kevent_blf_load(loopdata_t *loopdata, lineproc_t *lineproc, wbhead_t *wbhead)
{
	s2c_check_file(loopdata->bfile);
	s2c_parse_and_block_bl_static_clear(loopdata->dev, loopdata->tablename);
	s2c_parse_load_bl_static(loopdata->dev, lineproc, loopdata->tablename, loopdata->bfile, &wbhead->whead);
	return;
}

void
s2c_kevent_loop(loopdata_t *loopdata)
{
	int pf_reset_check = 0;
	pftbl_t *pftbl = NULL;

	if ((pftbl = (pftbl_t *)malloc(sizeof(pftbl_t))) == NULL) s2c_malloc_err();

	while (1) {

		s2c_pf_tbl_ping(loopdata->dev, loopdata->tablename, pftbl);

		pthread_mutex_lock(&pf_mutex);
		pf_reset_check = pf_reset;
		pf_reset = 0;
		pthread_mutex_unlock(&pf_mutex);

		if (pf_reset_check) {
			close(loopdata->dev);
			if ((loopdata->dev = open(loopdata->nmpfdev, O_RDWR)) == -1) {
				syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, loopdata->nmpfdev, LANG_EXIT);
				s2c_exit_fail();
			}

		}

	sleep(5);
	}

	free(pftbl);
	return;
}

int
s2c_kevent_read(loopdata_t *loopdata, wbhead_t *wbhead, lineproc_t *lineproc, int nbytes)
{
	int i = 0, r = 0, total = 0;

	do  {
		for (i = 0; i < BUFSIZ; i++) {
			if((r = read(loopdata->fd, &lineproc->cad[i], sizeof(char))) <= 0) return(r);
			if (lineproc->cad[i] == '\n') break;
		}
		s2c_parse_and_block(loopdata, lineproc, wbhead);
		syslog(LOG_ERR | LOG_DAEMON, "%s", lineproc->lastret);
		memset(lineproc, 0x00, sizeof(lineproc_t));
		total += i;

	} while (i > 0 && total < nbytes);

	return(total);
}
