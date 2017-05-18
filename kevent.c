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
*s2c_kevent_file_monitor(void *arg){
	thread_fm_t *data = (thread_fm_t *)arg;
	struct kevent change, trigger;
	int fd = 0, kq = 0, *fm = NULL;
	char *local_file = NULL;

	if ((local_file = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	strlcpy(local_file, data->file, NMBUFSIZ);
	fm = data->file_monitor;
	free(data);

	kq = s2c_kqueue_open();
	fd = s2c_kevent_open(local_file);
	memset(&change, 0x00, sizeof(struct kevent));
	EV_SET(&change, fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXTEND | NOTE_WRITE, 0, 0);

	if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	while (1) {
		
		memset(&trigger, 0x00, sizeof(struct kevent));
		if (kevent(kq, NULL, 0, &trigger, 1, NULL) == -1) {
			syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
			s2c_exit_fail();

		} else if (trigger.fflags & NOTE_EXTEND || trigger.fflags & NOTE_WRITE) {
			pthread_mutex_lock(&fm_mutex);
			*fm = 1;
			pthread_mutex_unlock(&fm_mutex);
		}
	}

	close(fd);
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

int
s2c_pf_open(char *nmpfdev)
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
s2c_kevent_open(char *file)
{
	int fd = 0;

	if ((fd = s2c_fd_open(file)) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s alertfile - %s", LANG_NO_OPEN, LANG_EXIT);
		s2c_exit_fail();
	}
	free(file);
	return(fd);
}

int s2c_kqueue_open()
{
	int kq = 0;

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KQ_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	return(kq);
}

void
s2c_kevent_loop(loopdata_t *loopdata)
{
	struct kevent trigger, change;
	int kq = 0, pf_reset_check = 0;
	unsigned long age = EXPTIME;
	unsigned long last_time = 0, this_time = 0;
	lineproc_t *lineproc = NULL;
	wbhead_t *wbhead = NULL;
	
	if ((wbhead = (wbhead_t *)malloc(sizeof(wbhead_t))) == NULL) s2c_malloc_err();
	if ((lineproc = (lineproc_t *)malloc(sizeof(lineproc_t))) == NULL) s2c_malloc_err();

	while (1) {

		s2c_check_file(loopdata->bfile);
		s2c_check_file(loopdata->wfile);

		memset(wbhead, 0x00, sizeof(wbhead_t));
		memset(lineproc, 0x00, sizeof(lineproc_t));

		if (!loopdata->W) s2c_parse_load_wl(loopdata->Z, loopdata->extif, loopdata->wfile, lineproc, &wbhead->whead);
		s2c_pf_ruleadd(loopdata->dev, loopdata->tablename);
		if (!loopdata->B) s2c_parse_load_bl_static(loopdata->dev, lineproc, loopdata->tablename, loopdata->bfile, &wbhead->whead);
		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_CON_EST);

		if (loopdata->t > 0) age = loopdata->t;
		this_time = time(NULL);
		last_time = this_time;

		kq = s2c_kqueue_open();
		memset(&change, 0x00, sizeof(struct kevent));
		EV_SET(&change, loopdata->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

		if (kevent(kq, &change, 1, NULL, 0, NULL) == -1) {
			syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_ERROR, LANG_EXIT);
			s2c_exit_fail();
		}

		while (!pf_reset_check) {

			memset(&trigger, 0x00, sizeof(struct kevent));
			memset(lineproc, 0x00, sizeof(lineproc_t));

			this_time = time(NULL);
		
			if ((last_time + age) < (this_time + 1)) {
				last_time = this_time;
				s2c_parse_and_block_bl_del(age, this_time, &wbhead->bhead);
			}

			if (kevent(kq, NULL, 0, &trigger, 1, NULL) == -1) {
				syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
				s2c_exit_fail();
			}

			if (trigger.filter == EVFILT_READ)
				if (s2c_kevent_read(loopdata, wbhead, lineproc, trigger.data) == -1)
					syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_READ_ERROR, LANG_WARN);

			pthread_mutex_lock(&fm_mutex);

			if(wfile_monitor) {
				wfile_monitor = 0;
				if(!loopdata->W) {
					s2c_check_file(loopdata->wfile);
					s2c_parse_and_block_wl_clear(&wbhead->whead);
					s2c_parse_load_wl(loopdata->Z, loopdata->extif, loopdata->wfile, lineproc, &wbhead->whead);
					if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, loopdata->wfile, LANG_RELOAD);
				}
			}

			if(bfile_monitor) {
				bfile_monitor = 0;
				if(!loopdata->B) {
					s2c_check_file(loopdata->bfile);
					s2c_parse_and_block_bl_static_clear(loopdata->dev, loopdata->tablename);
					s2c_parse_load_bl_static(loopdata->dev, lineproc, loopdata->tablename, loopdata->bfile, &wbhead->whead);
					if (v) syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_STATE_CHANGE, loopdata->bfile, LANG_RELOAD);
				}
			}

			pthread_mutex_unlock(&fm_mutex);

			pthread_mutex_lock(&pf_mutex);
			pf_reset_check = pf_reset;
			pf_reset = 0;
			pthread_mutex_unlock(&pf_mutex);
		}

		s2c_parse_and_block_wl_clear(&wbhead->whead);
		s2c_parse_and_block_bl_clear(&wbhead->bhead);

	}

	free(wbhead); 
	free(lineproc);
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
		memset(lineproc, 0x00, sizeof(lineproc_t));
		total += i;

	} while (i > 0 && total < nbytes);

	return(total);
}
