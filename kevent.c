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
#include <sys/event.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include "defdata.h"
#include "tools.h"
#include "spfc.h"
#include "parser.h"
#include "kevent.h"


int
s2c_kevent_open(char *file)
{
	int fd = 0;

	s2c_check_file(file);
	if ((fd = open(file, O_RDONLY)) == -1) return(-1);
	if (lseek(fd, 0, SEEK_END) == -1) return(-1);
	free(file);

	return(fd);
}

void
s2c_kevent_loop(unsigned long t, int fd, int dev, int priority, int repeat_offenses, char *logfile, char *tablename, struct wlist_head *whead, struct blist_head *bhead)
{
	struct kevent ke, kev;
	int kq = 0;
	unsigned long age = EXPTIME;
	unsigned long last_time = 0, this_time = 0;
	lineproc_t *lineproc = NULL;
	

	if ((lineproc = (lineproc_t *)malloc(sizeof(lineproc_t))) == NULL) s2c_malloc_err();
	if (t > 0) age = t;
	this_time = time(NULL);
	last_time = this_time;

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KQ_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	memset(&kev, 0x00, sizeof(struct kevent));
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}


	while (pf_reset != -1) {

		memset(&ke, 0x00, sizeof(struct kevent));
		memset(lineproc, 0x00, sizeof(lineproc_t));
		
		pf_reset = 0;
		this_time = time(NULL);
		
		if ((last_time + age) < (this_time + 1)) {
			last_time = this_time;
			s2c_parse_and_block_bl_del(age, this_time, bhead);
		}

		if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1) {
			syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_REQ_ERROR, LANG_EXIT);
			s2c_exit_fail();
		}

		if (ke.filter == EVFILT_READ)
			if (s2c_kevent_read_f(fd, dev, priority, repeat_offenses, logfile, tablename, whead, bhead, lineproc, ke.data) == -1)
				syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_KE_READ_ERROR, LANG_WARN);
	}

	free(lineproc);
}

int
s2c_kevent_read_l(int fd, char *buf)
{
	int i = 0, b_r = 0;

	for (i = 0; i < BUFSIZ; i++) {

		b_r = read(fd, &buf[i], sizeof(char));
		if (b_r == -1 || b_r == 0) return(b_r);
		if (buf[i] == '\n') break;
	}
	
	return(i);
}

int
s2c_kevent_read_f(int fd, int dev, int priority, int repeat_offenses, char *logfile, char *tablename, struct wlist_head *whead, struct blist_head *bhead, lineproc_t *lineproc, int nbytes)
{
	int i = 0, total = 0;

	do  {
		if ((i = s2c_kevent_read_l(fd, lineproc->cad)) == -1) return(-1);
		s2c_parse_and_block(dev, priority, repeat_offenses, logfile, tablename, lineproc, whead, bhead);
		memset(lineproc, 0x00, sizeof(lineproc_t));
		total += i;

	} while (i > 0 && total < nbytes);

	return(total);
}
