/*
 * snort2pfcd
 * Copyright (c) 2016 Samee Shahzada <onestsam@gmail.com>
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
#include "spfc.h"
#include "parser.h"
#include "kevent.h"

int
s2c_kevent_set(int fd, int kq)
{
	struct kevent kev;
	memset(&kev, 0x00, sizeof(struct kevent));
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		return(-1);

	return(0);
}

int
s2c_kevent_open(char *file)
{
	int fd = open(file, O_RDONLY);
	if (fd == -1)
		return(-1);
	if (lseek(fd, 0, SEEK_END) == -1)
		return(-1);
	return(fd);
}


void
s2c_kevent_loop(int fd, int dev, int priority, int kq, char *logfile, char *tablename, struct wlist_head *whead)
{
	struct kevent ke;
	struct blist_head bhead;
	char buf[BUFSIZ];

	memset(&bhead, 0x00, sizeof(struct blist_head));

	while (1) {
		memset(&ke, 0x00, sizeof(struct kevent));
		bzero(buf, BUFSIZ);

		if (kevent(kq, NULL, 0, &ke, 1, NULL) == -1) {
			syslog(LOG_ERR | LOG_DAEMON, "kevent request error - exit");
			exit(EXIT_FAILURE);
		}
		if (ke.filter == EVFILT_READ)
			if (s2c_kevent_read_f(fd, dev, priority, logfile, whead, &bhead, buf, tablename, BUFSIZ, ke.data) == -1)
				syslog(LOG_ERR | LOG_DAEMON, "warning, kevent read error.");
	}
}

int
s2c_kevent_read_l(int fd, char *buf, size_t len)
{
	int i, b_r = 0;

	for (i = 0; i < len; i++) {
		b_r = read(fd, &buf[i], sizeof(char));
		if (b_r == -1 || b_r == 0) 
			return(b_r);
		if (buf[i] == '\n')
			break;
	}

	return(i);
}

int
s2c_kevent_read_f(int fd, int dev, int priority, char *logfile, struct wlist_head *whead, struct blist_head *bhead, char *buf, char *tablename, size_t len, int nbytes)
{
	int i, total = 0;

	do  {
		i = s2c_kevent_read_l(fd, buf, len);
		if (i == -1)
			return(-1);

		s2c_parse_and_block(dev, priority, logfile, buf, tablename, whead, bhead);
		total += i;

		memset(buf, 0x00, len);

	} while (i > 0 && total < nbytes);

	return(total);

}
