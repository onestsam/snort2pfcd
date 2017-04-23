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
#ifndef _TOOLS_H
#define _TOOLS_H

void usage();
void sighandle();
void s2c_daemonize();
void s2c_exit_fail();
void s2c_malloc_err();
void s2c_ioctl_wait(char *);
void s2c_spawn_expiretable(int, int);
void s2c_spawn_block_log(char *, char *);
void s2c_spawn_thread(void *(*) (void *), void *);
void s2c_mutexes_init();
void s2c_mutexes_destroy();
void s2c_log_init(char *);
void s2c_db_init(int, int, char *, struct wlist_head *);
void s2c_pf_block_log_check();
void s2c_check_file(char *);
void s2c_write_file(char *, char *);

long lmax(long ,long);
long lmin(long ,long);
int	optnum(char *, char *);

#endif /* _TOOLS_H */


