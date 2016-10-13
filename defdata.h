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

#ifndef _DEFDATA_H_
#define _DEFDATA_H_

#include <libcidr.h>
#include <net/if.h>
#include <net/pfvar.h>

#define PFDEVICE "/dev/pf"
#define LISTMAX   1024
#define REG_ADDR "(((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)(/(3[012]|[12]?[0-9]))?)"

struct ipwlist {
	CIDR *waddr;
	LIST_ENTRY(ipwlist) elem;
};

struct ipblist {
	char baddr[LISTMAX];
	LIST_ENTRY(ipblist) elem;
};

typedef struct thread_expt_t {
	int dev;
	int t;
	char tablename[PF_TABLE_NAME_SIZE];
} thread_expt_t;

typedef struct thread_log_t {
	char logip[LISTMAX];
	char logfile[LISTMAX];
} thread_log_t;


LIST_HEAD(wlist_head, ipwlist);
LIST_HEAD(blist_head, ipblist);

extern char *__progname;

#endif /* _DEFDATA_H */

