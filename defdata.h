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

#ifndef _DEFDATA_H_
#define _DEFDATA_H_

#include <libcidr.h>
#include <net/if.h>
#include <net/pfvar.h>

#define THRMAX		100
#define EXPTIME		60*60
#define PFDEVICE "/dev/pf"
#define REG_ADDR "(((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)(/(3[012]|[12]?[0-9]))?)"

/* Paths */
#define PATH_LOG "/var/log/"
#define PATH_RUN "/var/run/"
#define PATH_RESOLV "/etc/resolv.conf"
#define PATH_ALERT "/var/log/snort/alert"
#define PATH_WHITELIST "/usr/local/etc/snort/rules/iplists/default.whitelist"
#define PATH_BLACKLIST "/usr/local/etc/snort/rules/iplists/default.blacklist"

/* Language */
#define LANG_EXIT "exiting"
#define LANG_WARN "warning"
#define LANG_START "started"
#define LANG_USE "usage"
#define LANG_MAN "see man"
#define LANG_ARG "argument for"
#define LANG_NUM "must be a number"
#define LANG_BENT "blacklist entry"
#define LANG_WL "is whitelisted"
#define LANG_DETAILS "for more details"
#define LANG_NO_DAEMON "cannot daemonize"
#define LANG_MALLOC_ERROR "malloc error"
#define LANG_IOCTL_WAIT "error: attempting to establish connection with pf"
#define LANG_IFADDR_ERROR "ifaddr error"
#define LANG_MUTEX_ERROR "unable to init mutex"
#define LANG_NO_OPEN "unable to open"
#define LANG_RECEXIT "exit signal received - exiting"
#define LANG_DAEMON_RUNNING "daemon already running"
#define LANG_NO_PID "cannot open or create pidfile"
#define LANG_INIT_THR "unable to init detached thread attributes"
#define LANG_SET_THR "unable to set detached thread attributes"
#define LANG_LAUNCH_THR "unable to launch detached thread attributes"
#define LANG_NOT_WHITELISTED "not whitelisted, added to block table"
#define LANG_ERR_ROOT "error: must be root to run"
#define LANG_ERR_REGEX "error compiling regex expr"
#define LANG_KQ_ERROR "kqueue init error"
#define LANG_KE_REQ_ERROR "kevent request error"
#define LANG_KE_READ_ERROR "kevent read error"
#define LANG_KE_ERROR "unable to set kevent structure"
#define LANG_FILE_ERROR "file error: file is a directory"


struct ipwlist {
	CIDR *waddr;
	LIST_ENTRY(ipwlist) elem;
};

struct ipblist {
	char baddr[BUFSIZ];
	unsigned long t;
	LIST_ENTRY(ipblist) elem;
};

typedef struct _thread_expt_t {
	int dev;
	unsigned long t;
} thread_expt_t;

typedef struct _thread_log_t {
	char logip[BUFSIZ];
	char logfile[BUFSIZ];
} thread_log_t;

LIST_HEAD(wlist_head, ipwlist);
LIST_HEAD(blist_head, ipblist);

extern char *__progname;
int s2c_threads;
int pf_reset;
char *wfile;
char *bfile;
char *extif;
pthread_mutex_t dns_mutex;
pthread_mutex_t thr_mutex;

#endif /* _DEFDATA_H */

