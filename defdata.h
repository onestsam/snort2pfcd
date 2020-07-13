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

#ifndef _DEFDATA_H_
#define _DEFDATA_H_

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/event.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <libcidr.h>
#include <regex.h>
#include <libutil.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <ifaddrs.h>

/* Params */

#define REPEATO			0
#define THRMAX			100
#define NMBUFSIZ		128
#define REGARSIZ		3
#define EXPTIME			60*60
#define ID_WF			0
#define ID_BF			1
#define ID_AF			2

/* snort priorities */
#define S2C_SP_HIGH		4
#define S2C_SP_MEDIUM		3
#define S2C_SP_LOW		2
#define S2C_SP_VERYLOW		1

/* Paths & regex */
#define PFDEVICE		"/dev/pf"
#define PATH_LOG		"/var/log/"
#define PATH_RUN		"/var/run/"
#define PATH_RESOLV		"/etc/resolv.conf"
#define PATH_ALERT		"/var/log/snort/alert"
#define PATH_PASSLIST		"/usr/local/etc/snort/rules/iplists/default.passlist"
#define PATH_BLOCKLIST		"/usr/local/etc/snort/rules/iplists/default.blacklist"
#define REG_ADDR 		"^(([0-9])|([1-9][0-9])|(1([0-9]{2}))|(2[0-4][0-9])|(25[0-5]))((\\.(([0-9])|([1-9][0-9])|(1([0-9]{2}))|(2[0-4][0-9])|(25[0-5]))){3})(\\/(([0-9])|([12][0-9])|(3[0-2])))?"
/* Regexp modified from https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp */

/* Language */
#define LANG_EXIT		"exiting"
#define LANG_WARN		"warning"
#define LANG_RELOAD		"reloading"
#define LANG_START		"started"
#define LANG_MON		"monitoring"
#define LANG_USE		"usage"
#define LANG_FOUND		"found"
#define LANG_MAN		"see man"
#define LANG_PF			"packet filter"
#define LANG_BLK		"blocked"
#define LANG_PRIB		"priority blocked at or above"
#define LANG_THRS		"max dns request threads"
#define LANG_PRIO		"found priority"
#define LANG_BENT		"blocklist entry"
#define LANG_WLL		"Passlist:"
#define LANG_WL			"is passlisted"
#define LANG_DETAILS		"for more details"
#define LANG_NO_REG		"no regex match found"
#define LANG_NO_DAEMON		"cannot daemonize"
#define LANG_MALLOC_ERROR	"malloc error"
#define LANG_STATE_CHANGE	"state change detected in"
#define LANG_INTDB		"!! internal database error !!"
#define LANG_CON_EST		"connection with pf established"
#define LANG_TBLADD		"table added"
#define LANG_IOCTL_WAIT		"attempting to re-establish connection with pf"
#define LANG_IOCTL_ERROR	"unable to connect to pf"
#define LANG_IFADDR_ERROR	"ifaddr error"
#define LANG_MUTEX_ERROR	"unable to init mutex"
#define LANG_NO_OPEN		"unable to open"
#define LANG_RECEXIT		"exit signal received - exiting"
#define LANG_DAEMON_RUNNING	"daemon already running"
#define LANG_NO_PID		"cannot open or create pidfile"
#define LANG_INIT_THR		"unable to init detached thread attributes"
#define LANG_SET_THR		"unable to set detached thread attributes"
#define LANG_LAUNCH_THR		"unable to launch detached thread attributes"
#define LANG_NOT_WHITELISTED	"not passlisted, added to block table"
#define LANG_UNBLOCKED		"block-time expired, removed from block table"
#define LANG_ERR_ROOT		"error: must be root to run"
#define LANG_ERR_REGEX		"error compiling regex expr"
#define LANG_KQ_ERROR		"kqueue init error"
#define LANG_KE_READ		"kevent read"
#define LANG_KE_REQ_ERROR	"kevent request error"
#define LANG_KE_READ_ERROR	"kevent read error"
#define LANG_KE_ERROR		"unable to set kevent structure"
#define LANG_FILE_ERROR		"file error: file is a directory"
#define LANG_LOGTHR_ERROR	"!! internal log thread error !!"
#define LANG_DNS_DISABLED	"DNS lookup disabled"

/* Macros */
LIST_HEAD(ulist_head, ipulist);

/* Global structs */

struct ipulist {
        unsigned long t;
        int repeat_offenses;
	CIDR ciaddr;
        char chaddr[BUFSIZ];
        LIST_ENTRY(ipulist) elem;
};

typedef struct _pftbl_t {
	struct pfioc_table io;
	struct pfr_table table;
} pftbl_t;

typedef struct _thread_expt_t {
	int dev;
	unsigned long t;
	char logfile[NMBUFSIZ];
	char nmpfdev[NMBUFSIZ];
	char tablename[PF_TABLE_NAME_SIZE];
} thread_expt_t;

typedef struct _thread_log_t {
	int D;
	char logip[BUFSIZ];
	char logfile[NMBUFSIZ];
} thread_log_t;

typedef struct _wbhead_t {
	struct ulist_head whead;
	struct ulist_head bhead;
} wbhead_t;

typedef struct _lineproc_t {
	regex_t expr;
	char cad[BUFSIZ];
	char ret[BUFSIZ];
} lineproc_t;

typedef struct _pfbl_log_t {
	char message[BUFSIZ];
	char local_logip[BUFSIZ];
	char local_logfile[NMBUFSIZ];
	char hbuf[NI_MAXHOST];
	struct sockaddr sa;
} pfbl_log_t;

typedef struct _loopdata_t {
	int B;
	int W;
	int D;
	int Z;
	int fd;
	int kq;
	int dev;
	int thr_max;
	int priority;
	long timebuf;
	unsigned long t;
	wbhead_t wbhead;
	int repeat_offenses;
	char wfile[NMBUFSIZ];
	char bfile[NMBUFSIZ];
	char extif[IFNAMSIZ];
	char logfile[NMBUFSIZ];
	char nmpfdev[NMBUFSIZ];
	char alertfile[NMBUFSIZ];
	char randombuf[BUFSIZ];
	char tablename[PF_TABLE_NAME_SIZE];
	char tablename_static[PF_TABLE_NAME_SIZE];
} loopdata_t;

typedef struct _thread_fm_t {
	int fid;
        int fileread;
        int *file_monitor;
        loopdata_t loopdata;
} thread_fm_t;

/* Global vars */
extern char *__progname;
struct pidfh *pfh;
int v;
int C;
int s2c_threads;
int pf_reset;
int afile_monitor;
int wfile_monitor;
int bfile_monitor;
pthread_mutex_t log_mutex;
pthread_mutex_t dns_mutex;
pthread_mutex_t thr_mutex;
pthread_mutex_t pf_mutex;
pthread_mutex_t fm_mutex;

/* Function defs */
void usage();
void sighandle();
void s2c_pre_exit();
void s2c_exit_fail();
void s2c_malloc_err();
void s2c_init(loopdata_t *);
void s2c_pre_init(loopdata_t *);
void s2c_daemonize(loopdata_t *);
void s2c_thr_init(loopdata_t *);
void s2c_get_optargs(int, char **, loopdata_t *);
void s2c_pf_ioctl(int, unsigned long, void *);
void s2c_spawn_file_monitor(int *, int, int, loopdata_t *);
void s2c_spawn_expiretable(loopdata_t *);
void s2c_spawn_block_log(int, char *, char *);
void s2c_spawn_thread(void *(*) (void *), void *);
void s2c_mutex_init();
void s2c_mutex_destroy();
void s2c_log_init(loopdata_t *);
void s2c_check_file(char *);
void s2c_write_file(char *, char *);
void s2c_pftbl_set(char *, pftbl_t *);
long lmin(long ,long);

void s2c_pf_block(int, char *, char *);
void s2c_pf_tbladd(int, char *);
void s2c_pf_tbldel(int, char *);
void s2c_pf_ruleadd(int, char *);
void s2c_pf_unblock_log(pfbl_log_t *);
void *s2c_file_monitor(void *);
void *s2c_pf_block_log(void *);
void *s2c_pf_expiretable(void *);
int s2c_pf_tbl_get(int, char *, pftbl_t *);

void s2c_parse_ipu_set(char *, struct ipulist *);
int s2c_parse_priority(int, lineproc_t *);
int s2c_parse_line(char *, FILE *);
void s2c_parse_add_list(struct ipulist *, struct ifaddrs *);
void s2c_parse_and_block_list_clear(struct ulist_head *);
void s2c_parse_and_block_list_timeout(unsigned long, unsigned long, struct ulist_head *);
void s2c_parse_and_block(loopdata_t *, lineproc_t *);
void s2c_parse_load_bl_static(int, lineproc_t *, char*, char *, struct ulist_head *);
int s2c_parse_and_block_bl(char *, struct ulist_head *);
void s2c_parse_load_file(loopdata_t *, lineproc_t *, char *, struct ulist_head *, struct ipulist *, int);
void s2c_parse_load_ifaces(struct ipulist *);
void s2c_parse_load_wl(loopdata_t *, char *, lineproc_t *, struct ulist_head *);
void s2c_parse_print_list(struct ulist_head *);
int s2c_parse_search_list(char *, struct ulist_head *);

int s2c_fd_open(char *);
int s2c_kevent_read(loopdata_t *, lineproc_t *, int);
void s2c_kevent_open(int *, int *, char *);
void s2c_kevent_wlf_reload(loopdata_t *, lineproc_t *);
void s2c_kevent_loop(loopdata_t *);
void *s2c_kevent_file_monitor(void *arg);

#endif /* _DEFDATA_H */

