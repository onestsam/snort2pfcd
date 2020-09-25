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
#define S2CD_REPEATO			0
#define S2CD_THRMAX			100
#define S2CD_NMBUFSIZ			128
#define S2CD_REGARSIZ			3
#define S2CD_BASE_THR			5
#define S2CD_EXPTIME			60*60
#define S2CD_ID_PF			0	/* ID passfile */
#define S2CD_ID_BF			1	/* ID blockfile */
#define S2CD_ID_AF			2	/* ID alertfile */
#define S2CD_MONITOR_ONLY		0
#define S2CD_MONITOR_READ		1
#define S2CD_PF_POLLING_FREQ		4	/* seconds */

/* Snort Priorities */
#define S2CD_SP_HIGH			4
#define S2CD_SP_MEDIUM			3
#define S2CD_SP_LOW			2
#define S2CD_SP_VERYLOW			1

/* Paths & Regex */
#define S2CD_PFDEVICE			"/dev/pf"
#define S2CD_PATH_LOG			"/var/log/"
#define S2CD_PATH_RUN			"/var/run/"
#define S2CD_PATH_RESOLV		"/etc/resolv.conf"
#define S2CD_PATH_ALERT			"/var/log/snort/alert"
#define S2CD_PATH_PASSLIST		"/usr/local/etc/snort/rules/iplists/default.passlist"
#define S2CD_PATH_BLOCKLIST		"/usr/local/etc/snort/rules/iplists/default.blocklist"
#define S2CD_MALLOC_ERR			s2cd_sw_switch_f(S2CD_LANG_MALLOC_ERROR, S2CD_LANG_EXIT)
#define S2CD_OPTIONS			"[-h] [-v] [-e extif] [-w pfile] [-W] [-b bfile] [-B] [-C] [-D] [-F] [-Z] [-a alertfile] [-d pf_device] [-l logfile] [-p priority] [-t expiretime] [-q wait_time] [-m thr_max] [-r repeat_offenses]"
#define S2CD_REG_ADDR 			"^(([0-9])|([1-9][0-9])|(1([0-9]{2}))|(2[0-4][0-9])|(25[0-5]))((\\.(([0-9])|([1-9][0-9])|(1([0-9]{2}))|(2[0-4][0-9])|(25[0-5]))){3})(\\/(([0-9])|([12][0-9])|(3[0-2])))?"
					/* Regexp modified from https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp */

/* Language */
#define S2CD_LANG_EXIT			"exiting"
#define S2CD_LANG_WARN			"warning"
#define S2CD_LANG_RELOAD		"reloading"
#define S2CD_LANG_START			"started"
#define S2CD_LANG_MON			"monitoring"
#define S2CD_LANG_USE			"usage"
#define S2CD_LANG_FOUND			"found"
#define S2CD_LANG_MAN			"see man"
#define S2CD_LANG_PF			"packet filter"
#define S2CD_LANG_BLK			"blocked"
#define S2CD_LANG_PRIB			"priority blocked at or above"
#define S2CD_LANG_THRS			"max dns request threads"
#define S2CD_LANG_PRIO			"found priority"
#define S2CD_LANG_BENT			"blocklist entry"
#define S2CD_LANG_PLL			"Passlist:"
#define S2CD_LANG_PL			"is passlisted"
#define S2CD_LANG_SPBL			"error: cannot spawn block log thread"
#define S2CD_LANG_THR_WAIT		"waiting for exiting threads"
#define S2CD_LANG_ERR_ID		"Internal Error: ID undefined"
#define S2CD_LANG_DETAILS		"for more details"
#define S2CD_LANG_NO_REG		"no regex match found"
#define S2CD_LANG_NO_DAEMON		"cannot daemonize"
#define S2CD_LANG_MALLOC_ERROR		"malloc error"
#define S2CD_LANG_STATE_CHANGE		"state change detected in"
#define S2CD_LANG_INTDB			"!! internal database error !!"
#define S2CD_LANG_CON_EST		"connection with pf established"
#define S2CD_LANG_TBLADD		"table added"
#define S2CD_LANG_IOCTL_WAIT		"attempting to re-establish connection with pf"
#define S2CD_LANG_IOCTL_ERROR		"unable to connect to pf"
#define S2CD_LANG_IFADDR_ERROR		"ifaddr error"
#define S2CD_LANG_MUTEX_ERROR		"unable to init mutex"
#define S2CD_LANG_NO_OPEN		"unable to open"
#define S2CD_LANG_RECEXIT		"exit signal received"
#define S2CD_LANG_DAEMON_RUNNING	"daemon already running"
#define S2CD_LANG_NO_PID		"cannot open or create pidfile"
#define S2CD_LANG_INIT_THR		"unable to init detached thread attributes"
#define S2CD_LANG_SET_THR		"unable to set detached thread attributes"
#define S2CD_LANG_LAUNCH_THR		"unable to launch detached thread attributes"
#define S2CD_LANG_PTRHR_ERROR		"failed to spawn thread"
#define S2CD_LANG_NOT_PASSLISTED	"not passlisted, added to block table"
#define S2CD_LANG_UNBLOCKED		"block-time expired, removed from block table"
#define S2CD_LANG_ERR_ROOT		"error: must be root to run"
#define S2CD_LANG_ERR_REGEX		"error compiling regex expr"
#define S2CD_LANG_KQ_ERROR		"kqueue init error"
#define S2CD_LANG_KE_READ		"kevent read"
#define S2CD_LANG_KE_REQ_ERROR		"kevent request error"
#define S2CD_LANG_KE_READ_ERROR		"kevent read error"
#define S2CD_LANG_KE_ERROR		"unable to set kevent structure"
#define S2CD_LANG_KE_WAIT		"waiting for kevent"
#define S2CD_LANG_FILE_ERROR		"file error: file is a directory"
#define S2CD_LANG_LOGTHR_ERROR		"!! internal log thread error !!"
#define S2CD_LANG_DNS_DISABLED		"DNS lookup disabled"

/* Macros */
LIST_HEAD(ulist_head, ipulist);

/* Global Structs */
struct ipulist {
        time_t t;
        int repeat_offenses;
	CIDR ciaddr;
        char chaddr[BUFSIZ];
        LIST_ENTRY(ipulist) elem;
};

struct pftbl_t {
	struct pfioc_pooladdr io_paddr;
	struct pfioc_rule io_rule;
	struct pfioc_table io;
	struct pfr_table table;
	struct pfr_addr addr;
	struct ifreq ifr;
};

struct thread_expt_t {
	int v;
	int C;
	int dev;
	time_t t;
	char logfile[S2CD_NMBUFSIZ];
	char nmpfdev[S2CD_NMBUFSIZ];
	char tablename[PF_TABLE_NAME_SIZE];
};

struct thread_log_t {
	int C;
	int D;
	char logip[BUFSIZ];
	char logfile[S2CD_NMBUFSIZ];
};

struct pbhead_t {
	struct ulist_head phead;
	struct ulist_head bhead;
};

struct lnpc_t {
	regex_t expr;
	char cad[BUFSIZ];
	char ret[BUFSIZ];
};

struct pfbl_log_t {
	char message[BUFSIZ];
	char local_logip[BUFSIZ];
	char local_logfile[S2CD_NMBUFSIZ];
	char hbuf[NI_MAXHOST];
	struct sockaddr sa;
};

struct lpdt_t {
	int v;
	int B;
	int C;
	int D;
	int W;
	int Z;
	int fd;
	int kq;
	int dev;
	time_t t;
	int thr_max;
	int priority;
	time_t timebuf;
	int repeat_offenses;
	struct pbhead_t pbhead;
	char pfile[S2CD_NMBUFSIZ];
	char bfile[S2CD_NMBUFSIZ];
	char extif[IFNAMSIZ];
	char logfile[S2CD_NMBUFSIZ];
	char nmpfdev[S2CD_NMBUFSIZ];
	char alertfile[S2CD_NMBUFSIZ];
	char tablename[PF_TABLE_NAME_SIZE];
	char tablename_static[PF_TABLE_NAME_SIZE];
};

struct thread_fm_t {
	int fid;
        int fileread;
        int *file_monitor;
        struct lpdt_t lpdt;
};

/* Global Vars Decs */
extern char *__progname;
extern struct pidfh *pfh;
extern int F;
extern int pf_reset;
extern int s2cd_threads;
extern int afile_monitor;
extern int pfile_monitor;
extern int bfile_monitor;
extern pthread_mutex_t log_mutex;
extern pthread_mutex_t dns_mutex;
extern pthread_mutex_t thr_mutex;
extern pthread_mutex_t pf_mutex;
extern pthread_mutex_t fm_mutex;

/* Function Defs */
void s2cd_usage();
void s2cd_sighandle();
void s2cd_pre_exit();
void s2cd_exit_fail();
void s2cd_init(struct lpdt_t *);
void s2cd_pre_init(struct lpdt_t *);
void s2cd_daemonize(struct lpdt_t *);
void s2cd_thr_init(struct lpdt_t *);
void s2cd_sw_switch(const char *, const char *);
void s2cd_sw_switch_f(const char *, const char *);
void s2cd_sw_switch_e(const char *, const char *, const char *);
void s2cd_sw_switch_ef(const char *, const char *, const char *);
void s2cd_get_optargs(int, char **, struct lpdt_t *);
int s2cd_spawn_file_monitor(int *, int, int, struct lpdt_t *);
int s2cd_spawn_expiretable(struct lpdt_t *);
int s2cd_spawn_block_log(int, int, char *, char *);
int s2cd_spawn_thread(void *(*) (void *), void *);
int s2cd_fd_open(char *);
void s2cd_mutex_init();
void s2cd_mutex_destroy();
void s2cd_check_file(char *, struct stat *);
void s2cd_write_file(char *, const char *);
time_t s2cd_lmin(time_t, time_t);
void s2cd_pf_block(int, int, char *, char *, struct pftbl_t *);
void s2cd_pf_tbl_set(char *, struct pftbl_t *);
void s2cd_pf_tbl_add(int, int, char *, struct pftbl_t *);
int s2cd_pf_tbl_get(int, int, char *, struct pftbl_t *);
void s2cd_pf_tbl_del(int, int, char *, struct pftbl_t *);
void s2cd_pf_rule_add(int, int, char *, struct pftbl_t *);
void s2cd_pf_unblock_log(int, struct pfbl_log_t *);
void *s2cd_file_monitor(void *);
void *s2cd_pf_block_log(void *);
void *s2cd_pf_expiretable(void *);
int s2cd_pf_ioctl(int, int, unsigned long, void *);
void s2cd_parse_ipu_set(int, char *, struct ipulist *);
void s2cd_parse_add_list(int, struct ipulist *, struct ifaddrs *);
void s2cd_parse_and_block_list_clear(struct ulist_head *);
void s2cd_parse_and_block_list_timeout(time_t, time_t, struct ulist_head *);
void s2cd_parse_and_block(struct lpdt_t *, struct lnpc_t *, struct pftbl_t *);
void s2cd_parse_load_bl_static(int, struct lnpc_t *, char*, char *, struct ulist_head *);
void s2cd_parse_load_file(struct pftbl_t *pftbl, struct lpdt_t *, struct lnpc_t *, const char *, struct ulist_head *, struct ipulist *, int);
void s2cd_parse_load_ifaces(int, struct ipulist *);
void s2cd_parse_load_pl(struct pftbl_t *pftbl, struct lpdt_t *, char *, struct lnpc_t *, struct ulist_head *);
void s2cd_parse_print_list(struct ulist_head *);
int s2cd_parse_search_list(char *, struct ulist_head *);
int s2cd_parse_and_block_bl(int, char *, struct ulist_head *);
int s2cd_parse_priority(int, int, struct lnpc_t *);
int s2cd_parse_line(char *, FILE *);
int s2cd_radix_ioctl(int, int, unsigned long, struct pfioc_table *);
int s2cd_radix_get_astats(int, int, struct pfioc_table *, struct pfr_astats *, const struct pfr_table *, int);
int s2cd_radix_del_addrs(int, int, struct pfioc_table *, const struct pfr_table *, struct pfr_addr *, int, int);
int s2cd_kevent_read(struct lpdt_t *, struct lnpc_t *, struct pftbl_t *, int);
void s2cd_kevent_open(struct kevent *, int *, int *, char *);
void s2cd_kevent_plf_reload(struct pftbl_t *, struct lpdt_t *, struct lnpc_t *);
void s2cd_kevent_loop(struct lpdt_t *);
void *s2cd_kevent_file_monitor(void *arg);

#endif /* _DEFDATA_H */
