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

int s2cd_parse_and_block_bl(int C, char *ret, struct ulist_head *head) {

	register struct ipulist *ipu1 = NULL, *ipu = NULL;

	if (head->lh_first == NULL){
		S2CD_IPU_INIT;
		LIST_INIT(head);
		LIST_INSERT_HEAD(head, ipu, elem);
		return(0);

	} else {
		for (ipu1 = head->lh_first; ipu1 != NULL; ipu1 = ipu1->elem.le_next) {
			if (!strcmp(ipu1->chaddr, ret)) {
				ipu1->repeat_offenses++;
				return(ipu1->repeat_offenses);
			} else if (!ipu1->elem.le_next) {
				S2CD_IPU_INIT;
				LIST_INSERT_AFTER(ipu1, ipu, elem);
				return(0);
			}   /* else if (!ipu1 */
		}   /* for (ipu1 */
	}   /* else if (head */

	return(-1);

}   /* s2cd_parse_and_block_bl */

void s2cd_parse_and_block_list_clear(struct ulist_head *head) {

	register struct ipulist *ipu1 = NULL, *ipu = NULL;

 	ipu1 = LIST_FIRST(head);

	while (ipu1 != NULL) {
		ipu = LIST_NEXT(ipu1, elem);
		free(ipu1);
		ipu1 = ipu;
	}   /* while (ipu1 */

	return;

}   /* s2cd_parse_and_block_list_clear */

void s2cd_parse_and_block_list_timeout(time_t age, time_t this_time, struct ulist_head *head) {

	register struct ipulist *ipu = NULL;

	for (ipu = head->lh_first; ipu != NULL; ipu = ipu->elem.le_next)
		if ((ipu->t + age) < this_time) {
			LIST_REMOVE(ipu, elem);
			free(ipu);
		}   /* if ((ipu->t */

	return;

}   /* s2cd_parse_and_block_list_timeout */

int s2cd_parse_line(char *buf, FILE* pfile) {

	static char next_ch = ' ';
	int i = 0;

	if (feof(pfile)) return (0);                                

	do {
		next_ch = fgetc(pfile);
		if (i < BUFSIZ) buf[i++] = next_ch;
	} while (!feof(pfile) && !isspace(next_ch));

	if (i >= BUFSIZ) return (-1);
	buf[i] = '\0';

	return(1);

}   /* s2cd_parse_line */

int s2cd_parse_priority(int priority, int v, struct lnpc_t *lnpc) {

	register char *p = NULL;

	if ((p = strstr(lnpc->cad, "y: "))) {
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %c", S2CD_LANG_PRIO, p[3]);
			else fprintf(stderr, "%s - %c\n", S2CD_LANG_PRIO, p[3]);
		}   /* if (v) */

		if (isdigit(p[3]))
			if ((p[3] - 48) >= priority)
				return(1);
	}   /* if ((p */

	return(0);

}   /* s2cd_parse_priority */

/* s2cd_parse_ip returns the last ip address regmatched per kevent which should be the 
ip address we are looking for. */

int s2cd_parse_ip(struct lnpc_t *lnpc) {

	int len = 0, i = 0;
	char *regpos = NULL;
	regmatch_t rado[S2CD_REGARSIZ];

	memset((regmatch_t*)rado, 0x00, (S2CD_REGARSIZ * sizeof(regmatch_t)));
	regpos = lnpc->cad;

	for (i = 0; (regexec(&lnpc->expr, regpos, S2CD_REGARSIZ, rado, 0) == 0); i++) {

		len = (rado[0].rm_eo - rado[0].rm_so);

		if (len) {
			memset((char *)lnpc->ret, 0x00, (BUFSIZ * sizeof(char)));
			memcpy(lnpc->ret, (regpos + rado[0].rm_so), len);
			lnpc->ret[len]='\0';
			regpos = (regpos + rado[0].rm_eo);
			memset((regmatch_t*)rado, 0x00, (S2CD_REGARSIZ * sizeof(regmatch_t)));
		}   /* if (len) */
	}   /* for (i */

	return(i);

}   /* s2cd_parse_ip */

void s2cd_parse_and_block(struct lpdt_t *lpdt, struct lnpc_t *lnpc, struct pftbl_t *pftbl) {

	int pb_status = 0, threadcheck = 0;

	if (!s2cd_parse_priority(lpdt->priority, lpdt->v, lnpc)) return;
	if (!s2cd_parse_ip(lnpc)) {
		if (lpdt->v) s2cd_sw_switch(S2CD_LANG_NO_REG, S2CD_LANG_WARN);
		return;
	}   /* if (!s2cd_parse_ip */

	if (!LIST_EMPTY(&lpdt->pbhead.phead))
		if (s2cd_parse_search_list(lnpc->ret, &lpdt->pbhead.phead))
			return;

	if ((pb_status = s2cd_parse_and_block_bl(lpdt->C, lnpc->ret, &lpdt->pbhead.bhead)) == lpdt->repeat_offenses) {

		pthread_mutex_lock(&thr_mutex);
		s2cd_threads++;
		threadcheck = s2cd_threads;
		pthread_mutex_unlock(&thr_mutex);

		if (threadcheck < lpdt->thr_max)
			if (s2cd_spawn_block_log(lpdt->C, lpdt->D, lnpc->ret, lpdt->logfile)) s2cd_sw_switch_f(S2CD_LANG_SPBL, S2CD_LANG_EXIT);

		s2cd_pf_block(lpdt->dev, lpdt->v, lpdt->tblnm, lnpc->ret, pftbl);
		if (lpdt->v) s2cd_sw_switch(S2CD_LANG_BLK, lnpc->ret);

	} else if (pb_status == -1) s2cd_sw_switch_f(S2CD_LANG_INTDB, S2CD_LANG_EXIT);

	return;

}   /* s2cd_parse_and_block */

void s2cd_parse_load_file(struct pftbl_t *pftbl, struct lpdt_t *lpdt, struct lnpc_t *lnpc, const char *ufile, struct ulist_head *head, struct ipulist *ipu1, int id) {

	register struct ipulist *ipu = NULL;
	FILE *file = NULL;

	if ((file = fopen(ufile, "r")) == NULL) {
		s2cd_sw_switch_e(S2CD_LANG_NO_OPEN, ufile, S2CD_LANG_WARN);
		return;
	}   /* if ((file */

	flockfile(file);

	while (s2cd_parse_line(lnpc->cad, file)) {
		if (s2cd_parse_ip(lnpc)) {

			if (id == S2CD_ID_PF) {
				if ((ipu = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) S2CD_MALLOC_ERR;
				s2cd_parse_ipu_set(lpdt->C, lnpc->ret, ipu);
				LIST_INSERT_AFTER(ipu1, ipu, elem);
				ipu1 = ipu;
			}   /* if(id == S2CD_ID_PF) */

			if (id == S2CD_ID_BF) {
				if (!LIST_EMPTY(head))
					if (s2cd_parse_search_list(lnpc->ret, head)) {
						if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", S2CD_LANG_BENT, lnpc->ret, S2CD_LANG_PL, S2CD_LANG_WARN);
						else fprintf(stderr, "%s %s %s - %s\n", S2CD_LANG_BENT, lnpc->ret, S2CD_LANG_PL, S2CD_LANG_WARN);
					}   /* if (s2cd_parse_search_list */

				s2cd_pf_rule_add(lpdt->dev, lpdt->v, lpdt->tblnm_static, pftbl);
				s2cd_pf_block(lpdt->dev, lpdt->v, lpdt->tblnm_static, lnpc->ret, pftbl);
			}   /* if (id == S2CD_ID_BF) */
		}   /* if (s2cd_parse_ip */
	}   /* while (s2cd_parse_line */

	funlockfile(file);
	fclose(file);

	return;

}   /* s2cd_parse_load_file */

void s2cd_parse_load_ifaces(int C, struct ipulist *ipu) {

	struct ifaddrs *ifaddr = NULL;
	register struct ifaddrs *ifa = NULL;

	if (getifaddrs(&ifaddr) == -1) s2cd_sw_switch_f(S2CD_LANG_IFADDR_ERROR, S2CD_LANG_EXIT);

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if ((ifa->ifa_addr)->sa_family == AF_INET)
			s2cd_parse_add_list(C, ipu, ifa);
	}   /* for (ifa */

	freeifaddrs(ifaddr);

	return;

}   /* s2cd_parse_load_ifaces */

void s2cd_parse_add_list(int C, struct ipulist *ipu1, struct ifaddrs *ifa) {

	register struct ipulist *ipu = NULL;
	char ret[BUFSIZ];

	inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ret, INET_ADDRSTRLEN);

	S2CD_IPU_INIT;
	LIST_INSERT_AFTER(ipu1, ipu, elem);
	ipu1 = ipu;

	return;

}   /* s2cd_parse_add_list */

void s2cd_parse_load_pl(struct pftbl_t *pftbl, struct lpdt_t *lpdt, char *pfile, struct lnpc_t *lnpc, struct ulist_head *head) {

	register struct ipulist *ipu = NULL;
	int fd = 0;

	if ((ipu = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) S2CD_MALLOC_ERR;
	memset((struct ipulist *)ipu, 0x00, sizeof(struct ipulist));

	ipu->ciaddr = *cidr_from_str("127.0.0.0/8");
	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipu, elem);

	if (!strcmp(lpdt->extif, "all")) s2cd_parse_load_ifaces(lpdt->C, ipu);
	else {

		memset((struct ifreq *)&pftbl->ifr, 0x00, sizeof(struct ifreq));
		
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		pftbl->ifr.ifr_addr.sa_family = AF_INET;
		strlcpy(pftbl->ifr.ifr_name, lpdt->extif, IFNAMSIZ);

		if (s2cd_pf_ioctl(fd, lpdt->v, SIOCGIFADDR, &pftbl->ifr) != 0) s2cd_sw_switch_ef(S2CD_LANG_NO_OPEN, lpdt->extif, S2CD_LANG_EXIT);

		close(fd);

		s2cd_parse_add_list(lpdt->C, ipu, (struct ifaddrs *)&pftbl->ifr.ifr_addr);
	}   /* else if (!strcmp */

	if (!lpdt->Z) s2cd_parse_load_file(pftbl, lpdt, lnpc, S2CD_PATH_RESOLV, head, ipu, S2CD_ID_PF);
	s2cd_parse_load_file(pftbl, lpdt, lnpc, pfile, head, ipu, S2CD_ID_PF);

	return;

}   /* s2cd_parse_load_pl */

void s2cd_parse_print_list(struct ulist_head *head) {

	register struct ipulist *ipu = NULL;

	s2cd_sw_switch( "<", S2CD_LANG_PLL);

	for (ipu = head->lh_first; ipu != NULL; ipu = ipu->elem.le_next)
		s2cd_sw_switch("<", ipu->chaddr);

	return;

}   /* s2cd_parse_print_list */

int s2cd_parse_search_list(char *ip, struct ulist_head *head) {

	register struct ipulist *ipu = NULL;
	CIDR ipcidr;
	int f = 0;

	ipcidr = *cidr_from_str(ip);

	for (ipu = head->lh_first; ipu != NULL; ipu = ipu->elem.le_next)
		if (!cidr_contains(&ipu->ciaddr, &ipcidr)) { f = 1; break; }

	return(f);

}   /* s2cd_parse_search_list */

void s2cd_parse_ipu_set(int C, char *ret, struct ipulist *ipu) {

	memset((struct ipulist *)ipu, 0x00, sizeof(struct ipulist));
	strlcpy(ipu->chaddr, ret, BUFSIZ);
	ipu->ciaddr = *cidr_from_str(ret);
	if (!C) ipu->t = time(NULL);
	else ipu->t = 0;
	ipu->repeat_offenses = 0;

	return;

}   /* s2cd_parse_ipu_set */
