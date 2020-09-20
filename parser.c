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
 * s2cd_pf_expiretable from expiretable
 * s2cd_radix_ioctlfrom ioctl_helpers.c
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

int s2cd_parse_and_block_bl(char *ret, int C, int F, struct ulist_head *head) {

	register struct ipulist *aux2 = NULL;
	struct ipulist *ipu = NULL;

	if (head->lh_first == NULL){
		S2CD_IPU_SET;
		LIST_INIT(head);
		LIST_INSERT_HEAD(head, ipu, elem);
		return(0);

	} else {
		for (aux2=head->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
			if (!strcmp(aux2->chaddr, ret)) {
				aux2->repeat_offenses++;
				return(aux2->repeat_offenses);
			} else if (!aux2->elem.le_next) {
				S2CD_IPU_SET;
				LIST_INSERT_AFTER(aux2, ipu, elem);
				return(0);
			}   /* else if (!aux2 */
		}   /* for (aux2 */
	}   /* else if (head */

	return(-1);

}   /* s2cd_parse_and_block_bl */

void s2cd_parse_and_block_list_clear(struct ulist_head *head) {

	register struct ipulist *n1 = NULL, *n2 = NULL;

 	n1 = LIST_FIRST(head);

	while (n1 != NULL) {
		n2 = LIST_NEXT(n1, elem);
		free(n1);
		n1 = n2;
	}   /* while (n1 */

	return;

}   /* s2cd_parse_and_block_list_clear */

void s2cd_parse_and_block_list_timeout(time_t age, time_t this_time, struct ulist_head *head) {

	register struct ipulist *aux = NULL;

	for (aux=head->lh_first; aux !=NULL; aux=aux->elem.le_next)
		if ((aux->t + age) < this_time) {
			LIST_REMOVE(aux, elem);
			free(aux);
		}   /* if ((aux->t */

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

int s2cd_parse_priority(int priority, int v, int F, lineproc_t *lineproc) {

	register char *p = NULL;

	if ((p = strstr(lineproc->cad, "y: "))) {
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %c", S2CD_LANG_PRIO, p[3]);
			else fprintf(stderr, "%s - %c\n", S2CD_LANG_PRIO, p[3]);
		}   /* if (v) */

		if (isdigit(p[3])) if ((p[3] - 48) >= priority) return(1);
	}   /* if ((p */

	return(0);

}   /* s2cd_parse_priority */

/* s2cd_parse_ip returns the last ip address regmatched per kevent which should be the 
ip address we are looking for. */

int s2cd_parse_ip(lineproc_t *lineproc) {

	int len = 0, i = 0;
	char *regpos = NULL;
	regmatch_t rado[S2CD_REGARSIZ];

	memset((regmatch_t *)rado, 0x00, (S2CD_REGARSIZ * sizeof(regmatch_t)));
	regpos = lineproc->cad;

	for (i = 0; (regexec(&lineproc->expr, regpos, S2CD_REGARSIZ, rado, 0) == 0); i++) {

		len = (rado[0].rm_eo - rado[0].rm_so);

		if (len) {
			memset((char *)lineproc->ret, 0x00, (BUFSIZ * sizeof(char)));
			memcpy(lineproc->ret, (regpos + rado[0].rm_so), len);
			lineproc->ret[len]='\0';
			regpos = (regpos + rado[0].rm_eo);
			memset((regmatch_t *)rado, 0x00, (S2CD_REGARSIZ * sizeof(regmatch_t)));
		}   /* if (len) */
	}   /* for (i */

	return(i);

}   /* s2cd_parse_ip */

void s2cd_parse_and_block(loopdata_t *loopdata, lineproc_t *lineproc) {

	int pb_status = 0, threadcheck = 0;

	if (!s2cd_parse_priority(loopdata->priority, loopdata->v, loopdata->F, lineproc)) return;
	if (!s2cd_parse_ip(lineproc)) {
		if (loopdata->v) s2cd_sw_switch(loopdata->F, S2CD_LANG_NO_REG, S2CD_LANG_WARN);
		return;
	}   /* if (!s2cd_parse_ip */

	if (!LIST_EMPTY(&loopdata->pbhead.phead))
		if (s2cd_parse_search_list(lineproc->ret, &loopdata->pbhead.phead)) return;

	if ((pb_status = s2cd_parse_and_block_bl(lineproc->ret, loopdata->C, loopdata->F, &loopdata->pbhead.bhead)) == loopdata->repeat_offenses) {

		pthread_mutex_lock(&thr_mutex);
		s2cd_threads++;
		threadcheck = s2cd_threads;
		pthread_mutex_unlock(&thr_mutex);

		if (threadcheck < loopdata->thr_max)
			if (s2cd_spawn_block_log(loopdata->C, loopdata->D, loopdata->F, lineproc->ret, loopdata->logfile))
				s2cd_sw_switch_f(loopdata->F, S2CD_LANG_SPBL, S2CD_LANG_EXIT);

		s2cd_pf_block(loopdata->dev, loopdata->v, loopdata->F, loopdata->tablename, lineproc->ret);
		if (loopdata->v) s2cd_sw_switch(loopdata->F, S2CD_LANG_BLK, lineproc->ret);

	} else if (pb_status == -1) s2cd_sw_switch_f(loopdata->F, S2CD_LANG_INTDB, S2CD_LANG_EXIT);

	return;

}   /* s2cd_parse_and_block */

void s2cd_parse_load_file(loopdata_t *loopdata, lineproc_t *lineproc, char *ufile, struct ulist_head *head, struct ipulist *ipu1, int id) {

	struct ipulist *ipu = NULL;
	FILE *file = NULL;
	int F = loopdata->F;

	if (id == S2CD_ID_BF) {
		if (s2cd_pf_rule_add(loopdata->dev, loopdata->v, loopdata->F, loopdata->tablename_static) < 0)
                                if (loopdata->v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, "s2cd_parse_load_file");
	}   /* if (id == S2CD_ID_BF) */

	if ((file = fopen(ufile, "r")) == NULL) {
		s2cd_sw_switch_e(F, S2CD_LANG_NO_OPEN, ufile, S2CD_LANG_WARN);
		return;
	}   /* if ((file */

	flockfile(file);

	while (s2cd_parse_line(lineproc->cad, file)) {
		if (s2cd_parse_ip(lineproc)) {

			if (id == S2CD_ID_PF) {
				if ((ipu = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) S2CD_MALLOC_ERR;
				s2cd_parse_ipu_set(lineproc->ret, loopdata->C, ipu);
				LIST_INSERT_AFTER(ipu1, ipu, elem);
				ipu1 = ipu;
			}   /* if(id == S2CD_ID_PF) */

			if (id == S2CD_ID_BF) {
				if (!LIST_EMPTY(head))
					if (s2cd_parse_search_list(lineproc->ret, head)) {
						if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", S2CD_LANG_BENT, lineproc->ret, S2CD_LANG_PL, S2CD_LANG_WARN);
						else fprintf(stderr, "%s %s %s - %s\n", S2CD_LANG_BENT, lineproc->ret, S2CD_LANG_PL, S2CD_LANG_WARN);
					}   /* if (s2cd_parse_search_list */

				s2cd_pf_block(loopdata->dev, loopdata->v, loopdata->F, loopdata->tablename_static, lineproc->ret);
			}   /* if (id == S2CD_ID_BF) */
		}   /* if (s2cd_parse_ip */
	}   /* while (s2cd_parse_line */

	funlockfile(file);
	fclose(file);

	return;

}   /* s2cd_parse_load_file */

void s2cd_parse_load_ifaces(int C, int F, struct ipulist *ipu1) {

	struct ifaddrs *ifaddr = NULL;
	register struct ifaddrs *ifa = NULL;

	if (getifaddrs(&ifaddr) == -1) s2cd_sw_switch_f(F, S2CD_LANG_IFADDR_ERROR, S2CD_LANG_EXIT);

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if ((ifa->ifa_addr)->sa_family == AF_INET) s2cd_parse_add_list(C, F, ipu1, ifa);
	}   /* for (ifa */

	freeifaddrs(ifaddr);

	return;

}   /* s2cd_parse_load_ifaces */

void s2cd_parse_add_list(int C, int F, struct ipulist *ipu1, struct ifaddrs *ifa) {

	struct ipulist *ipu = NULL;
	char ret[BUFSIZ];

	inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ret, INET_ADDRSTRLEN);
	S2CD_IPU_SET;

	LIST_INSERT_AFTER(ipu1, ipu, elem);
	ipu1 = ipu;

	return;

}   /* s2cd_parse_add_list */

void s2cd_parse_load_pl(loopdata_t *loopdata, char *pfile, lineproc_t *lineproc, struct ulist_head *head) {

	struct ipulist *ipu = NULL;
	struct ifreq *ifr = NULL;
	int fd = 0, F = loopdata->F;

	if ((ipu = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) S2CD_MALLOC_ERR;
	memset(ipu, 0x00, sizeof(struct ipulist));

	ipu->ciaddr = *cidr_from_str("127.0.0.0/8");
	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipu, elem);

	if (!strcmp(loopdata->extif, "all")) s2cd_parse_load_ifaces(loopdata->C, F, ipu);
	else {

		if ((ifr = (struct ifreq *)malloc(sizeof(struct ifreq))) == NULL) S2CD_MALLOC_ERR;
		memset(ifr, 0x00, sizeof(struct ifreq));
		
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr->ifr_addr.sa_family = AF_INET;
		strlcpy(ifr->ifr_name, loopdata->extif, IFNAMSIZ);

		if (s2cd_pf_ioctl(fd, loopdata->v, loopdata->F, SIOCGIFADDR, ifr) < 0)
			s2cd_sw_switch_ef(F, S2CD_LANG_NO_OPEN, loopdata->extif, S2CD_LANG_EXIT);

		close(fd);
		free(ifr);

		s2cd_parse_add_list(loopdata->C, F, ipu, (struct ifaddrs *)&(ifr->ifr_addr));
	}   /* else if (!strcmp */

	if (!loopdata->Z) s2cd_parse_load_file(loopdata, lineproc, S2CD_PATH_RESOLV, head, ipu, S2CD_ID_PF);
	s2cd_parse_load_file(loopdata, lineproc, pfile, head, ipu, S2CD_ID_PF);

	return;

}   /* s2cd_parse_load_pl */

void s2cd_parse_print_list(int F, struct ulist_head *head) {

	register struct ipulist *aux2 = NULL;

	s2cd_sw_switch(F, "<", S2CD_LANG_PLL);

	for (aux2 = head->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		s2cd_sw_switch(F, "<", aux2->chaddr);

	return;

}   /* s2cd_parse_print_list */

int s2cd_parse_search_list(char *ip, struct ulist_head *head) {

	register struct ipulist *aux2 = NULL;
	CIDR ipcidr;
	int f = 0;

	ipcidr = *cidr_from_str(ip);

	for (aux2 = head->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		if (!cidr_contains(&aux2->ciaddr, &ipcidr)) { f = 1; break; }

	return(f);

}   /* s2cd_parse_search_list */

void s2cd_parse_ipu_set(char *ret, int C, struct ipulist *ipu) {

	memset(ipu, 0x00, sizeof(struct ipulist));
	strlcpy(ipu->chaddr, ret, BUFSIZ);
	ipu->ciaddr = *cidr_from_str(ret);
	if (!C) ipu->t = time(NULL);
	else ipu->t = 0;
	ipu->repeat_offenses = 0;

	return;

}   /* s2cd_parse_ipu_set */
