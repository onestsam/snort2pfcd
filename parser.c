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
 * s2cd_parse_line based in pfctl code (pfctl_radix.c)
 * Copyright (c) Armin's Wolfermann
 *
 * s2cd_pf_block functions are based
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

#include "defdata.h"

int s2cd_parse_and_block_bl(char *ret, struct ulist_head *head) {

	struct ipulist *aux2 = NULL, *ipu = NULL;

	if (head->lh_first == NULL){
		if ((ipu = (struct ipulist*)malloc(sizeof(struct ipulist))) == NULL) s2cd_malloc_err();

		s2cd_parse_ipu_set(ret, ipu);
		LIST_INIT(head);
		LIST_INSERT_HEAD(head, ipu, elem);
		return(0);

	} else {
		for (aux2=head->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
			if (!strcmp(aux2->chaddr, ret)) {
				aux2->repeat_offenses++;
				return(aux2->repeat_offenses);
			} else if (!aux2->elem.le_next) {
				if ((ipu = (struct ipulist*)malloc(sizeof(struct ipulist))) == NULL) s2cd_malloc_err();
				s2cd_parse_ipu_set(ret, ipu);
				LIST_INSERT_AFTER(aux2, ipu, elem);
				return(0);
			}   /* else if (!aux2 */
		}   /* for (aux2 */
	}   /* else if (head */

	return(-1);

} /* s2cd_parse_and_block_bl */

void s2cd_parse_and_block_list_clear(struct ulist_head *head) {

	struct ipulist *n1 = NULL, *n2 = NULL;

 	n1 = LIST_FIRST(head);

	while (n1 != NULL) {
		n2 = LIST_NEXT(n1, elem);
		free(n1);
		n1 = n2;
	}   /* while (n1 */

	return;

} /* s2cd_parse_and_block_list_clear */

void s2cd_parse_and_block_list_timeout(unsigned long age, unsigned long this_time, struct ulist_head *head) {

	struct ipulist *aux2 = NULL;

	for (aux2=head->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next)
		if ((aux2->t + age) < this_time) {
			LIST_REMOVE(aux2, elem);
			free(aux2);
		}   /* if ((aux2->t */

	return;

} /* s2cd_parse_and_block_list_timeout */

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

} /* s2cd_parse_line */

int s2cd_parse_priority(int priority, lineproc_t *lineproc) {

	char *p = NULL;

	if ((p = strstr(lineproc->cad, "y: "))) {
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %c", S2CD_LANG_PRIO, p[3]);
			else fprintf(stderr, "%s - %c\n", S2CD_LANG_PRIO, p[3]);
		}   /* if (v) */

		if (isdigit(p[3]))
			if ((p[3] - 48) >= priority)
				return(1);
	}   /* if ((p */

	return(0);

} /* s2cd_parse_priority */

/* s2cd_parse_ip returns the last ip address regmatched per kevent which should be the 
ip address we are looking for. */

int s2cd_parse_ip(lineproc_t *lineproc) {

	int len = 0, i = 0;
	char *regpos = NULL;
	regmatch_t rado[S2CD_REGARSIZ];

	memset((regmatch_t*)rado, 0x00, (S2CD_REGARSIZ * sizeof(regmatch_t)));
	regpos = lineproc->cad;

	for (i = 0; (regexec(&lineproc->expr, regpos, S2CD_REGARSIZ, rado, 0) == 0); i++) {

		len = (rado[0].rm_eo - rado[0].rm_so);

		if (len) {
			memset((char *)lineproc->ret, 0x00, (BUFSIZ * sizeof(char)));
			memcpy(lineproc->ret, (regpos + rado[0].rm_so), len);
			lineproc->ret[len]='\0';
			regpos = (regpos + rado[0].rm_eo);
			memset((regmatch_t*)rado, 0x00, (S2CD_REGARSIZ * sizeof(regmatch_t)));
		}   /* if (len) */
	}   /* for (i */

	return(i);

} /* s2cd_parse_ip */

void s2cd_parse_and_block(loopdata_t *loopdata, lineproc_t *lineproc) {

	int pb_status = 0, threadcheck = 0;

	if (!s2cd_parse_priority(loopdata->priority, lineproc)) return;
	if (!s2cd_parse_ip(lineproc)) {
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s", S2CD_LANG_NO_REG);
			else fprintf(stderr, "%s\n", S2CD_LANG_NO_REG);
		}   /* if (v) */
		return;
	}   /* if (!s2cd_parse_ip */

	if (!LIST_EMPTY(&loopdata->pbhead.phead)) {
		if (s2cd_parse_search_list(lineproc->ret, &loopdata->pbhead.phead))
			return;
	}   /* if (!LIST_EMPTY */

	if ((pb_status = s2cd_parse_and_block_bl(lineproc->ret, &loopdata->pbhead.bhead)) == loopdata->repeat_offenses) {

		pthread_mutex_lock(&thr_mutex);
		s2cd_threads++;
		threadcheck = s2cd_threads;
		pthread_mutex_unlock(&thr_mutex);

		if(threadcheck < loopdata->thr_max)
			s2cd_spawn_block_log(loopdata->D, lineproc->ret, loopdata->logfile);

		s2cd_pf_block(loopdata->dev, loopdata->tablename, lineproc->ret);
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", S2CD_LANG_BLK, lineproc->ret);
			else fprintf(stderr, "%s - %s\n", S2CD_LANG_BLK, lineproc->ret);
		}   /* if (v) */

	} else if (pb_status == -1) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", S2CD_LANG_INTDB, S2CD_LANG_EXIT);
		else fprintf(stderr, "%s - %s\n", S2CD_LANG_INTDB, S2CD_LANG_EXIT);
		s2cd_exit_fail();
	}   /* else if (pb_status */

	return;

} /* s2cd_parse_and_block */

void s2cd_parse_load_file(loopdata_t *loopdata, lineproc_t *lineproc, char *ufile, struct ulist_head *head, struct ipulist *ipu1, int id) {

	struct ipulist *ipu2 = NULL;
	FILE *file = NULL;

	if ((file = fopen(ufile, "r")) == NULL) {
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", S2CD_LANG_NO_OPEN, ufile, S2CD_LANG_WARN);
		else fprintf(stderr, "%s %s - %s\n", S2CD_LANG_NO_OPEN, ufile, S2CD_LANG_WARN);
		return;
	}   /* if ((file */

	flockfile(file);

	while (s2cd_parse_line(lineproc->cad, file)) {
		if (s2cd_parse_ip(lineproc)) {

			if(id == S2CD_ID_PF) {
				if ((ipu2 = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) s2cd_malloc_err();
				s2cd_parse_ipu_set(lineproc->ret, ipu2);
				LIST_INSERT_AFTER(ipu1, ipu2, elem);
				ipu1 = ipu2;
			}   /* if(id == S2CD_ID_PF) */

			if (id == S2CD_ID_BF) {
				if (!LIST_EMPTY(head))
					if (s2cd_parse_search_list(lineproc->ret, head)) {
						if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", S2CD_LANG_BENT, lineproc->ret, S2CD_LANG_PL, S2CD_LANG_WARN);
						else fprintf(stderr, "%s %s %s - %s\n", S2CD_LANG_BENT, lineproc->ret, S2CD_LANG_PL, S2CD_LANG_WARN);
					}   /* if (s2cd_parse_search_list */

				s2cd_pf_ruleadd(loopdata->dev, loopdata->tablename_static);
				s2cd_pf_block(loopdata->dev, loopdata->tablename_static, lineproc->ret);
			}   /* if (id == S2CD_ID_BF) */
		}   /* if (s2cd_parse_ip */
	}   /* while (s2cd_parse_line */

	funlockfile(file);
	fclose(file);

	return;

} /* s2cd_parse_load_file */

void s2cd_parse_load_ifaces(struct ipulist *ipu1) {

	struct ifaddrs *ifaddr = NULL, *ifa = NULL;

	if (getifaddrs(&ifaddr) == -1) {
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s - %s", S2CD_LANG_IFADDR_ERROR, S2CD_LANG_EXIT);
		else fprintf(stderr, "%s - %s\n", S2CD_LANG_IFADDR_ERROR, S2CD_LANG_EXIT);
		s2cd_exit_fail();
	}   /* if (getifaddrs */

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if ((ifa->ifa_addr)->sa_family == AF_INET)
			s2cd_parse_add_list(ipu1, ifa);
	}   /* for (ifa */

	freeifaddrs(ifaddr);

	return;

} /* s2cd_parse_load_ifaces */

void s2cd_parse_add_list(struct ipulist *ipu1, struct ifaddrs *ifa) {

	struct ipulist *ipu2 = NULL;
	char ret[BUFSIZ];

	if ((ipu2 = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) s2cd_malloc_err();

	inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ret, INET_ADDRSTRLEN);
	s2cd_parse_ipu_set(ret, ipu2);

	LIST_INSERT_AFTER(ipu1, ipu2, elem);
	ipu1 = ipu2;

	return;

} /* s2cd_parse_add_list */

void s2cd_parse_load_pl(loopdata_t *loopdata, char *pfile, lineproc_t *lineproc, struct ulist_head *head) {

	struct ipulist *ipu1 = NULL;
	struct ifreq *ifr = NULL;
	int fd = 0;

	if ((ipu1 = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) s2cd_malloc_err();
	memset(ipu1, 0x00, sizeof(struct ipulist));

	ipu1->ciaddr = *cidr_from_str("127.0.0.0/8");
	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipu1, elem);

	if (!strcmp(loopdata->extif, "all")) s2cd_parse_load_ifaces(ipu1);
	else {

		if ((ifr = (struct ifreq *)malloc(sizeof(struct ifreq))) == NULL) s2cd_malloc_err();
		memset(ifr, 0x00, sizeof(struct ifreq));
		
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr->ifr_addr.sa_family = AF_INET;
		strlcpy(ifr->ifr_name, loopdata->extif, IFNAMSIZ);

		pthread_mutex_lock(&pf_mutex);
		if (ioctl(fd, SIOCGIFADDR, ifr) != 0){
			if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", S2CD_LANG_NO_OPEN, loopdata->extif, S2CD_LANG_EXIT);
			else fprintf(stderr, "%s %s - %s\n", S2CD_LANG_NO_OPEN, loopdata->extif, S2CD_LANG_EXIT);
			s2cd_exit_fail();
		}
		pthread_mutex_unlock(&pf_mutex);

		close(fd);
		free(ifr);

	s2cd_parse_add_list(ipu1, (struct ifaddrs *)&(ifr->ifr_addr));
	}   /* else if (!strcmp */

	if (!loopdata->Z) s2cd_parse_load_file(loopdata, lineproc, S2CD_PATH_RESOLV, head, ipu1, S2CD_ID_PF);
	s2cd_parse_load_file(loopdata, lineproc, pfile, head, ipu1, S2CD_ID_PF);

	return;

} /* s2cd_parse_load_pl */

void s2cd_parse_print_list(struct ulist_head *head) {

	struct ipulist *aux2 = NULL;

	if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s", S2CD_LANG_PLL);
	else fprintf(stderr, "%s\n", S2CD_LANG_PLL);

	for (aux2 = head->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s", aux2->chaddr);
		else fprintf(stderr, "%s\n", aux2->chaddr);

	return;

} /* s2cd_parse_print_list */

int s2cd_parse_search_list(char *ip, struct ulist_head *head) {

	struct ipulist *aux2 = NULL;
	CIDR ipcidr;
	int f = 0;

	ipcidr = *cidr_from_str(ip);

	for (aux2 = head->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		if (!cidr_contains(&aux2->ciaddr, &ipcidr)) { f = 1; break; }

	return(f);

} /* s2cd_parse_search_list */

void s2cd_parse_ipu_set(char *ret, struct ipulist *ipu) {

	memset(ipu, 0x00, sizeof(struct ipulist));
	strlcpy(ipu->chaddr, ret, BUFSIZ);
	ipu->ciaddr = *cidr_from_str(ret);
	if (!C) ipu->t = time(NULL);
	else ipu->t = 0;
	ipu->repeat_offenses = 0;

	return;

} /* s2cd_parse_ipu_set */
