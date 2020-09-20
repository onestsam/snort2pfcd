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

void *s2cd_pf_expiretable(void *arg) {

	typedef struct _pfas_t {
		struct pfr_astats astats;
		struct pfr_table target;
		pfbl_log_t pfbl_log;
		char tablename[PF_TABLE_NAME_SIZE];
		char nmpfdev[S2CD_NMBUFSIZ];
	} pfas_t;

	pfas_t *pfas = NULL;
	struct pfr_astats *astatsp = NULL;
	struct pfr_addr *del_addrs_list = NULL;
	int astats_count = 0, del_addrs_count = 0, dev = 0, v = 0, C = 0, F = 0, i = 0;
	time_t age = S2CD_EXPTIME, min_timestamp = 0, oldest_entry = 0;
	int flags = PFR_FLAG_FEEDBACK;
	thread_expt_t *data = (thread_expt_t *)arg;

	v = data->v;
	C = data->C;
	F = data->F;
	dev = data->dev;
	if (data->t > 0) age = data->t;

	if ((pfas = (pfas_t *)malloc(sizeof(pfas_t))) == NULL) S2CD_MALLOC_ERR;
	memset(pfas, 0x00, sizeof(pfas_t));

	strlcpy(pfas->tablename, data->tablename, PF_TABLE_NAME_SIZE);
	strlcpy(pfas->pfbl_log.local_logfile, data->logfile, S2CD_NMBUFSIZ);
	strlcpy(pfas->nmpfdev, data->nmpfdev, S2CD_NMBUFSIZ);
	free(data);

	astatsp = (struct pfr_astats *)&pfas->astats;

	while (1) {
		memset(&pfas->target, 0x00, sizeof(struct pfr_table));
		memset(&pfas->astats, 0x00, sizeof(struct pfr_astats));
		strlcpy(pfas->target.pfrt_name, pfas->tablename, PF_TABLE_NAME_SIZE);
		if (!C) oldest_entry = time(NULL);
		else oldest_entry = 0;
		min_timestamp = oldest_entry - age;

		astats_count = s2cd_radix_get_astats(dev, v, F, &astatsp, &pfas->target, 0);

		if (astats_count > 0) {

			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++) {
				if (astatsp[i].pfras_tzero <= min_timestamp) del_addrs_count++;
				else oldest_entry = s2cd_lmin(oldest_entry, astatsp[i].pfras_tzero);
			}   /* for (i */

			if ((del_addrs_list = (struct pfr_addr *)malloc(del_addrs_count * sizeof(struct pfr_addr))) == NULL) S2CD_MALLOC_ERR;
			memset(del_addrs_list, 0x00, sizeof(struct pfr_addr));

			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++)
				if (astatsp[i].pfras_tzero <= min_timestamp) {
					del_addrs_list[del_addrs_count] = astatsp[i].pfras_a;
					del_addrs_list[del_addrs_count].pfra_fback = 0;
					((struct sockaddr_in *)&pfas->pfbl_log.sa)->sin_addr = astatsp[i].pfras_a.pfra_ip4addr;
					s2cd_pf_unblock_log(C, F, &pfas->pfbl_log);
					del_addrs_count++;
				}   /* if (astats */

			if (del_addrs_count > 0) s2cd_radix_del_addrs(dev, v, F, &pfas->target, del_addrs_list, del_addrs_count, flags);
		}   /* if (astats_count > 0) */

		free(del_addrs_list);
		sleep(age + 1);
	}   /* while (1) */

	free(pfas);

	pthread_exit(NULL);

}   /* s2cd_pf_expiretable */

int s2cd_radix_ioctl(int dev, int v, int F, unsigned long request, struct pfioc_table *pt) {
	void *newinbuf;
	size_t len = 0;
	pt->pfrio_buffer = newinbuf = malloc(0);

	if (newinbuf == NULL) S2CD_MALLOC_ERR;

	for (;;) {
		pt->pfrio_size = len;

		if (len) {
			if ((newinbuf = realloc(pt->pfrio_buffer, len * pt->pfrio_esize)) == NULL) S2CD_MALLOC_ERR;
			pt->pfrio_buffer = newinbuf;
		}   /* if (len) */

		if (s2cd_pf_ioctl(dev, v, F, request, pt) < 0) {
			free(pt->pfrio_buffer);
			pt->pfrio_buffer = NULL;
			return(-1);
		}   /* if (s2cd_pf_ioctl */

		if (pt->pfrio_size + 1 < len) break;
		if (pt->pfrio_size == 0) return(0);
		if (len == 0) len = pt->pfrio_size;

		len *= 2;
	}   /* for (;;) */

	return(pt->pfrio_size);

}   /* s2cd_radix_ioctl */

int s2cd_radix_get_astats(int dev, int v, int F, struct pfr_astats **astats, const struct pfr_table *filter, int flags) {
	struct pfioc_table *pt;
	int ch = 0;

	if ((pt = (struct pfioc_table *)malloc(sizeof(struct pfioc_table))) == NULL) S2CD_MALLOC_ERR;
	memset(pt, 0x00, sizeof(struct pfioc_table));

	pt->pfrio_esize = sizeof(struct pfr_astats);
	pt->pfrio_flags = flags;

	if (filter != NULL) {
		pt->pfrio_table = *filter;
		pt->pfrio_table.pfrt_flags = 0;
	}

	if (s2cd_radix_ioctl(dev, v, F, DIOCRGETASTATS, pt) < 0) ch = -1;
	else {
		ch = pt->pfrio_size;
		*astats = (struct pfr_astats *)pt->pfrio_buffer;
	}   /* else */

	free(pt);

	return(ch);

}   /* s2cd_radix_get_astats */
        
int s2cd_radix_del_addrs(int dev, int v, int F, const struct pfr_table *table, struct pfr_addr *addrs, int addr_count, int flags) {
	struct pfioc_table *pt;
	int ch = 0;

	if ((pt = (struct pfioc_table *)malloc(sizeof(struct pfioc_table))) == NULL) S2CD_MALLOC_ERR;
	memset(pt, 0x00, sizeof(struct pfioc_table));

	pt->pfrio_size = addr_count;
	pt->pfrio_esize = sizeof(struct pfr_addr);
	pt->pfrio_flags = flags;

	pt->pfrio_table = *table;
	pt->pfrio_buffer = addrs;

	if (s2cd_pf_ioctl(dev, v, F, DIOCRDELADDRS, pt) < 0) ch = -1;
	else ch = pt->pfrio_ndel;

	free(pt);

	return(ch);

}   /* s2cd_radix_del_addrs */

void s2cd_pf_block(int dev, int v, int F, char *tablename, char *ip)  {

	pftbl_t *pfbls = NULL;

	if ((pfbls = (pftbl_t *)malloc(sizeof(pftbl_t))) == NULL) S2CD_MALLOC_ERR;
	memset(pfbls, 0x00, sizeof(pftbl_t));
	
	strlcpy(pfbls->table.pfrt_name, tablename, PF_TABLE_NAME_SIZE); 
	inet_aton(ip, (struct in_addr *)&pfbls->addr.pfra_ip4addr.s_addr);

	pfbls->addr.pfra_af  = AF_INET;
	pfbls->addr.pfra_net = 32; 

	pfbls->io.pfrio_table  = pfbls->table; 
	pfbls->io.pfrio_buffer = &pfbls->addr; 
	pfbls->io.pfrio_esize  = sizeof(struct pfr_addr); 
	pfbls->io.pfrio_size   = 1;

	if (s2cd_pf_ioctl(dev, v, F, DIOCRADDADDRS, &pfbls->io) < 0)
	if (v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, "s2cd_pf_block");

	free(pfbls);

	return;

}   /* s2cd_pf_block */

void s2cd_pf_unblock_log(int C, int F, pfbl_log_t *pfbl_log) {

	time_t timebuf = 0;

	if (!C) timebuf = time(NULL);
	
	pfbl_log->sa.sa_family = AF_INET;
	if(!inet_ntop(AF_INET, &((struct sockaddr_in *)&pfbl_log->sa)->sin_addr, pfbl_log->local_logip, sizeof(struct sockaddr_in)))
		strlcpy(pfbl_log->hbuf, S2CD_LANG_LOGTHR_ERROR, NI_MAXHOST);

	sprintf(pfbl_log->message, "%s %s %s %s", pfbl_log->local_logip, pfbl_log->hbuf, S2CD_LANG_UNBLOCKED, asctime(localtime(&timebuf)));
	s2cd_write_file(F, pfbl_log->local_logfile, pfbl_log->message);

	memset(&pfbl_log->sa, 0x00, sizeof(pfbl_log->sa));
	memset(pfbl_log->message, 0x00, BUFSIZ);
	memset(pfbl_log->local_logip, 0x00, BUFSIZ);
	memset(pfbl_log->hbuf, 0x00, NI_MAXHOST);

	return;

}   /* s2cd_pf_unblock_log */

void *s2cd_pf_block_log(void *arg) {

	time_t timebuf = 0;
	int gni_error = 0, C = 0, D = 0, F = 0;
	pfbl_log_t *pfbl_log = NULL;
	thread_log_t *data = (thread_log_t *)arg;

	C = data->C;
	D = data->D;
	F = data->F;

	if ((pfbl_log = (pfbl_log_t *)malloc(sizeof(pfbl_log_t))) == NULL) S2CD_MALLOC_ERR;
	memset(pfbl_log, 0x00, sizeof(pfbl_log_t));

	strlcpy(pfbl_log->local_logip, data->logip, BUFSIZ);
	strlcpy(pfbl_log->local_logfile, data->logfile, S2CD_NMBUFSIZ);
	free(data);

	if (!C) timebuf = time(NULL);

	if (!D) {
		pfbl_log->sa.sa_family = AF_INET;
		if (inet_pton(AF_INET, pfbl_log->local_logip, &((struct sockaddr_in *)&pfbl_log->sa)->sin_addr)) {

			pthread_mutex_lock(&dns_mutex);
			gni_error = getnameinfo(&pfbl_log->sa, sizeof(struct sockaddr_in), pfbl_log->hbuf, sizeof(char)*NI_MAXHOST, NULL, 0, NI_NAMEREQD);
			if (gni_error != 0) strlcpy(pfbl_log->hbuf, gai_strerror(gni_error), NI_MAXHOST);
			pthread_mutex_unlock(&dns_mutex);

		} else strlcpy(pfbl_log->hbuf, S2CD_LANG_LOGTHR_ERROR, NI_MAXHOST);
	} else strlcpy(pfbl_log->hbuf, S2CD_LANG_DNS_DISABLED, NI_MAXHOST);

	sprintf(pfbl_log->message, "%s (%s) %s %s", pfbl_log->local_logip, pfbl_log->hbuf, S2CD_LANG_NOT_PASSLISTED, asctime(localtime(&timebuf)));
	s2cd_write_file(F, pfbl_log->local_logfile, pfbl_log->message);
	
	free(pfbl_log);

	pthread_mutex_lock(&thr_mutex);
	if (s2cd_threads > 1) s2cd_threads--;
	pthread_mutex_unlock(&thr_mutex);

	pthread_exit(NULL);

}   /* s2cd_pf_block_log */

int s2cd_pf_rule_add(int dev, int v, int F, char *tablename) {

	int ch = 0;
        pftbl_t *pftbl = NULL;

        if ((pftbl = (pftbl_t *)malloc(sizeof(pftbl_t))) == NULL) S2CD_MALLOC_ERR;
        memset(pftbl, 0x00, sizeof(pftbl_t));

	s2cd_pf_tbl_add(dev, v, F, tablename, pftbl);

	pftbl->io_rule.action = PF_CHANGE_GET_TICKET;
	pftbl->io_rule.rule.direction = PF_IN;
	pftbl->io_rule.rule.action = PF_DROP;
	pftbl->io_rule.rule.src.addr.type = PF_ADDR_TABLE;
	pftbl->io_rule.rule.rule_flag = PFRULE_RETURN;
	strlcpy(pftbl->io_rule.rule.src.addr.v.tblname, tablename, sizeof(pftbl->io_rule.rule.src.addr.v.tblname));

	if (s2cd_pf_ioctl(dev, v, F, DIOCCHANGERULE, &pftbl->io_rule) == 0) {
		if (s2cd_pf_ioctl(dev, v, F, DIOCBEGINADDRS, &pftbl->io_paddr) == 0) {
			pftbl->io_rule.pool_ticket = pftbl->io_paddr.ticket;
			pftbl->io_rule.action = PF_CHANGE_ADD_TAIL;

			if (s2cd_pf_ioctl(dev, v, F, DIOCCHANGERULE, &pftbl->io_rule) < 0) ch = -1;
		} else ch = -1;
	} else ch = -1;

	free(pftbl);

	return(ch);

}   /* s2cd_pf_rule_add */

int s2cd_pf_tbl_get(int dev, int v, int F, char *tablename, pftbl_t *pftbl) {

	s2cd_pftbl_set(tablename, pftbl);
	pftbl->io.pfrio_size = 0;
	if (s2cd_pf_ioctl(dev, v, F, DIOCRGETTABLES, &pftbl->io) < 0) return(-1);

	return(pftbl->io.pfrio_size);

}   /* s2cd_pf_tbl_get */

void s2cd_pf_tbl_add(int dev, int v, int F, char *tablename, pftbl_t *pftbl) {

	if (s2cd_pf_tbl_get(dev, v, F, tablename, pftbl) < 0)
	if (v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, "s2cd_pf_tbl_add");

	pftbl->io.pfrio_buffer = &pftbl->table;
	pftbl->io.pfrio_esize = sizeof(struct pfr_table);

	if (s2cd_pf_ioctl(dev, v, F, DIOCRGETTABLES, &pftbl->io) < 0)
	if (v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, "s2cd_pf_tbl_add");

	s2cd_pftbl_set(tablename, pftbl);
	pftbl->table.pfrt_flags = PFR_TFLAG_PERSIST;

	if (s2cd_pf_ioctl(dev, v, F, DIOCRADDTABLES, &pftbl->io) < 0)
	if (v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, "s2cd_pf_tbl_add");

	if (v) s2cd_sw_switch(F, S2CD_LANG_TBLADD, tablename);

	return;

}   /* s2cd_pf_tbladd */

void s2cd_pf_tbl_del(int dev, int v, int F, char *tablename) {

	pftbl_t *pftbl = NULL;

	if ((pftbl = (pftbl_t *)malloc(sizeof(pftbl_t))) == NULL) S2CD_MALLOC_ERR;
	s2cd_pftbl_set(tablename, pftbl);
	if (s2cd_pf_ioctl(dev, v, F, DIOCRDELTABLES, &pftbl->io) < 0)
	if (v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, "s2cd_pf_tbl_del");

	free(pftbl);

	return;

}   /* s2cd_pf_tbldel */

int s2cd_pf_ioctl(int dev, int v, int F, unsigned long request, void *pf_io_arg) {
	int i = 0, ch = 0;

	pthread_mutex_lock(&pf_mutex);
	for (i = 0; ioctl(dev, request, pf_io_arg) < 0; i++) {
		if (v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_WAIT, S2CD_LANG_WARN);
		sleep(1);
		if (i > 4) {
			if (v) s2cd_sw_switch(F, S2CD_LANG_IOCTL_ERROR, S2CD_LANG_WARN);
			pf_reset = 1; ch = -1;
			break;
		}   /* end if */
	}   /* while (ioctl */
	pthread_mutex_unlock(&pf_mutex);

	return(ch);

}   /* s2cd_pf_ioctl */

void s2cd_pftbl_set(char *tablename, pftbl_t *pftbl) {

	memset(pftbl, 0x00, sizeof(pftbl_t));
	strlcpy(pftbl->table.pfrt_name, tablename, PF_TABLE_NAME_SIZE);
	pftbl->io.pfrio_buffer = &pftbl->table; 
	pftbl->io.pfrio_esize  = sizeof(struct pfr_table); 
	pftbl->io.pfrio_size   = 1; 

	return;

}   /* s2cd_pftbl_set */
