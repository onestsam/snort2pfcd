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


#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>

#include "defdata.h"
#include "tools.h"
#include "spfc.h"
#include "parser.h"
#include "ioctl_helpers.h"


void
*s2c_pf_expiretable(void *arg)
{
	struct pfr_astats *astats = NULL;
	struct pfr_table *target = NULL;
	struct pfr_addr *del_addrs_list = NULL;
	int astats_count = 0, del_addrs_count = 0, local_dev = 0, i = 0;
	unsigned long age = EXPTIME;
	long min_timestamp = 0, oldest_entry = 0;
	int flags = PFR_FLAG_FEEDBACK;
	thread_expt_t *data = (thread_expt_t *)arg;


	if ((target = (struct pfr_table *)malloc(sizeof(struct pfr_table))) == NULL) s2c_malloc_err();
	if ((astats = (struct pfr_astats *)malloc(sizeof(struct pfr_astats))) == NULL) s2c_malloc_err();

	if (data->t) age = data->t;
	local_dev = data->dev;

	while (1) {
		memset(target, 0x00, sizeof(struct pfr_table));
		memset(astats, 0x00, sizeof(struct pfr_astats));
		memcpy(target->pfrt_name, __progname, PF_TABLE_NAME_SIZE);
		min_timestamp = (long)time(NULL) - age;
		oldest_entry = time(NULL);
		astats_count = radix_get_astats(local_dev, &astats, target, 0);

		if (astats_count > 0) {

			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++) {
				if (astats[i].pfras_tzero <= min_timestamp) del_addrs_count++;
				else oldest_entry = lmin(oldest_entry, astats[i].pfras_tzero);
			}

			if ((del_addrs_list = malloc(del_addrs_count * sizeof(struct pfr_addr))) == NULL) s2c_malloc_err();	
			memset(del_addrs_list, 0x00, sizeof(struct pfr_addr));

			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++)
				if (astats[i].pfras_tzero <= min_timestamp) {
					del_addrs_list[del_addrs_count] = astats[i].pfras_a;
					del_addrs_list[del_addrs_count].pfra_fback = 0;
					del_addrs_count++;
				}

			if (del_addrs_count > 0) radix_del_addrs(local_dev, target, del_addrs_list, del_addrs_count, flags);
		}

		free(del_addrs_list);
		sleep(60);
	}

	free(target);
	free(astats);
	free(arg);
	pthread_exit(NULL);
}

void
s2c_pf_block(int dev, char *tablename, char *ip, struct wlist_head *whead, struct blist_head *bhead) 
{ 
	typedef struct _pfbl_t {
		struct pfioc_table io;
		struct pfr_table table;
		struct pfr_addr addr;
		struct in_addr net_addr;
	} pfbl_t;

	pfbl_t *pfbl = NULL;

	if ((pfbl = (pfbl_t *)malloc(sizeof(pfbl_t))) == NULL) s2c_malloc_err();

	memset(pfbl, 0x00, sizeof(pfbl_t));
	
	memcpy(pfbl->table.pfrt_name, tablename, PF_TABLE_NAME_SIZE); 
	inet_aton(ip, (struct in_addr *)&pfbl->net_addr);
	memcpy(&pfbl->addr.pfra_ip4addr.s_addr, &pfbl->net_addr, sizeof(struct in_addr));

	pfbl->addr.pfra_af  = AF_INET;
	pfbl->addr.pfra_net = 32; 

	pfbl->io.pfrio_table  = pfbl->table; 
	pfbl->io.pfrio_buffer = &pfbl->addr; 
	pfbl->io.pfrio_esize  = sizeof(struct pfr_addr); 
	pfbl->io.pfrio_size   = 1;

	if ((pf_reset = ioctl(dev, DIOCRADDADDRS, &pfbl->io)) != 0) s2c_ioctl_wait("DIOCRADDADDRS");
		
	free(pfbl);
	return;
}

void
*s2c_pf_block_log(void *arg)
{
	typedef struct _pfbl_log_t {
		char message[BUFSIZ];
		char local_logip[BUFSIZ];
		char local_logfile[BUFSIZ];
		char hbuf[NI_MAXHOST];
		struct sockaddr sa;
	} pfbl_log_t;

	long timebuf = 0;
	int gni_error = 0;
	struct sockaddr_in *sin = NULL;
	pfbl_log_t *pfbl_log = NULL;
	thread_log_t *data = (thread_log_t *)arg;

	if ((pfbl_log = (pfbl_log_t *)malloc(sizeof(pfbl_log_t))) == NULL) s2c_malloc_err();

	memset(pfbl_log, 0x00, sizeof(pfbl_log_t));

	memcpy(pfbl_log->local_logip, data->logip, BUFSIZ);
	memcpy(pfbl_log->local_logfile, data->logfile, BUFSIZ);

	timebuf = time(NULL);

	pfbl_log->sa.sa_family = AF_INET;
	sin = (struct sockaddr_in *) &pfbl_log->sa;

	if(inet_pton(AF_INET, pfbl_log->local_logip, &((struct sockaddr_in *)&pfbl_log->sa)->sin_addr)) {

		pthread_mutex_lock(&dns_mutex);
		gni_error = getnameinfo(&pfbl_log->sa, sizeof(struct sockaddr_in), pfbl_log->hbuf, sizeof(char)*NI_MAXHOST, NULL, 0, NI_NAMEREQD);
		pthread_mutex_unlock(&dns_mutex);

		if (gni_error != 0) strlcpy(pfbl_log->hbuf, gai_strerror(gni_error), NI_MAXHOST);
	}

	sprintf(pfbl_log->message, "%s (%s) %s %s", pfbl_log->local_logip, pfbl_log->hbuf, LANG_NOT_WHITELISTED, asctime(localtime(&timebuf)));
	s2c_write_file(pfbl_log->local_logfile, pfbl_log->message);

	free(pfbl_log);
	free(arg);

	pthread_mutex_lock(&thr_mutex);
	if (s2c_threads > 1) s2c_threads--;
	pthread_mutex_unlock(&thr_mutex);

	pthread_exit(NULL);
}

void
s2c_pf_ruleadd(int dev, char *tablename)
{
	typedef struct _pfrla_t {
		struct pfioc_rule io_rule;
		struct pfioc_pooladdr io_paddr;
	} pfrla_t;

	pfrla_t *pfrla = NULL;

	if (!s2c_pf_intbl(dev, tablename))
		s2c_pf_tbladd(dev, tablename);

	if ((pfrla = (pfrla_t *)malloc(sizeof(pfrla_t))) == NULL) s2c_malloc_err();

	memset(pfrla, 0x00, sizeof(pfrla_t));

	pfrla->io_rule.rule.direction = PF_IN;
	pfrla->io_rule.rule.action = PF_DROP;
	pfrla->io_rule.rule.src.addr.type = PF_ADDR_TABLE;
	pfrla->io_rule.rule.rule_flag = PFRULE_RETURN;
	memcpy(pfrla->io_rule.rule.src.addr.v.tblname, tablename, sizeof(pfrla->io_rule.rule.src.addr.v.tblname));

	pfrla->io_rule.action = PF_CHANGE_GET_TICKET;

	if ((pf_reset = ioctl(dev, DIOCCHANGERULE, &pfrla->io_rule) != 0)) s2c_ioctl_wait("DIOCCHANGERULE");

	if ((pf_reset = ioctl(dev, DIOCBEGINADDRS, &pfrla->io_paddr)) != 0) s2c_ioctl_wait("DIOCBEGINADDRS");

	pfrla->io_rule.pool_ticket = pfrla->io_paddr.ticket;
	pfrla->io_rule.action = PF_CHANGE_ADD_TAIL;

	if ((pf_reset = ioctl(dev, DIOCCHANGERULE, &pfrla->io_rule) != 0)) s2c_ioctl_wait("DIOCCHANGERULE");

	free(pfrla);
	return;
}

void
s2c_pf_tbladd(int dev, char *tablename) 
{
	typedef struct _pftbl_t {
		struct pfioc_table io;
		struct pfr_table table;
	} pftbl_t;

	pftbl_t *pftbl = NULL;

	if ((pftbl = (pftbl_t *)malloc(sizeof(pftbl_t))) == NULL) s2c_malloc_err();

	memset(pftbl, 0x00, sizeof(pftbl_t));

	memcpy(pftbl->table.pfrt_name, tablename, PF_TABLE_NAME_SIZE);
	pftbl->table.pfrt_flags = PFR_TFLAG_PERSIST;

	pftbl->io.pfrio_buffer = &pftbl->table; 
	pftbl->io.pfrio_esize  = sizeof(struct pfr_table); 
	pftbl->io.pfrio_size   = 1; 

	while (ioctl(dev, DIOCRADDTABLES, &pftbl->io) != 0) s2c_ioctl_wait("DIOCRADDTABLES");

	free(pftbl);
	return; 
}

int 
s2c_pf_intbl(int dev, char *tablename)
{
	typedef struct _pfintbl_t {
		struct pfioc_table io;
		struct pfr_table table_aux;
	} pfintbl_t;

	int i = 0;
	pfintbl_t *pfintbl = NULL;

	if ((pfintbl = (pfintbl_t *)malloc(sizeof(pfintbl_t))) == NULL) s2c_malloc_err();

	memset(pfintbl, 0x00, sizeof(pfintbl_t));

	pfintbl->io.pfrio_buffer = &pfintbl->table_aux;
	pfintbl->io.pfrio_esize  = sizeof(struct pfr_table);
	pfintbl->io.pfrio_size   = 0;
	
	if ((pf_reset = ioctl(dev, DIOCRGETTABLES, &pfintbl->io)) != 0) s2c_ioctl_wait("DIOCRGETTABLES");
	
	pfintbl->io.pfrio_buffer = &pfintbl->table_aux;
	pfintbl->io.pfrio_esize = sizeof(struct pfr_table);

	if ((pf_reset = ioctl(dev, DIOCRGETTABLES, &pfintbl->io)) != 0) s2c_ioctl_wait("DIOCRGETTABLES");

	for(i=0; i< pfintbl->io.pfrio_size; i++) {
		if (!strcmp((&pfintbl->table_aux)[i].pfrt_name, tablename)){
			free(pfintbl);
			return(1);
		}
	}
	free(pfintbl);
	return(0);
}
