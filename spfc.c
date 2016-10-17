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
#include "ioctl_helpers.h"


void
*s2c_pf_expiretable(void *arg)
{
	struct pfr_astats *astats;
	struct pfr_table target;
	struct pfr_addr *del_addrs_list;
	int astats_count, del_addrs_count, del_addrs_result;
	struct thread_expt_t *data = (struct thread_expt_t *)arg;

	unsigned long age = 60*60*3;
	long min_timestamp, oldest_entry;
	int local_dev, i = 0;
	int flags = PFR_FLAG_FEEDBACK;

	if(data->t) age = (unsigned long)data->t;
	local_dev = data->dev;

	/* already been strlcpy'd */
	memcpy(target.pfrt_name, data->tablename, PF_TABLE_NAME_SIZE);

	while (1) {
		memset(&target, 0x00, sizeof(struct pfr_table));
		min_timestamp = (long)time(NULL) - age;
		oldest_entry = time(NULL);
		astats_count = radix_get_astats(local_dev, &astats, &target,0);

		if (astats_count > 0) {

			del_addrs_list = NULL;
			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++) {
				if (astats[i].pfras_tzero <= min_timestamp) {
					del_addrs_count++;
				}
				else {
					oldest_entry = lmin(oldest_entry, astats[i].pfras_tzero);
				}
			}

			if ((del_addrs_list = malloc(del_addrs_count * sizeof(struct pfr_addr))) == NULL) {
				syslog(LOG_DAEMON | LOG_ERR, "malloc error B01 - exit");
				s2c_exit_fail();
				}

			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++) {
				if (astats[i].pfras_tzero <= min_timestamp) {
					del_addrs_list[del_addrs_count] = astats[i].pfras_a;
					del_addrs_list[del_addrs_count].pfra_fback = 0;
					del_addrs_count++;
				}
			}

			if (del_addrs_count > 0) {
				del_addrs_result = radix_del_addrs(local_dev, &target, del_addrs_list, del_addrs_count, flags);
				free(del_addrs_list);
			}
			free(astats);
		}
		else if (astats_count == 0) {
			free(astats);
		}

		sleep(60);
	}
}

void
s2c_spawn_thread(void *(*func) (void *), void *data)
{
	pthread_t *thr;
	pthread_attr_t *attr;
 
	thr = (pthread_t *)malloc(sizeof(pthread_t));
	attr = (pthread_attr_t *)malloc(sizeof(pthread_attr_t));
 
	memset(thr, 0x00, sizeof(pthread_t));
	memset(attr, 0x00, sizeof(pthread_attr_t));
 
	if(pthread_attr_init(attr)) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to init detached thread attributes - warning");
 
	} else if(pthread_attr_setdetachstate(attr, PTHREAD_CREATE_DETACHED)) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to set detached thread attributes - warning");
 
	} else if(pthread_create(thr, attr, func, data))
		syslog(LOG_ERR | LOG_DAEMON, "unable to launch detached thread - warning");

	free(attr);
	free(thr);
	return;
}

int 
s2c_pf_block(int dev, char *tablename, char *ip) 
{ 
	struct pfioc_table *io;
	struct pfr_table *table;
	struct pfr_addr *addr;
	struct in_addr *net_addr;

	io = (struct pfioc_table *)malloc(sizeof(struct pfioc_table));
	table = (struct pfr_table *)malloc(sizeof(struct pfr_table));
	addr = (struct pfr_addr *)malloc(sizeof(struct pfr_addr));
	net_addr = (struct in_addr *)malloc(sizeof(struct in_addr));

	memset(io,    0x00, sizeof(struct pfioc_table)); 
	memset(table, 0x00, sizeof(struct pfr_table)); 
	memset(addr,  0x00, sizeof(struct pfr_addr));
	memset(net_addr,  0x00, sizeof(struct in_addr));

	memcpy(table->pfrt_name, tablename, PF_TABLE_NAME_SIZE); 
	inet_aton(ip, (struct in_addr *)net_addr);
	memcpy(&addr->pfra_ip4addr.s_addr, net_addr, sizeof(struct in_addr));

	addr->pfra_af  = AF_INET;
	addr->pfra_net = 32; 

	io->pfrio_table  = *table; 
	io->pfrio_buffer = addr; 
	io->pfrio_esize  = sizeof(struct pfr_addr); 
	io->pfrio_size   = 1; 

	if (ioctl(dev, DIOCRADDADDRS, io)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRADDADDRS - ioctl error - exit");
		s2c_exit_fail();
	}

	free(io);
	free(table);
	free(addr);
	free(net_addr);

	return(0);
}

void
s2c_pf_block_log_check()
{
	int threadcheck = 0;

	pthread_mutex_lock(&thr_mutex);
	threadcheck = s2c_threads;
	pthread_mutex_unlock(&thr_mutex);

	while(!(threadcheck < THRMAX)){
		sleep(10);
		pthread_mutex_lock(&thr_mutex);
		threadcheck = s2c_threads;
		pthread_mutex_unlock(&thr_mutex);  
	}

	return;
}

void
*s2c_pf_block_log(void *arg)
{
	char *message;
	char *local_logip;
	char *local_logfile;
	char *hbuf;
	long timebuf = 0;
	int gni_error = 0;
	FILE *lfile = NULL;
	struct sockaddr sa;
	struct sockaddr_in *sin;
	struct thread_log_t *data = (struct thread_log_t *)arg;

	message = (char *)malloc(sizeof(char)*LISTMAX);
	local_logip = (char *)malloc(sizeof(char)*LISTMAX);
	local_logfile = (char *)malloc(sizeof(char)*LISTMAX);
	hbuf = (char *)malloc(sizeof(char)*NI_MAXHOST);

	bzero(message, LISTMAX);
	bzero(hbuf, NI_MAXHOST);
	bzero(local_logip, LISTMAX);
	bzero(local_logfile, LISTMAX);
	memset(&sa, 0x00, sizeof(struct sockaddr_in));

	memcpy(local_logip, data->logip, LISTMAX);
	memcpy(local_logfile, data->logfile, LISTMAX);

	timebuf = time(NULL);

	sa.sa_family = AF_INET;
	sin = (struct sockaddr_in *) &sa;

	if(inet_pton(AF_INET, local_logip, &((struct sockaddr_in *)&sa)->sin_addr)) {

		pthread_mutex_lock(&dns_mutex);
		gni_error = getnameinfo(&sa, sizeof(sa), hbuf, sizeof(char)*NI_MAXHOST, NULL, 0, NI_NAMEREQD);
		pthread_mutex_unlock(&dns_mutex);

		if (gni_error != 0)
			strlcpy(hbuf, gai_strerror(gni_error), NI_MAXHOST);
	}

	sprintf(message, "%s (%s) not whitelisted, added to block table %s", local_logip, hbuf, asctime(localtime(&timebuf)));

	lfile = fopen(local_logfile, "a");
	flockfile(lfile);
	fputs(message, lfile);
	funlockfile(lfile);
	fclose(lfile);

	free(arg);
	free(hbuf);
	free(message);
	free(local_logip);
	free(local_logfile);

	pthread_mutex_lock(&thr_mutex);
	s2c_threads--;
	pthread_mutex_unlock(&thr_mutex);

	pthread_exit(NULL);
}

int 
s2c_pf_tbladd(int dev, char * tablename) 
{
	struct pfioc_table *io;
	struct pfr_table *table;

	io = (struct pfioc_table *)malloc(sizeof(struct pfioc_table));
	table = (struct pfr_table *)malloc(sizeof(struct pfr_table));

	memset(io,    0x00, sizeof(struct pfioc_table));
	memset(table, 0x00, sizeof(struct pfr_table));

	memcpy(table->pfrt_name, tablename, PF_TABLE_NAME_SIZE);
	table->pfrt_flags = PFR_TFLAG_PERSIST;

	io->pfrio_buffer = table; 
	io->pfrio_esize  = sizeof(struct pfr_table); 
	io->pfrio_size   = 1; 

	if (ioctl(dev, DIOCRADDTABLES, io)) { 
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRADDTABLES - ioctl error - exit");
		return(1);
	}

	free(io);
	free(table);
	return(0); 
}

int
s2c_pf_ruleadd(int dev, char *tablename)
{
	struct pfioc_rule *io_rule;
	struct pfioc_pooladdr *io_paddr;

	io_rule = (struct pfioc_rule *)malloc(sizeof(struct pfioc_rule));
	io_paddr = (struct pfioc_pooladdr *)malloc(sizeof(struct pfioc_pooladdr));

	memset(io_rule,  0x00, sizeof(struct pfioc_rule));
	memset(io_paddr, 0x00, sizeof(struct pfioc_pooladdr));

	if(!s2c_pf_intbl(dev, tablename))
		if(s2c_pf_tbladd(dev, tablename))
			return(1);

	io_rule->rule.direction = PF_IN;
	io_rule->rule.action = PF_DROP;
	io_rule->rule.src.addr.type = PF_ADDR_TABLE;
	io_rule->rule.rule_flag = PFRULE_RETURN;
	memcpy(io_rule->rule.src.addr.v.tblname, tablename, sizeof(io_rule->rule.src.addr.v.tblname));

	io_rule->action = PF_CHANGE_GET_TICKET;

	if (ioctl(dev, DIOCCHANGERULE, io_rule)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCCHANGERULE - ioctl error - exit");
		s2c_exit_fail();
	}	

	if (ioctl(dev, DIOCBEGINADDRS, io_paddr)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCBEGINADDRS - ioctl error - exit");
		s2c_exit_fail();
	}

	io_rule->pool_ticket = io_paddr->ticket;
	io_rule->action = PF_CHANGE_ADD_TAIL;

	if (ioctl(dev, DIOCCHANGERULE, io_rule)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCCHANGERULE - ioctl error - exit");
		s2c_exit_fail();
	}

	free(io_rule);
	free(io_paddr);

	return(0);
}

int 
s2c_pf_intbl(int dev, char *tablename)
{
	int i;
	struct pfioc_table *io;
	struct pfr_table *table_aux = NULL;

	io = (struct pfioc_table *)malloc(sizeof(struct pfioc_table));
	
	memset(io, 0x00, sizeof(struct pfioc_table));
	
	io->pfrio_buffer = table_aux;
	io->pfrio_esize  = sizeof(struct pfr_table);
	io->pfrio_size   = 0;
	
	if(ioctl(dev, DIOCRGETTABLES, io)) { 
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRGETTABLES - ioctl error - exit");
		s2c_exit_fail();
	}
	
	table_aux = (struct pfr_table *)malloc(sizeof(struct pfr_table)*io->pfrio_size);
	if(table_aux == NULL){
		syslog(LOG_DAEMON | LOG_ERR, "malloc error B02 - exit");
		s2c_exit_fail();
	}

	io->pfrio_buffer = table_aux;
	io->pfrio_esize = sizeof(struct pfr_table);

	if(ioctl(dev, DIOCRGETTABLES, io)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRGETTABLES - ioctl error - exit");
		s2c_exit_fail();
	}

	for(i=0; i< io->pfrio_size; i++) {
		if (!strcmp(table_aux[i].pfrt_name, tablename)){
			free(table_aux);
			free(io);
			return(1);
		}
	}

	free(table_aux);
	free(io);

	return(0);
}
