/*
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

#include "defdata.h"

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	unsigned int F = 0, ch = 0, w = 0, b = 0, a = 0, l = 0, e = 0, d = 0, q = 0;
	unsigned long t = 0;
	loopdata_t *loopdata = NULL;

	if ((loopdata = (loopdata_t *)malloc(sizeof(loopdata_t))) == NULL) s2c_malloc_err();
	
	s2c_init(loopdata);

	while ((ch = getopt(argc, argv, "w:p:q:m:r:vWDFBZb:a:l:e:t:d:h")) != -1)
		switch(ch) {

			case 'v': v = 1; break;
			case 'F': F = 1; break;
			case 'W': loopdata->W = 1; break;
			case 'B': loopdata->B = 1; break;
			case 'D': loopdata->D = 1; break;
			case 'Z': loopdata->Z = 1; break;
			case 'd': memcpy(loopdata->nmpfdev, optarg, NMBUFSIZ); d = 1; break;
			case 'a': memcpy(loopdata->alertfile, optarg, NMBUFSIZ); a = 1; break;
			case 'w': memcpy(loopdata->wfile, optarg, NMBUFSIZ); w = 1; break;
			case 'b': memcpy(loopdata->bfile, optarg, NMBUFSIZ); b = 1; break;
			case 'e': memcpy(loopdata->extif, optarg, IFNAMSIZ); e = 1; break;
			case 'l': memcpy(loopdata->logfile, optarg, NMBUFSIZ); l = 1; break;
			case 't': if ((t = optnum("t", optarg)) == -1) usage(); break;
			case 'q': if ((q = optnum("q", optarg)) == -1) usage(); break;
			case 'p':
				if ((loopdata->priority = optnum("p", optarg)) == -1) usage(); 
				if (!loopdata->priority) loopdata->priority = 1; break;
			case 'm':
				if ((loopdata->thr_max = optnum("m", optarg)) == -1) usage();
				if (!loopdata->thr_max) loopdata->thr_max = THRMAX; break;
			case 'r': 
				if ((loopdata->repeat_offenses = optnum("r", optarg)) == -1) usage(); break;
			case 'h': usage();
			case '?': usage();
			default: usage();
		}
	
	argc -= optind;
	argv += optind;

	if (!w) memcpy(loopdata->wfile, PATH_WHITELIST, NMBUFSIZ);
	if (!b) memcpy(loopdata->bfile, PATH_BLACKLIST, NMBUFSIZ);
	if (!a) memcpy(loopdata->alertfile, PATH_ALERT, NMBUFSIZ);
	if (!d) memcpy(loopdata->nmpfdev, PFDEVICE, NMBUFSIZ);
	if (!e) memcpy(loopdata->extif, "all", IFNAMSIZ);
	if (!l) {
		memcpy(loopdata->logfile, PATH_LOG, NMBUFSIZ);
		strlcat(loopdata->logfile,  __progname, NMBUFSIZ);
		strlcat(loopdata->logfile, ".log", NMBUFSIZ);
	}

	if(!F) s2c_daemonize();
	if (q) sleep(q);

        if ((loopdata->dev = open(loopdata->nmpfdev, O_RDWR)) == -1) {
                syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, loopdata->nmpfdev, LANG_EXIT);
                s2c_exit_fail();
        }

	s2c_log_init(loopdata->logfile);
	s2c_thr_init(loopdata);
	s2c_kevent_loop(loopdata);

	close(loopdata->dev);
	free(loopdata);
	closelog();
	return(0);
}
