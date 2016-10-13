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


#ifndef _PARSER_H_
#define _PARSER_H_

#include "defdata.h"

int	s2c_parse_ip(char *, char *);
int	s2c_parse_priority(int, char *);
int	s2c_parse_line(char *, FILE *);
int	s2c_parse_and_block_blisted(char *, struct blist_head *);
void	s2c_parse_and_block(int, int, char *, char *, char *, struct wlist_head *, struct blist_head *);
int	s2c_parse_load_bl(int, char *, char *, struct wlist_head *);
int	s2c_parse_load_wl(char *, char *, struct wlist_head *);
int	s2c_parse_load_wl_file(char *, struct ipwlist *);
void	s2c_parse_load_wl_ifaces(struct ipwlist *);
int	s2c_parse_search_wl(char *, struct wlist_head *);

#endif /* _PARSER_H */

