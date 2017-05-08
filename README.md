# snort2pfcd
v1.9
SNORT2PFCD(8)           FreeBSD System Manager's Manual          SNORT2PFCD(8)

[1mNAME[0m
     [1msnort2pfcd [22m— provides real-time blocking of ip addresses from snort
     alerts via packet filter firewall tables.

[1mSYNOPSIS[0m
     [1msnort2pfcd [22m[[1m-e [4m[22mExternal_Interface[24m] [[1m-w [4m[22mWhitelist_File[24m]
                [[1m-b [4m[22mBlacklist_File[24m] [[1m-W[22m] [[1m-B[22m] [[1m-D[22m] [[1m-l [4m[22mLog_File[24m]
                [[1m-a [4m[22mAlert_File[24m] [[1m-p [4m[22mPriority[24m] [[1m-r [4m[22mRepeat_Offenses[24m]
                [[1m-t [4m[22mSeconds[24m] [[1m-d [4m[22mpf_device[24m] [[1m-m [4m[22mThr_max[24m] [[1m-v[22m] [[1m-h[22m]

[1mDESCRIPTION[0m
     [1msnort2pfcd [22mAnalyzes snort alert output and blocks ip addresses for a
     given snort priority using pf table entries for a specified period of
     time. A whitelist is specified to exclude local and trusted ip address
     from being blocked.  [1msnort2pfcd [22malso preloads the community maintained
     and supplied snort blacklist by default. The whitelist and blacklist
     files are monitored and [1msnort2pfcd [22mautomatically reloads and updates the
     tables when changes are made to the files.

     The options are as follows:

     [1m-e [4m[22mExternal_Interface[0m
             external interface e.g. eth0 or "all" to whitelist all inter‐
             faces, default is to whitelist all interfaces.

     [1m-w [4m[22mWhitelist_File[0m
             whitelist file, default is
             /usr/local/etc/snort/rules/iplists/default.whitelist.

     [1m-W      [22mIf set, will prevent loading of any whitelist file.

     [1m-b [4m[22mBlacklist_File[0m
             blacklist file, default is
             /usr/local/etc/snort/rules/iplists/default.blacklist.

     [1m-B      [22mIf set, will prevent loading of the snort blacklist file.

     [1m-D      [22mIf set, will disable the DNS lookup functionality.

     [1m-l [4m[22mLog_File[0m
             log file, default is /var/log/snort2pfcd.log.

     [1m-a [4m[22mAlert_File[0m
             snort alert file, default is /var/log/snort/alert.

     [1m-p [4m[22mPriority[0m
             The priority level to block ip addresses in snort logs, default
             is 1.  Lower priority includes higher priority, for example, -p 3
             includes priorities 3, 2 and 1.

     [1m-r [4m[22mRepeat_Offenses[0m
             Number of times an ip address may commit a priority p offense
             before being added to pf block table.  Default is 0. For example,
             -p 2 -r 2 specifies that priority 1 or 2 snort alerts will be
             blocked only after 2 repeated snort alerts (3 snort alerts
             total).

     [1m-t [4m[22mSeconds[0m
             The number of seconds to block an ip address, default is 60*60 or
             1 hour.

     [1m-d [4m[22mpf_device[0m
             Packet filter device interface. Default is /dev/pf.

     [1m-m [4m[22mthr_max[0m
             Maximum number of DNS request threads. Default is 100.
             [1msnort2pfcd [22muses a non-blocking design to ensure that waiting for
             DNS names to resolve in the block log do not interere with
             [1msnort2pfcd [22mblocking of snort alerts. Instead of the main program
             waiting, a new thread is spun to do the waiting. Since connection
             speeds vary widely (100mb/s - >40Gb/s) and servers also vary in
             terms of processing capability, the option exists to increase or
             decrease the maximum number of threads waiting for DNS requests.

     [1m-v      [22mIncrease verbosity.

     [1m-h      [22mShow help.

[1mTHEORY OF OPERATION[0m
     The snort intrusion detection system monitors network traffic and will
     generate an alert if this traffic matches a rule for a type of malicious
     activity.  [1msnort2pfcd [22mmonitors this alert file and can then add the
     offending ip address to a pf block table.  [1msnort2pfcd [22mprovides the above
     options for the user to specify the conditions under which the offending
     address is added to the pf block table. Differentiating between benign
     and malicious network traffic is difficult and, unfortunately, snort gen‐
     erates a fair amount of false-positives. One will find that many estab‐
     lished and trusted websites will also produce network traffic that
     appears (or is genuinely) malicious. To assist the user with filtering
     network traffic produced by various network entities, [1msnort2pfcd [22mwill
     automatically resolve the offending ip address and display the DNS name
     in the [1msnort2pfcd [22mblock log. Should the user decide that the offending
     address is trustworthy, the user can add the address, or alternatively,
     research and add the entire CIDR address block assigned to that network
     entity, to the whitelist. Whitelisted addresses or CIDR address blocks
     generating a snort alert will not be added to the packet filter block ta‐
     ble.  [1msnort2pfcd [22malso loads the snort community supplied blacklist file
     into a separate packet filter block table by default. Table entries are
     named "snort2pfcd" for dynamic entries which can be viewed with "pfctl -t
     snort2pfcd -T show". Static entries loaded from the community provided
     snort blacklist are populated within the "snort2pfcd_static" table which
     can be viewed with "pfctl -t snort2pfcd_static -T show".

[1mFILES[0m
     [1mWhitelist[0m
     Whitelist entries can be single ip addressess (e.g. 192.168.0.1) or
     blocks of addresses in CIDR format (e.g. 192.168.0.0/24). Each entry
     should be on a separate line.

     [1mBlacklist[0m
     Blacklist entries provided by the snort community contain a list of sin‐
     gle ip addresses and [1msnort2pfcd [22mwill only accept entries in this format
     (e.g. 192.168.0.1). Each entry should be on a separate line.

[1mNOTES[0m
     While [1msnort2pfcd [22mwill parse the default snort alert file, this can pro‐
     duce less than real-time blocking given the burden being placed on snort
     especially over an active, fast or low latency connection. Would strongly
     recommend using a spooler like barnyard2 to output the text alerts from
     the snort unified2 binary output.

     By default, the user-supplied whitelist is prepended with the addresses
     of all of the local interfaces as the handling of these addresses are
     usually specified by more complex pf rules and simply blocking these
     addresses can cause problems with certain configurations.

     The user-supplied whitelist can also be prepended with the address of the
     external interface only for paranoid configurations. Lo0 is always
     whitelisted.

     [1msnort2pfcd [22malso automatically whitelists addresses found within the
     /etc/resolv.conf file as these addresses should also be handled by spe‐
     cific pf rules.

     A static blacklist table is also maintained and populated within pf with
     the addresses found within the
     /usr/local/etc/snort/rules/iplists/default.blacklist file. These
     addresses can be supplied by the user or automatically populated with
     addresses supplied by the snort community.

[1mCREDITS[0m
     This program is based on snort2c written by Antonio Benojar which was
     based on the original snort2pf perl script written by Stephan Schmieder.
     Expiration of entries use Henrik Gustafsson's expiretable functions.

[1mSEE ALSO[0m
     pf(4), pfctl(8), snort(8), expiretable(1), libcidr(3),

[1mAUTHORS[0m
     Samee Shahzada <onestsam@gmail.com>

                                April 30, 2017
