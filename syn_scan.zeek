##! Detects Nmap SYN scans (-sS).
##! A SYN scan to an open port shows up in Zeek as history "ShR":
##! SYN, SYN-ACK from the target, then RST from the scanner.
@load base/frameworks/notice

module NmapSYN;

export {
    redef enum Notice::Type += { Scan };

    ## Half-open connections from one source (within 1 minute) before a Notice.
    const threshold: count = 50 &redef;
}

# Counter per source IP; entries expire after 1 minute (the time window).
global half_open: table[addr] of count &default=0 &create_expire=1min;

# Number of Notices raised so far for this scan type.
global previous_notices: count = 0;

event connection_state_remove(c: connection)
    {
    if ( ! c?$conn || ! c$conn?$history )
        return;

    if ( c$conn$proto != tcp || c$conn$history != "ShR" )
        return;

    local src = c$id$orig_h;
    ++half_open[src];

    if ( half_open[src] >= threshold )
        {
        NOTICE([$note=Scan, $src=src, $conn=c,
                $msg=fmt("Nmap SYN scan (-sS) from %s: %d half-open connections within 1 minute. Previous SYN scan Notices: %d",
                         src, half_open[src], previous_notices),
                $suppress_for=0secs]);

        ++previous_notices;
        delete half_open[src];   # start over
        }
    }
