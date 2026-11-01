##! Detects Nmap TCP connect scans (-sT).
##! A connect scan to an open port shows up in Zeek as history "ShAR":
##! SYN, SYN-ACK from the target, ACK (handshake completes), then RST from the scanner.
@load base/frameworks/notice

module NmapConnect;

export {
    redef enum Notice::Type += { Scan };

    ## Completed-then-reset connections from one source (within 1 minute) before a Notice.
    const threshold: count = 50 &redef;
}

# Counter per source IP; entries expire after 1 minute (the time window).
global connects: table[addr] of count &default=0 &create_expire=1min;

# Number of Notices raised so far for this scan type.
global previous_notices: count = 0;

event connection_state_remove(c: connection)
    {
    if ( ! c?$conn || ! c$conn?$history )
        return;

    if ( c$conn$proto != tcp || c$conn$history != "ShAR" )
        return;

    local src = c$id$orig_h;
    ++connects[src];

    if ( connects[src] >= threshold )
        {
        NOTICE([$note=Scan, $src=src, $conn=c,
                $msg=fmt("Nmap connect scan (-sT) from %s: %d full-handshake-then-reset connections within 1 minute. Previous connect scan Notices: %d",
                         src, connects[src], previous_notices),
                $suppress_for=0secs]);

        ++previous_notices;
        delete connects[src];   # start over
        }
    }
