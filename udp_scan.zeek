##! Detects Nmap UDP scans (-sU).
##! A UDP scan sends datagrams to many different ports and mostly gets no reply,
##! which Zeek records as history "D" (data from originator only).
##! Normal UDP traffic talks to few ports, so we count DIFFERENT destination ports per source.
@load base/frameworks/notice

module NmapUDP;

export {
    redef enum Notice::Type += { Scan };

    ## Different UDP ports probed without reply by one source (within 1 minute) before a Notice.
    const threshold: count = 20 &redef;
}

# Set of probed ports per source IP; entries expire after 1 minute (the time window).
global probed: table[addr] of set[port] &create_expire=1min;

# Number of Notices raised so far for this scan type.
global previous_notices: count = 0;

event connection_state_remove(c: connection)
    {
    if ( ! c?$conn || ! c$conn?$history )
        return;

    if ( c$conn$proto != udp || c$conn$history != "D" )
        return;

    local src = c$id$orig_h;

    if ( src !in probed )
        probed[src] = set();

    add probed[src][c$id$resp_p];

    if ( |probed[src]| >= threshold )
        {
        NOTICE([$note=Scan, $src=src, $conn=c,
                $msg=fmt("Nmap UDP scan (-sU) from %s: %d different UDP ports probed without reply within 1 minute. Previous UDP scan Notices: %d",
                         src, |probed[src]|, previous_notices),
                $suppress_for=0secs]);

        ++previous_notices;
        delete probed[src];   # start over
        }
    }
