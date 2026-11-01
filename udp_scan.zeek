@load base/frameworks/notice

module NmapUDP;

export {
    redef enum Notice::Type += { Scan };

    const threshold: count = 20 &redef;
}

global probed: table[addr] of set[port] &create_expire=1min;

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
        delete probed[src];
        }
    }
