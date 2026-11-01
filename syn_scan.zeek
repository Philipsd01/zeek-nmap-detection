@load base/frameworks/notice

module NmapSYN;

export {
    redef enum Notice::Type += { Scan };

    const threshold: count = 50 &redef;
}

global half_open: table[addr] of count &default=0 &create_expire=1min;

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
        delete half_open[src];
        }
    }
