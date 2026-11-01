@load base/frameworks/notice

module NmapConnect;

export {
    redef enum Notice::Type += { Scan };

    const threshold: count = 50 &redef;
}

global connects: table[addr] of count &default=0 &create_expire=1min;

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
        delete connects[src];
        }
    }
