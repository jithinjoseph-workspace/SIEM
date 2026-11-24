module ARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:        time    &log;
        operation: string  &log;
        src_mac:   string  &log;
        dst_mac:   string  &log;
        src_ip:    addr    &log;
        dst_ip:    addr    &log;
    };
}

event zeek_init() &priority=5
{
    Log::create_stream(ARP::LOG, [$columns=Info, $path="arp"]);
}

event arp_request(mac_src: string, mac_dst: string,
                  SPA: addr, SHA: string,
                  TPA: addr, THA: string)
{
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "request",
        $src_mac   = SHA,
        $dst_mac   = mac_dst,
        $src_ip    = SPA,
        $dst_ip    = TPA
    ));
}

event arp_reply(mac_src: string, mac_dst: string,
                SPA: addr, SHA: string,
                TPA: addr, THA: string)
{
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "reply",
        $src_mac   = SHA,
        $dst_mac   = THA,
        $src_ip    = SPA,
        $dst_ip    = TPA
    ));
}
