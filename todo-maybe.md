# netcap — TODO & Roadmap

> A from-scratch packet capture tool in C. Goal: make it genuinely useful and educational.

---

## 🟢 Quick Wins (do these first)

- [ ] **Print timestamp per packet**
    - Already in `pcap_pkthdr->ts` (struct timeval), just format it
    - `strftime()` + `tv_usec` for microsecond precision
    - Ref: [pcap_pkthdr man page](https://www.tcpdump.org/manpages/pcap.3pcap.html)

- [ ] **Print packet length**
    - `header->len` (wire length) and `header->caplen` (captured length)
    - You already have `ip_len` commented out — uncomment + use both

- [ ] **ANSI color output**
    - TCP = blue, UDP = green, ICMP = yellow, unknown = red
    - Ref: [ANSI escape codes](https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797)
    - Disable if stdout is not a TTY: `isatty(STDOUT_FILENO)`

- [ ] **Stats summary on exit (SIGINT)**
    - Total packets, breakdown by protocol, bytes captured
    - Store counters in `callback_data_t`, print in `sigint_handler`

- [ ] **Interactive interface selection**
    - If no `-i` given, list interfaces with `pcap_findalldevs()` and prompt
    - Ref: [pcap_findalldevs man page](https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html)

---

## 🟡 Protocol Dissection

### ARP

- [ ] Parse ARP packets (EtherType 0x0806)
    - Print sender/target MAC and IP
    - Good for detecting ARP spoofing
    - Ref: [ARP packet structure — Wikipedia](https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure)
    - Ref: `<net/if_arp.h>` — `struct arphdr`

### ICMP (extend existing)

- [ ] Map ICMP type/code to human-readable string
    - e.g. type 8 code 0 = "Echo Request", type 3 code 3 = "Port Unreachable"
    - Ref: [ICMP types — IANA](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)

### DNS (highest value)

- [ ] Parse DNS queries and responses over UDP port 53
    - Print: query type (A, AAAA, MX, etc.), queried name, response IPs
    - Parse the wire format yourself — good exercise in bit manipulation
    - Handle compressed labels (pointer format `0xC0xx`)
    - Ref: [RFC 1035 — DNS](https://datatracker.ietf.org/doc/html/rfc1035) (sections 3-4)
    - Ref: [Implement DNS in a weekend](https://implement-dns.wizardzines.com/) ← excellent guide
    - Ref: [DNS wire format explained — Julia Evans](https://jvns.ca/blog/2022/11/06/making-a-dns-query-in-ruby-from-scratch/)

### HTTP

- [ ] Detect HTTP on TCP port 80 (and optionally configurable ports)
    - Extract: method, URL, Host header, response status code
    - Just `strstr()` the payload for `"HTTP/"`, `"GET "`, `"POST "` etc.
    - Ref: [HTTP/1.1 spec — RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230)

### TLS (ClientHello fingerprinting)

- [ ] Parse TLS ClientHello on TCP port 443
    - Extract: SNI (server name), cipher suites list, TLS version
    - No decryption needed — just the handshake metadata
    - Ref: [TLS record format — TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446#section-4)
    - Ref: [Parsing TLS ClientHello — blog post](https://idea.popcount.org/2012-06-16-dissecting-ssl-handshake/)
    - Ref: [JA3 fingerprinting](https://github.com/salesforce/ja3) ← cool follow-on idea

---

## 🟠 IPv6 Support

- [ ] Detect IPv6 (EtherType 0x86DD)
    - Use `struct ip6_hdr` from `<netinet/ip6.h>`
    - Handle extension headers (at least skip them properly)
    - Print src/dst with `inet_ntop()` (already handles both v4 and v6)
    - Ref: [IPv6 header format — RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200#section-3)
    - Ref: [IPv6 extension headers explained](https://www.networkacademy.io/ccnp-encor/ipv6/ipv6-extension-headers)

---

## 🔵 Hex Dump Mode

- [ ] Add `-x` flag for hex + ASCII dump of packet payload
    - Classic `xxd`-style output: offset | hex bytes | ASCII
    - Clamp to first N bytes (configurable, default 64)
    - Ref: [Writing a hex dump in C — example](https://stackoverflow.com/a/7776146)

---

## 🔴 TCP Stream Reassembly (big feature)

This is a proper sub-project. Track TCP connections and reconstruct the byte stream.

- [ ] Connection tracking
    - Key: 4-tuple `(src_ip, src_port, dst_ip, dst_port)`
    - Use a hash map or sorted list of active connections
    - Track sequence numbers, handle SYN/FIN/RST

- [ ] Out-of-order segment buffering
    - Buffer segments that arrive early, insert in order by seq number

- [ ] Payload reconstruction
    - Once contiguous data is available, pass to protocol parser (HTTP etc.)

- [ ] Connection timeout/cleanup
    - Expire stale connections after N seconds

- Ref: [TCP sequence number mechanics — RFC 793](https://datatracker.ietf.org/doc/html/rfc793)
- Ref: [Writing a TCP stack from scratch — saminiir.com](http://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/) ← excellent multi-part series
- Ref: [libnids — existing C library for reassembly, good reference](https://github.com/MITRECND/libnids)

---

## ⚪ Code Quality / Misc

- [ ] Replace `strcpy(pkt_srcip, inet_ntoa(...))` with `inet_ntop()` — cleaner and v6-ready
- [ ] Add `-v` verbose flag (more packet detail) vs default terse output
- [ ] Proper `getopt` or `getopt_long` for argument parsing if not already
- [ ] `pcap_set_buffer_size()` — tunable capture buffer
- [ ] Read from existing `.pcap` file (`-r` flag) with `pcap_open_offline()`
    - Ref: [pcap_open_offline man page](https://www.tcpdump.org/manpages/pcap_open_offline.3pcap.html)
- [ ] Unit tests for protocol parsers (test against known good pcap files)
    - Use Wireshark sample captures: [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures)

---

## 📚 General References

- [tcpdump/libpcap source code](https://github.com/the-tcpdump-group/tcpdump) — best reference for protocol parsing in C
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/) — if any networking concepts feel shaky
- [Julia Evans — networking zines](https://wizardzines.com/) — very readable explanations
- [Wireshark dissector source](https://gitlab.com/wireshark/wireshark/-/tree/master/epan/dissectors) — how the pros do it (C)
- [PacketLife.net cheat sheets](https://packetlife.net/library/cheat-sheets/) — protocol header field references

---

## 🏁 Suggested Order

1. Timestamp + length + colors + stats on exit ← one session
2. Interactive interface selection ← one hour
3. DNS parser ← 2-3 days, most educational
4. IPv6 ← 1 day
5. HTTP parser ← 1 day
6. Hex dump mode ← a few hours
7. TLS ClientHello ← 2 days
8. ARP ← 1 day
9. TCP stream reassembly ← week+, save for last
