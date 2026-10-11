"""End-to-end probe for tools/hl2sb_master.py.

Replays the exact wire behaviour of the fork engine's server browser query
against a running master + fake servers:

  1. C2M_CLIENTQUERY ('1' + gamedir, connectionless header) to the master
  2. parse the M2C_QUERY ('J') reply like CMaster does (netadr_t semantics)
  3. C2S_INFOREQUEST ('v' + seq) to every listed server
  4. parse the S2C_INFOREPLY ('K') replies like CMaster::ProcessInfo does

Usage: python tools/hl2sb_master_probe.py <master ip> [master port]
"""

import socket
import struct
import sys

HEADER = b"\xff\xff\xff\xff"


def zstr(buf, off):
    end = buf.find(b"\x00", off)
    return buf[off:end], end + 1


def parse_info(data, addr):
    assert data[:5] == HEADER + b"K", data[:16].hex()
    (rseq,) = struct.unpack_from("<I", data, 5)
    proto = data[9]
    off = 10
    strings = []
    for _ in range(4):
        v, off = zstr(data, off)
        strings.append(v)
    players, maxp, bots, pw = struct.unpack_from("<BBBB", data, off)
    off += 4
    (flags,) = struct.unpack_from("<I", data, off)
    off += 4
    tags = b""
    if flags & 1:
        tags, off = zstr(data, off)
    return rseq, proto, strings, players, maxp, bots, pw, tags


def main():
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 27010
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(HEADER + b"1" + b"hl2sb\x00", (ip, port))
    data, frm = s.recvfrom(8192)
    print("master reply from %s:%d len=%d" % (frm[0], frm[1], len(data)))
    assert data[:5] == HEADER + b"J", data[:16].hex()
    body = data[5:]
    servers = []
    off = 0
    while off + 6 <= len(body):
        (unIP,) = struct.unpack_from("<I", body, off)
        (uport,) = struct.unpack_from("<H", body, off + 4)
        off += 6
        if unIP == 0 and uport == 0:
            break
        # engine: netadr_t(ReadLong LE, ReadShort LE) - SetIP() BigLongs into
        # the network-order ip[] array, SetPort() BigShorts the port field
        ipb = struct.pack("<I", struct.unpack(">I", struct.pack("<I", unIP))[0])
        addr = (socket.inet_ntoa(ipb), uport)
        servers.append(addr)
        print("  listed %s:%d" % addr)
    print("%d server(s) listed" % len(servers))

    ok = 0
    for addr in servers:
        try:
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c.settimeout(2.0)
            seq = 1234
            c.sendto(HEADER + b"v" + struct.pack("<I", seq), addr)
            data, _ = c.recvfrom(4096)
            rseq, proto, strings, players, maxp, bots, pw, tags = parse_info(data, addr)
            assert rseq == seq
            print("  %s:%d proto=%d name=%r map=%r dir=%r %d/%d bots=%d pw=%d tags=%r"
                  % (addr[0], addr[1], proto, strings[0].decode(), strings[1].decode(),
                     strings[2].decode(), players, maxp, bots, pw, tags.decode()))
            ok += 1
            c.close()
        except Exception as exc:
            print("  %s:%d FAILED: %s" % (addr[0], addr[1], exc))
    print("%d/%d info replies parsed" % (ok, len(servers)))
    print("PROBE PASS" if ok == len(servers) and servers else "PROBE FAIL")


if __name__ == "__main__":
    main()
