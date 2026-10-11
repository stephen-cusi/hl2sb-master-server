"""hl2sb fake master server + fake game servers (nosteam).

The fork's engine speaks its own master protocol (engine/masterserver.cpp,
common/proto_oob.h).  Every packet carries the 0xFFFFFFFF connectionless
header - the engine's receive dispatcher (net_ws) drops anything else, and
the engine prefixes it on all outgoing master packets:

  server ->  0xFFFFFFFF 'w' + i32 clientchallenge          S2M_GETCHALLENGE
  master ->  0xFFFFFFFF 'x' + i32 challenge + i32 echo     M2S_CHALLENGE
             (echo must equal the clientchallenge the server sent; the first
              long is what the server carries in every later heartbeat)
  server ->  0xFFFFFFFF 'y' + i32 challenge + u16 proto + z gamedir
                                                           S2M_HEARTBEAT
  server ->  0xFFFFFFFF 'z'                                S2M_SHUTDOWN
  client ->  0xFFFFFFFF '1' + z gamedir                    C2M_CLIENTQUERY
  master ->  0xFFFFFFFF 'J' + (ip, port)* + 6x00           M2C_QUERY
  client ->  0xFFFFFFFF 'v' + i32 seq                      C2S_INFOREQUEST
  server ->  0xFFFFFFFF 'K' + i32 seq + u8 proto + z name
              + z map + z gamedir + z description
              + u8 players + u8 maxplayers + u8 bots
              + u8 password + u32 flags + [z tags]         S2C_INFOREPLY
  client ->  0xFFFFFFFF 'p' + i32 seq                      C2S_PLAYERREQUEST
  server ->  0xFFFFFFFF 'O' + i32 seq + u8 count
              + per player {u8 index, z name, i32 score, f32 duration}
                                                           S2C_PLAYERREPLY

'p'/'O' are a fork extension: the info reply carries no player list, so the
game info dialog asks the server for one explicitly.

'J' entry encoding, derived from netadr_t (tier1/NetAdr.cpp):
  ip   - the four octets in reverse order: the engine does ReadLong (little
         endian) then SetIP() which stores the value byteswapped into the
         network-order ip[] array, so the wire form is inet_aton reversed
  port - little endian u16: engine ReadShort then SetPort() BigShorts it
         into the network-order port field

Old engine builds sent 'w'/'y'/'1' without the header; the master still
accepts the bare opcode form and says so in the log.  Heartbeat challenges
are validated when a session exists but never cause a rejection: a
self-hosted master on a trusted LAN gains nothing from strictness and a
friend's server must register on the first try.

Run it on any host both clients and servers can reach, then point every
install at it with cfg/masterservers.txt (one "ip:port" per line):

    python tools/hl2sb_master.py --fake 0.0.0.0 27010 <advertise ip>

Defaults: bind 0.0.0.0:27010.  --fake also answers the browser's per-server
info and player queries on ports 27100+, so the internet tab populates with
live rows without any real game running there (connecting to one will fail).
The fake servers are simulated: players join and leave, scores creep up,
maps rotate and every reply is delayed by the server's configured base ping
(+ jitter) so the browser shows varied realistic latencies.  Real fork
servers register themselves through the 'w'/'x'/'y' handshake above and are
forgotten after SERVER_TIMEOUT seconds without a heartbeat.

--selftest replays the exact engine wire behaviour against itself.
"""

import random
import socket
import struct
import sys
import threading
import time

SERVER_TIMEOUT = 300.0
CHALLENGE_TIMEOUT = 600.0  # engine re-heartbeats every ~140 s with the same challenge
CONNECTIONLESS = 0xFFFFFFFF
CONNECTIONLESS_HEADER = struct.pack("<I", CONNECTIONLESS)
PROTOCOL_VERSION = 24

S2M_GETCHALLENGE = b"w"
M2S_CHALLENGE = b"x"
S2M_HEARTBEAT = b"y"
S2M_SHUTDOWN = b"z"
C2M_CLIENTQUERY = b"1"
M2C_QUERY = b"J"
C2S_INFOREQUEST = b"v"
S2C_INFOREPLY = b"K"
C2S_PLAYERREQUEST = b"p"
S2C_PLAYERREPLY = b"O"

# --fake seeds these: the master also answers the browser's per-server info
# and player queries on each port, so the internet tab populates with live
# test rows even though no real game runs there.  Connecting to one will
# fail - they only exist to exercise the browser UI.  The last field is the
# artificial base ping in milliseconds (the browser measures the real round
# trip, so the delay applied to our replies shows up as that server's ping).
FAKE_SERVERS = [
    # (port, name, map, gamedir, desc, players, maxplayers, bots, password, tv, tags, base ping)
    (27100, "[CN]hl2sb 沙盒建造服", "gm_construct", "hl2sb", "Sandbox", 3, 8, 0, 0, 0, "sandbox,build", 12),
    (27101, "Half-Life 2 Box Official #1", "gm_flatgrass", "hl2sb", "Sandbox", 0, 16, 0, 0, 0, "", 35),
    (27102, "[测试]假服务器 Alpha", "gm_construct", "hl2sb", "Sandbox", 7, 10, 1, 0, 0, "test,fake", 8),
    (27103, "带密码的服务器", "gm_flatgrass", "hl2sb", "Sandbox", 2, 4, 0, 1, 0, "private", 75),
    (27104, "观看测试 TV", "gm_construct", "hl2sb", "Sandbox", 1, 8, 0, 0, 1, "tv", 110),
    (27105, "满员服务器", "gm_flatgrass", "hl2sb", "Sandbox", 16, 16, 0, 0, 0, "full", 22),
]

PLAYER_NAMES = [
    "小明", "Killer", "一刀999", "Builder_Bob", "老王", "NoobMaster",
    "小美", "Gordon", "ProBuilder_99", "Alyx", "拖更怪", "Barney",
    "萌新驾到", "xX_Sniper_Xx", "建筑业大亨", "Freeman", "夜行者",
    "CrabKing", "坏掉的狗", "Headcrab_Hat",
]
MAP_POOL = ["gm_construct", "gm_flatgrass", "gm_bigcity", "gm_boulder", "gm_genesis"]

g_challenges = {}   # (ip, port) -> (issued challenge, time)
g_servers = {}      # (ip, port) -> [gamedir, last_heartbeat]
g_sim = {}          # port -> {"players": [{name, score, joined}], "map": str}
g_sim_targets = {}  # port -> population the sim drifts around
g_used_names = set()


def log(addr, what):
    print("[%s] %s:%d %s" % (time.strftime("%H:%M:%S"), addr[0], addr[1], what), flush=True)


def hexs(data, limit=48):
    head = " ".join("%02x" % b for b in data[:limit])
    return head + (" ..." if len(data) > limit else "")


def read_zstring(buf, offset):
    end = buf.find(b"\x00", offset)
    if end < 0:
        return None, offset
    return buf[offset:end], end + 1


def split_packet(data):
    """Return (cmd, rest, bare) or None.

    Accepts both the headered form (engine convention) and the legacy bare
    opcode form old engine builds sent for 'w'/'y'/'1'.
    """
    if data and data[:4] == CONNECTIONLESS_HEADER:
        if len(data) < 5:
            return None
        return data[4:5], data[5:], False
    if data:
        return data[:1], data[1:], True
    return None


def entry_wire(ip, port):
    """One 6-byte M2C_QUERY entry the way the engine's netadr_t parses it."""
    return socket.inet_aton(ip)[::-1] + struct.pack("<H", port)


def new_name():
    if len(g_used_names) >= len(PLAYER_NAMES):
        # pool exhausted: recycle with a numeric suffix
        base = random.choice(PLAYER_NAMES)
        name = "%s%d" % (base, random.randint(2, 999))
    else:
        name = random.choice([n for n in PLAYER_NAMES if n not in g_used_names])
    g_used_names.add(name)
    return name


def seed_sim():
    for entry in FAKE_SERVERS:
        port, mapname, players = entry[0], entry[2], entry[5]
        g_sim_targets[port] = players
        roster = []
        for _ in range(players):
            roster.append({
                "name": new_name(),
                "score": random.randint(0, 40),
                "joined": time.time() - random.randint(60, 7200),
            })
        g_sim[port] = {"players": roster, "map": mapname}


def tick_sim():
    """One simulation step per second.  Every server drifts around a target
    population (which itself wanders), joins/leaves push the roster toward it
    and scores creep up, so the browser always shows lively, changing rows."""
    for entry in FAKE_SERVERS:
        port, maxplayers, bots = entry[0], entry[6], entry[7]
        sim = g_sim[port]
        roster = sim["players"]
        capacity = maxplayers - bots

        if random.random() < 0.08:
            g_sim_targets[port] = max(0, min(capacity,
                g_sim_targets[port] + random.choice((-2, -1, 1, 1, 2))))

        target = g_sim_targets[port]
        while len(roster) < target and random.random() < 0.7:
            player = {"name": new_name(), "score": 0, "joined": time.time()}
            roster.append(player)
            log(("sim", port), "join %r (%d/%d)" % (player["name"], len(roster) + bots, maxplayers))
        while len(roster) > target and random.random() < 0.6:
            player = roster.pop(random.randrange(len(roster)))
            g_used_names.discard(player["name"])
            log(("sim", port), "quit %r (%d/%d)" % (player["name"], len(roster) + bots, maxplayers))

        for player in roster:
            if random.random() < 0.3:
                player["score"] += random.randint(1, 3)

        if random.random() < 0.0015:
            candidates = [m for m in MAP_POOL if m != sim["map"]]
            sim["map"] = random.choice(candidates)
            log(("sim", port), "map changed to %s" % sim["map"])


def delayed_send(sock, data, addr, base_ping_ms):
    """Reply after the server's base ping + jitter; the browser measures this
    as the row's latency."""
    delay = (base_ping_ms * random.uniform(0.7, 1.3) + random.uniform(0, 6)) / 1000.0
    if delay < 0.002:
        sock.sendto(data, addr)
        return
    timer = threading.Timer(delay, lambda: _safe_send(sock, data, addr))
    timer.daemon = True
    timer.start()


def _safe_send(sock, data, addr):
    try:
        sock.sendto(data, addr)
    except OSError:
        pass


def handle_packet(data, addr, sock):
    parsed = split_packet(data)
    if parsed is None:
        return
    cmd, rest, bare = parsed
    log(addr, "cmd=%r %s len=%d wire=%s"
        % (cmd, "bare" if bare else "hdr", len(data), hexs(data)))
    now = time.time()

    if cmd == S2M_GETCHALLENGE and len(rest) >= 4:
        (client_challenge,) = struct.unpack_from("<i", rest, 0)
        challenge = random.randint(1, 0x7FFFFFF0)
        g_challenges[addr] = (challenge, now)
        sock.sendto(CONNECTIONLESS_HEADER + M2S_CHALLENGE +
                    struct.pack("<ii", challenge, client_challenge), addr)
        log(addr, "challenge %d issued (echo %d)" % (challenge, client_challenge))
        return

    if cmd == S2M_HEARTBEAT:
        gamedir = None
        if len(rest) >= 6:
            (challenge,) = struct.unpack_from("<i", rest, 0)
            gamedir, _ = read_zstring(rest, 6)
            expected = g_challenges.get(addr)
            if not expected or now - expected[1] > CHALLENGE_TIMEOUT:
                log(addr, "heartbeat accepted (no challenge session; challenge %d)" % challenge)
            elif challenge != expected[0]:
                log(addr, "heartbeat accepted (challenge mismatch: got %d, issued %d)"
                    % (challenge, expected[0]))
            else:
                log(addr, "heartbeat challenge ok")
        if gamedir:
            g_servers[addr] = [gamedir.decode("utf-8", "replace"), now]
            log(addr, "heartbeat: gamedir=%r (%d known)" % (gamedir, len(g_servers)))
        else:
            log(addr, "heartbeat rejected (truncated)")
        return

    if cmd == S2M_SHUTDOWN:
        if g_servers.pop(addr, None) is not None:
            log(addr, "shutdown: removed from list")
        else:
            log(addr, "shutdown: was not listed")
        return

    if cmd == C2M_CLIENTQUERY:
        gamedir, _ = read_zstring(rest, 0)
        if gamedir is None:
            log(addr, "client query without gamedir terminator")
            return
        wanted = gamedir.decode("utf-8", "replace")
        out = [CONNECTIONLESS_HEADER + M2C_QUERY]
        n = 0
        for (sip, sport), (sgamedir, seen) in list(g_servers.items()):
            if now - seen > SERVER_TIMEOUT:
                del g_servers[(sip, sport)]
                continue
            if sgamedir != wanted:
                continue
            out.append(entry_wire(sip, sport))
            n += 1
        out.append(b"\x00" * 6)
        sock.sendto(b"".join(out), addr)
        log(addr, "query gamedir=%r -> %d servers" % (wanted, n))
        return

    log(addr, "unknown/ignored cmd")


def fake_info_reply(seq, entry):
    """S2C_INFOREPLY, field-for-field what CMaster::ProcessInfo reads."""
    port, name, gamedir, desc = entry[0], entry[1], entry[3], entry[4]
    maxplayers, bots, password, tv, tags = entry[6], entry[7], entry[8], entry[9], entry[10]
    sim = g_sim[port]
    players = len(sim["players"])
    mapname = sim["map"]
    flags = 0
    if tv:
        flags |= 0x02
    if tags:
        flags |= 0x01
    out = CONNECTIONLESS_HEADER + S2C_INFOREPLY + struct.pack("<I", seq)
    out += struct.pack("<B", PROTOCOL_VERSION)
    out += name.encode("utf-8") + b"\x00"
    out += mapname.encode("utf-8") + b"\x00"
    out += gamedir.encode("utf-8") + b"\x00"
    out += desc.encode("utf-8") + b"\x00"
    out += struct.pack("<BBB", players, maxplayers, bots)
    out += struct.pack("<B", password)
    out += struct.pack("<I", flags)
    if tags:
        out += tags.encode("utf-8") + b"\x00"
    return out


def fake_player_reply(seq, entry):
    """S2C_PLAYERREPLY, what CMaster's player-list case reads."""
    sim = g_sim[entry[0]]
    roster = sim["players"]
    out = CONNECTIONLESS_HEADER + S2C_PLAYERREPLY + struct.pack("<I", seq)
    out += struct.pack("<B", min(len(roster), 255))
    for i, player in enumerate(roster):
        out += struct.pack("<B", i)
        out += player["name"].encode("utf-8") + b"\x00"
        out += struct.pack("<i", int(player["score"]))
        out += struct.pack("<f", time.time() - player["joined"])
    return out


def handle_fake_packet(data, entry, sock, addr):
    parsed = split_packet(data)
    if parsed is None:
        return
    cmd, rest, bare = parsed
    if len(rest) < 4:
        log(addr, "fake %d: truncated cmd=%r" % (entry[0], cmd))
        return
    (seq,) = struct.unpack_from("<I", rest, 0)
    ping = entry[11]
    if cmd == C2S_INFOREQUEST:
        delayed_send(sock, fake_info_reply(seq, entry), addr, ping)
        log(addr, "fake %d: info reply seq=%d (ping ~%dms)" % (entry[0], seq, ping))
        return
    if cmd == C2S_PLAYERREQUEST:
        delayed_send(sock, fake_player_reply(seq, entry), addr, ping)
        log(addr, "fake %d: player reply seq=%d" % (entry[0], seq))
        return
    log(addr, "fake %d: ignoring cmd=%r" % (entry[0], cmd))


def fake_pump(sock, entry):
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except OSError:
            return
        try:
            handle_fake_packet(data, entry, sock, addr)
        except Exception as exc:
            log(addr, "fake %d handler error: %s" % (entry[0], exc))


def serve(bind_ip, bind_port, fake=False, advertise_ip=None):
    import select

    # advertise_ip is what the master hands out for the fake servers; never
    # use 127.0.0.1 here - the engine loops back packets addressed to
    # localhost inside the process and they never reach the network.
    if advertise_ip is None:
        advertise_ip = bind_ip if bind_ip != "0.0.0.0" else "127.0.0.1"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, bind_port))
    sockets = [sock]
    fake_by_sock = {}

    if fake:
        seed_sim()
        for entry in FAKE_SERVERS:
            fport = entry[0]
            fs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            fs.bind(("0.0.0.0", fport))
            sockets.append(fs)
            fake_by_sock[fs] = entry
            # list the fake in the master query results too; the far-future
            # timestamp keeps the SERVER_TIMEOUT purge from dropping them
            g_servers[(advertise_ip, fport)] = [entry[3], time.time() + (1 << 30)]
        print("fake servers: %s" % ", ".join("%s:%d ping~%dms" % (advertise_ip, e[0], e[11]) for e in FAKE_SERVERS), flush=True)

    print("hl2sb master listening on %s:%d" % (bind_ip, bind_port), flush=True)
    while True:
        readable, _, _ = select.select(sockets, [], [], 1.0)
        for s in readable:
            data, addr = s.recvfrom(2048)
            try:
                if s is sock:
                    handle_packet(data, addr, sock)
                else:
                    handle_fake_packet(data, fake_by_sock[s], s, addr)
            except Exception as exc:
                log(addr, "handler error: %s" % exc)
        if fake:
            tick_sim()


def selftest():
    """Replay the engine's exact wire behaviour against a live master in this
    process and verify every reply parses the way the engine would."""
    port = 27999
    threading.Thread(target=serve, args=("127.0.0.1", port), daemon=True).start()
    time.sleep(0.3)

    # stand-in for the game server socket (heartbeats), like NS_SERVER
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.bind(("127.0.0.1", 27998))

    # S2M_GETCHALLENGE: header + 'w' + i32 clientchallenge
    client_challenge = 0x12345678
    s.sendto(CONNECTIONLESS_HEADER + S2M_GETCHALLENGE +
             struct.pack("<i", client_challenge), ("127.0.0.1", port))
    data, _ = s.recvfrom(1024)
    assert data[:5] == CONNECTIONLESS_HEADER + M2S_CHALLENGE, data
    master_challenge, echo = struct.unpack_from("<ii", data, 5)
    assert echo == client_challenge, (echo, client_challenge)
    print("challenge round trip OK (master issued %d, echoed %d)" % (master_challenge, echo))

    # S2M_HEARTBEAT: header + 'y' + i32 challenge + u16 proto + z gamedir
    s.sendto(CONNECTIONLESS_HEADER + S2M_HEARTBEAT +
             struct.pack("<i", master_challenge) + struct.pack("<H", 24) +
             b"hl2sb\x00", ("127.0.0.1", port))
    time.sleep(0.2)

    # C2M_CLIENTQUERY, headered (current engine) and bare (old builds): both
    # must yield the same M2C_QUERY reply
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(2.0)
    for form, payload in (("hdr", CONNECTIONLESS_HEADER + C2M_CLIENTQUERY + b"hl2sb\x00"),
                          ("bare", C2M_CLIENTQUERY + b"hl2sb\x00")):
        c.sendto(payload, ("127.0.0.1", port))
        data, _ = c.recvfrom(4096)
        assert data[:5] == CONNECTIONLESS_HEADER + M2C_QUERY, (form, data)
        body = data[5:]
        (unIP,) = struct.unpack_from("<I", body, 0)
        (rport,) = struct.unpack_from("<H", body, 4)
        # engine: netadr_t(ReadLong LE, ReadShort LE) - SetIP() BigLongs into
        # the network-order ip[] array, SetPort() BigShorts the port field
        stored_ip = struct.pack("<I", struct.unpack(">I", struct.pack("<I", unIP))[0])
        assert stored_ip == socket.inet_aton("127.0.0.1"), (form, stored_ip)
        assert rport == 27998, (form, rport)
        assert body[6:12] == b"\x00" * 6, (form, body[6:12])
        print("query round trip OK (%s): listed 127.0.0.1:%d" % (form, rport))

    # C2S_INFOREQUEST + C2S_PLAYERREQUEST against a standalone fake server on
    # an isolated port; the 'O' reply must parse exactly like CMaster does
    fentry = (27997, "[测试]selftest", "gm_selftest", "hl2sb", "Sandbox", 2, 4, 0, 0, 0, "selftest", 5)
    seed_sim()
    g_sim[fentry[0]] = {
        "players": [
            {"name": "小明", "score": 12, "joined": time.time() - 90},
            {"name": "Killer", "score": 3, "joined": time.time() - 15},
        ],
        "map": "gm_selftest",
    }
    fs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    fs.bind(("127.0.0.1", fentry[0]))
    threading.Thread(target=fake_pump, args=(fs, fentry), daemon=True).start()

    f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    f.settimeout(2.0)
    seq = 77
    f.sendto(CONNECTIONLESS_HEADER + C2S_INFOREQUEST + struct.pack("<I", seq),
             ("127.0.0.1", fentry[0]))
    data, _ = f.recvfrom(4096)
    assert data[:5] == CONNECTIONLESS_HEADER + S2C_INFOREPLY, data
    (rseq,) = struct.unpack_from("<I", data, 5)
    assert rseq == seq, (rseq, seq)
    proto = data[9]
    off = 10
    strings = []
    for _ in range(4):
        v, off = read_zstring(data, off)
        strings.append(v)
    players, maxplayers, bots, password = struct.unpack_from("<BBBB", data, off)
    off += 4
    (flags,) = struct.unpack_from("<I", data, off)
    off += 4
    tags = None
    if flags & 0x01:
        tags, off = read_zstring(data, off)
    assert proto == PROTOCOL_VERSION, proto
    assert strings[2] == b"hl2sb" and fentry[1].encode("utf-8") in strings[0], strings
    assert (players, maxplayers) == (2, 4), (players, maxplayers)
    assert flags & 0x01 and tags == fentry[10].encode("utf-8"), (flags, tags)
    print("info reply OK: name=%r map=%r players=%d/%d tags=%r"
          % (strings[0].decode(), strings[1].decode(), players, maxplayers, tags.decode()))

    seq = 78
    f.sendto(CONNECTIONLESS_HEADER + C2S_PLAYERREQUEST + struct.pack("<I", seq),
             ("127.0.0.1", fentry[0]))
    data, _ = f.recvfrom(4096)
    assert data[:5] == CONNECTIONLESS_HEADER + S2C_PLAYERREPLY, data
    (rseq,) = struct.unpack_from("<I", data, 5)
    assert rseq == seq, (rseq, seq)
    count = data[9]
    off = 10
    names = []
    for _ in range(count):
        idx = data[off]
        off += 1
        name, off = read_zstring(data, off)
        score, duration = struct.unpack_from("<if", data, off)
        off += 8
        names.append(name.decode())
        assert 0.0 <= duration < 7200
    assert count == 2 and names == ["小明", "Killer"], (count, names)
    print("player reply OK: %r" % (names,))
    print("selftest PASS")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        bind_ip = "0.0.0.0"
        advertise_ip = None
        ips = [a for a in sys.argv[1:] if a.count(".") == 3]
        if len(ips) >= 1:
            bind_ip = ips[0]
        if len(ips) >= 2:
            advertise_ip = ips[1]
        fake = "--fake" in sys.argv
        bind_port = 27010
        for a in sys.argv[1:]:
            if a.isdigit():
                bind_port = int(a)
        serve(bind_ip, bind_port, fake, advertise_ip)
