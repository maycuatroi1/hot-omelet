#!/usr/bin/env python3
"""
DVRIP (XiongMai "Sofia") client - authorized LAN camera security review.
Tests default/weak credentials and reads device info + account list.
Read-only: no config changes, no reboot, no firmware ops.
"""
import socket, struct, json, hashlib, sys

def sofia_hash(password=""):
    md5 = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(md5[i] + md5[i + 1]) % 62] for i in range(0, 16, 2))

class DVRIP:
    def __init__(self, host, port=34567, timeout=6):
        self.host, self.port, self.timeout = host, port, timeout
        self.session = 0
        self.seq = 0
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)

    def send(self, msgid, payload):
        if isinstance(payload, dict):
            data = json.dumps(payload).encode("utf-8")
        else:
            data = payload
        pkt = struct.pack("BB2xII2xHI", 0xff, 0, self.session, self.seq,
                          msgid, len(data) + 2) + data + b"\x0a\x00"
        self.sock.sendall(pkt)
        self.seq += 1
        # read 20-byte header
        head = b""
        while len(head) < 20:
            chunk = self.sock.recv(20 - len(head))
            if not chunk:
                raise IOError("conn closed")
            head += chunk
        _, _, sess, _seq, _msg, length = struct.unpack("BB2xII2xHI", head)
        self.session = sess
        body = b""
        while len(body) < length:
            chunk = self.sock.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        body = body.rstrip(b"\x00\x0a")
        try:
            return json.loads(body.decode("utf-8", "ignore"))
        except Exception:
            return {"_raw": body.decode("utf-8", "ignore")}

    def login(self, user="admin", password=""):
        self.connect()
        resp = self.send(1000, {
            "EncryptType": "MD5",
            "LoginType": "DVRIP-Web",
            "PassWord": sofia_hash(password),
            "UserName": user,
        })
        return resp

    def get_info(self, name):
        return self.send(1042, {"Name": name, "SessionID": "0x%08X" % self.session})

    def cmd(self, msgid, name=""):
        return self.send(msgid, {"Name": name, "SessionID": "0x%08X" % self.session})

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

# Ret codes: 100=OK, 101..=various, 205=user locked, 203=wrong pw, 204=user not found
CREDS = [("admin", ""), ("admin", "admin"), ("admin", "1234"),
         ("admin", "12345"), ("default", "tluafed"), ("default", "")]

def probe(host):
    print("=" * 60)
    print(f"[*] DVRIP probe {host}:34567")
    hit = None
    for user, pw in CREDS:
        try:
            d = DVRIP(host)
            r = d.login(user, pw)
            ret = r.get("Ret")
            if ret == 100:
                print(f"  [+] LOGIN OK  {user!r}/{pw!r}  session={r.get('SessionID')}")
                hit = (d, user, pw)
                break
            else:
                print(f"  [-] {user!r}/{pw!r}  Ret={ret}")
                d.close()
        except Exception as e:
            print(f"  [!] {user!r}/{pw!r}  error: {e}")
    if not hit:
        print("  [x] no default credentials worked")
        return
    d, user, pw = hit
    for name in ("SystemInfo", "SystemFunction", "General"):
        try:
            info = d.get_info(name)
            print(f"  --- {name} ---")
            print("  " + json.dumps(info, indent=2)[:1200].replace("\n", "\n  "))
        except Exception as e:
            print(f"  [!] get_info({name}) error: {e}")
    # account list (msg 1472)
    try:
        users = d.send(1472, {"Name": "", "SessionID": "0x%08X" % d.session})
        print("  --- Users (1472) ---")
        print("  " + json.dumps(users, indent=2)[:1500].replace("\n", "\n  "))
    except Exception as e:
        print(f"  [!] users error: {e}")
    d.close()

if __name__ == "__main__":
    targets = sys.argv[1:] or ["192.168.1.241", "192.168.1.243",
                                "192.168.1.244", "192.168.1.245", "192.168.1.246"]
    for t in targets:
        probe(t)
