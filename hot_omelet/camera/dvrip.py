#!/usr/bin/env python3
"""
DVRIP (XiongMai "Sofia") client - authorized LAN camera security review.
Tests default/weak credentials and reads device info + account list.
Read-only: no config changes, no reboot, no firmware ops.
"""
import socket
import struct
import json
import hashlib
import sys

DVRIP_PORT = 34567

# Sofia hash of the empty string. If a dumped account shows this hash the
# account has no password at all.
EMPTY_PW_HASH = "tlJwpbo6"

# Known XiongMai/Sofia default credentials - a small known-default set,
# deliberately NOT a brute-force list.
DEFAULT_CREDS = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("default", "tluafed"),
    ("default", ""),
]


def sofia_hash(password=""):
    md5 = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(md5[i] + md5[i + 1]) % 62] for i in range(0, 16, 2))


class DVRIP:
    def __init__(self, host, port=DVRIP_PORT, timeout=6):
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


def _extract_accounts(users_resp):
    """Pull (name, password-hash, empty?) records out of a msg-1472 response."""
    accounts = []
    if not isinstance(users_resp, dict):
        return accounts
    for entry in users_resp.get("Users", []) or []:
        if not isinstance(entry, dict):
            continue
        pw_hash = entry.get("Password")
        accounts.append({
            "name": entry.get("Name"),
            "password_hash": pw_hash,
            "authority": entry.get("AuthorityList"),
            "empty_password": pw_hash == EMPTY_PW_HASH,
        })
    return accounts


def assess(host, port=DVRIP_PORT, timeout=6, test_creds=True):
    """
    Assess a XiongMai DVRIP device on `host`.

    Returns a structured findings dict. Read-only: tries a small known-default
    credential set, then on success reads device info and the account list.
    """
    result = {
        "service": "dvrip",
        "host": host,
        "port": port,
        "reachable": False,
        "login": None,
        "system_info": {},
        "accounts": [],
        "empty_admin": False,
        "error": None,
    }
    # Ret codes: 100=OK, 203=wrong pw, 204=user not found, 205=user locked.
    creds = DEFAULT_CREDS if test_creds else [("admin", "")]
    hit = None
    for user, pw in creds:
        try:
            d = DVRIP(host, port, timeout)
            r = d.login(user, pw)
            result["reachable"] = True
            if r.get("Ret") == 100:
                hit = (d, user, pw, r)
                break
            d.close()
        except Exception as e:
            result["error"] = str(e)
    if not hit:
        return result

    d, user, pw, login_resp = hit
    result["login"] = {
        "user": user,
        "password": pw,
        "session": login_resp.get("SessionID"),
    }
    if pw == "":
        result["empty_admin"] = True

    for name in ("SystemInfo", "General"):
        try:
            result["system_info"][name] = d.get_info(name)
        except Exception:
            pass

    # account list (msg 1472) -> usernames + Sofia password hashes
    try:
        users = d.send(1472, {"Name": "", "SessionID": "0x%08X" % d.session})
        result["accounts"] = _extract_accounts(users)
        if any(a["name"] == "admin" and a["empty_password"]
               for a in result["accounts"]):
            result["empty_admin"] = True
    except Exception:
        pass

    d.close()
    return result


if __name__ == "__main__":
    targets = sys.argv[1:] or ["192.168.1.241", "192.168.1.243",
                                "192.168.1.244", "192.168.1.245", "192.168.1.246"]
    for t in targets:
        print("=" * 60)
        print(json.dumps(assess(t), indent=2, default=str))
