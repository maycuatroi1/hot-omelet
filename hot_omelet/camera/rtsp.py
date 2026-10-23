"""
RTSP stream verification.

A raw DESCRIBE proves video access without recording private footage -
the response status code is enough: 200 = open, 401 = auth required.
"""
import socket


def check_rtsp(ip, path="/", port=554, timeout=4):
    """
    Send an RTSP DESCRIBE for rtsp://ip:port<path> and report the result.

    Returns a dict with the parsed status code; `open_stream` is True when
    the server answers 200 (stream reachable without credentials).
    """
    uri = f"rtsp://{ip}:{port}{path}"
    req = (
        f"DESCRIBE {uri} RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"User-Agent: redomelet\r\n"
        f"Accept: application/sdp\r\n\r\n"
    )
    result = {"uri": uri, "reachable": False, "status": None,
              "status_line": None, "open_stream": False, "error": None}
    try:
        with socket.create_connection((ip, port), timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req.encode())
            data = sock.recv(2048).decode("latin-1", "ignore")
    except Exception as e:
        result["error"] = str(e)
        return result

    result["reachable"] = True
    line = data.splitlines()[0] if data else ""
    result["status_line"] = line
    parts = line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        result["status"] = int(parts[1])
        result["open_stream"] = result["status"] == 200
    return result
