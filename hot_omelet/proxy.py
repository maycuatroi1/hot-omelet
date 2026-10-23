import socket
import threading
import signal
from rich import print
from rich.table import Table


class TCPProxy:
    def __init__(self, local_host, remote_host, ports, bind_addr="0.0.0.0", buffer_size=65536):
        self.local_host = local_host
        self.remote_host = remote_host
        self.ports = ports
        self.bind_addr = bind_addr
        self.buffer_size = buffer_size
        self.servers = []
        self.running = True
        self.connections = {"active": 0, "total": 0}
        self._lock = threading.Lock()

    def _relay(self, src, dst, label):
        try:
            while self.running:
                data = src.recv(self.buffer_size)
                if not data:
                    break
                dst.sendall(data)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                src.close()
            except OSError:
                pass
            try:
                dst.close()
            except OSError:
                pass

    def _handle_client(self, client_sock, client_addr, port):
        with self._lock:
            self.connections["active"] += 1
            self.connections["total"] += 1

        print(f"[cyan][PROXY][/cyan] :{port} <- {client_addr[0]}:{client_addr[1]}")

        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10)
            remote_sock.connect((self.remote_host, port))
            remote_sock.settimeout(None)
        except (socket.error, OSError) as e:
            print(f"[red][PROXY][/red] :{port} -> {self.remote_host}:{port} failed: {e}")
            client_sock.close()
            with self._lock:
                self.connections["active"] -= 1
            return

        t1 = threading.Thread(target=self._relay, args=(client_sock, remote_sock, "client->remote"), daemon=True)
        t2 = threading.Thread(target=self._relay, args=(remote_sock, client_sock, "remote->client"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        with self._lock:
            self.connections["active"] -= 1

    def _serve_port(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(1)
            server.bind((self.bind_addr, port))
            server.listen(128)
            self.servers.append(server)
        except OSError as e:
            print(f"[red]Cannot bind :{port} - {e}[/red]")
            return

        while self.running:
            try:
                client_sock, client_addr = server.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, client_addr, port), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _setup_hosts(self):
        hosts_file = "/etc/hosts"
        self.hosts_entry = f"127.0.0.1 {self.local_host}"
        try:
            with open(hosts_file, "r") as f:
                content = f.read()
            if self.local_host in content:
                lines = content.splitlines()
                new_lines = [line for line in lines if self.local_host not in line]
                new_lines.append(self.hosts_entry)
                with open(hosts_file, "w") as f:
                    f.write("\n".join(new_lines) + "\n")
                print(f"[yellow]Updated /etc/hosts entry for {self.local_host}[/yellow]")
            else:
                with open(hosts_file, "a") as f:
                    f.write(f"\n{self.hosts_entry}\n")
                print(f"[green]Added /etc/hosts entry: {self.hosts_entry}[/green]")
        except PermissionError:
            print("[yellow]Cannot modify /etc/hosts (need sudo). Add manually:[/yellow]")
            print(f"  echo '{self.hosts_entry}' | sudo tee -a /etc/hosts")

    def _cleanup_hosts(self):
        hosts_file = "/etc/hosts"
        try:
            with open(hosts_file, "r") as f:
                lines = f.read().splitlines()
            new_lines = [line for line in lines if self.local_host not in line]
            with open(hosts_file, "w") as f:
                f.write("\n".join(new_lines) + "\n")
            print(f"\n[yellow]Removed /etc/hosts entry for {self.local_host}[/yellow]")
        except PermissionError:
            print("\n[yellow]Cannot clean /etc/hosts. Remove manually:[/yellow]")
            print(f"  sudo sed -i '/{self.local_host}/d' /etc/hosts")

    def run(self, setup_hosts=True):
        if setup_hosts:
            self._setup_hosts()

        table = Table(title="TCP Proxy")
        table.add_column("Local", style="cyan")
        table.add_column("", style="white")
        table.add_column("Remote", style="green")
        for port in self.ports:
            table.add_row(f"{self.local_host}:{port}", "->", f"{self.remote_host}:{port}")
        print(table)
        print(f"[dim]Proxying {len(self.ports)} ports. Ctrl+C to stop.[/dim]\n")

        def shutdown(sig, frame):
            self.running = False

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        threads = []
        for port in self.ports:
            t = threading.Thread(target=self._serve_port, args=(port,), daemon=True)
            t.start()
            threads.append(t)

        try:
            while self.running:
                signal.pause()
        except (KeyboardInterrupt, AttributeError):
            self.running = False

        print("\n[yellow]Shutting down proxy...[/yellow]")
        for s in self.servers:
            try:
                s.close()
            except OSError:
                pass

        if setup_hosts:
            self._cleanup_hosts()

        print(f"[green]Done. Total connections handled: {self.connections['total']}[/green]")


DEFAULT_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 993, 995,
                 3306, 5432, 6379, 27017, 8888, 9090, 3000, 4000, 5000]


def proxy_command(local_host, remote_host, custom_ports, all_common, no_hosts, bind):
    if custom_ports:
        port_list = []
        for p in custom_ports.split(","):
            p = p.strip()
            if "-" in p:
                start, end = p.split("-", 1)
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(p))
    elif all_common:
        port_list = DEFAULT_PORTS
    else:
        port_list = DEFAULT_PORTS

    resolved_ip = remote_host
    if not _is_ip(remote_host):
        try:
            resolved_ip = socket.gethostbyname(remote_host)
            print(f"[dim]Resolved {remote_host} -> {resolved_ip}[/dim]")
        except socket.gaierror:
            print(f"[red]Cannot resolve {remote_host}[/red]")
            return

    print(f"[cyan]Scanning reachable ports on {resolved_ip}...[/cyan]")
    reachable = _scan_ports(resolved_ip, port_list)
    if not reachable:
        print(f"[red]No reachable ports found on {resolved_ip}[/red]")
        return

    print(f"[green]Found {len(reachable)} open ports[/green]")
    proxy = TCPProxy(local_host, resolved_ip, reachable, bind_addr=bind)
    proxy.run(setup_hosts=not no_hosts)


def _is_ip(s):
    try:
        socket.inet_aton(s)
        return True
    except socket.error:
        return False


def _scan_ports(host, ports, timeout=2, threads=50):
    open_ports = []
    lock = threading.Lock()

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            with lock:
                open_ports.append(port)
        except (socket.error, OSError):
            pass

    batch_threads = []
    for port in ports:
        t = threading.Thread(target=check, args=(port,))
        t.start()
        batch_threads.append(t)
        if len(batch_threads) >= threads:
            for bt in batch_threads:
                bt.join()
            batch_threads = []

    for bt in batch_threads:
        bt.join()

    return sorted(open_ports)
