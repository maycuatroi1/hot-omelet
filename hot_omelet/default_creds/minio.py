"""MinIO default credential scanner."""

import requests
from typing import Dict, Any, List, Tuple
from urllib3.exceptions import InsecureRequestWarning
from .base_scanner import BaseDefaultCredsScanner

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


DEFAULT_MINIO_CREDENTIALS = [
    ("minioadmin", "minioadmin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("minio", "minio123"),
    ("admin", "admin123"),
    ("root", "password"),
    ("root", "rootpass"),
    ("minio", "minio"),
    ("access", "secretkey"),
    ("admin", "12345678"),
    ("minio", "password"),
    ("test", "test1234"),
    ("demo", "demo1234"),
    ("user", "password123"),
    ("minio", "miniostorage"),
]


class MinioScanner(BaseDefaultCredsScanner):
    """Scanner for MinIO default credentials."""

    def __init__(
        self,
        host: str,
        port: int = 9000,
        credentials: List[Tuple[str, str]] = None,
        max_workers: int = 10,
        timeout: int = 5,
        verbose: bool = True,
        use_ssl: bool = False,
    ):
        self.use_ssl = use_ssl
        self.base_url = f"{'https' if use_ssl else 'http'}://{host}:{port}"
        super().__init__(host, port, credentials, max_workers, timeout, verbose)

    def get_default_credentials(self) -> List[Tuple[str, str]]:
        """Return default MinIO credentials."""
        return DEFAULT_MINIO_CREDENTIALS

    def get_service_name(self) -> str:
        """Return service name."""
        return "MinIO"

    def test_connection(self, username: str, password: str) -> Dict[str, Any]:
        """Test credentials against MinIO API."""
        result = {
            "username": username,
            "password": password,
            "success": False,
            "service": "minio",
            "host": self.host,
            "port": self.port,
        }

        try:
            # MinIO uses S3-compatible API
            # We'll try to list buckets which requires valid credentials
            import hmac
            import hashlib
            import datetime
            from urllib.parse import urlparse

            # Generate AWS Signature v4
            parsed_url = urlparse(self.base_url)
            host_header = parsed_url.netloc

            # Create canonical request
            method = "GET"
            canonical_uri = "/"
            canonical_querystring = ""

            # Get current time
            t = datetime.datetime.utcnow()
            amz_date = t.strftime("%Y%m%dT%H%M%SZ")
            date_stamp = t.strftime("%Y%m%d")

            # Headers
            canonical_headers = f"host:{host_header}\nx-amz-date:{amz_date}\n"
            signed_headers = "host;x-amz-date"
            payload_hash = hashlib.sha256(b"").hexdigest()

            # Create canonical request
            canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

            # Create string to sign
            algorithm = "AWS4-HMAC-SHA256"
            credential_scope = f"{date_stamp}/us-east-1/s3/aws4_request"
            string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

            # Calculate signature
            def sign(key, msg):
                return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

            date_key = sign(("AWS4" + password).encode("utf-8"), date_stamp)
            region_key = sign(date_key, "us-east-1")
            service_key = sign(region_key, "s3")
            signing_key = sign(service_key, "aws4_request")
            signature = hmac.new(
                signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
            ).hexdigest()

            # Create authorization header
            authorization_header = f"{algorithm} Credential={username}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

            # Make request
            headers = {
                "x-amz-date": amz_date,
                "Authorization": authorization_header,
                "Host": host_header,
            }

            response = requests.get(
                self.base_url, headers=headers, timeout=self.timeout, verify=False
            )

            if response.status_code == 200:
                result["success"] = True

                # Try to parse bucket list
                try:
                    # MinIO returns XML for bucket listing
                    import xml.etree.ElementTree as ET

                    root = ET.fromstring(response.text)
                    buckets = root.findall(
                        ".//{http://s3.amazonaws.com/doc/2006-03-01/}Bucket"
                    )
                    bucket_count = len(buckets)
                    result["info"] = f"Accessible buckets: {bucket_count}"

                    if buckets:
                        bucket_names = [
                            b.find("{http://s3.amazonaws.com/doc/2006-03-01/}Name").text
                            for b in buckets[:5]
                        ]
                        result["info"] += f", Sample: {', '.join(bucket_names)}"
                except:  # noqa: E722
                    result["info"] = "Successfully authenticated"

            elif response.status_code == 403:
                result["error"] = "Access denied - invalid credentials"
            else:
                result["error"] = f"HTTP {response.status_code}"

        except requests.exceptions.Timeout:
            result["error"] = "Connection timeout"
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection failed"
        except Exception as e:
            # Try alternate method - MinIO Console API
            try:
                session = requests.Session()

                # Try MinIO Console login
                login_data = {"accessKey": username, "secretKey": password}

                console_response = session.post(
                    f"{self.base_url}/api/v1/login",
                    json=login_data,
                    timeout=self.timeout,
                    verify=False,
                    headers={"Content-Type": "application/json"},
                )

                if (
                    console_response.status_code == 204
                    or console_response.status_code == 200
                ):
                    result["success"] = True
                    result["info"] = "MinIO Console access verified"

                    # Try to get server info
                    try:
                        info_response = session.get(
                            f"{self.base_url}/api/v1/admin/info",
                            timeout=self.timeout,
                            verify=False,
                        )
                        if info_response.status_code == 200:
                            info_data = info_response.json()
                            result["info"] += (
                                f", Mode: {info_data.get('mode', 'Unknown')}"
                            )
                    except:  # noqa: E722
                        pass
                else:
                    result["error"] = "Invalid credentials"

            except Exception:
                result["error"] = f"Both S3 and Console auth failed: {str(e)}"

        return result


def scan_minio(
    host: str,
    port: int = 9000,
    credentials: List[Tuple[str, str]] = None,
    max_workers: int = 10,
    timeout: int = 5,
    verbose: bool = True,
    use_ssl: bool = False,
    output_file: str = None,
) -> Dict[str, Any]:
    """Scan MinIO instance for default credentials."""
    scanner = MinioScanner(
        host=host,
        port=port,
        credentials=credentials,
        max_workers=max_workers,
        timeout=timeout,
        verbose=verbose,
        use_ssl=use_ssl,
    )

    results = scanner.scan()
    scanner.print_summary()

    if output_file:
        scanner.save_results(output_file)

    return {
        "host": host,
        "port": port,
        "service": "minio",
        "valid_credentials": scanner.get_valid_credentials(),
        "total_tested": len(scanner.credentials),
        "results": results,
    }
