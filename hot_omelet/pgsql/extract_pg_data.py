from .scanner import PostgreSQLScanner


def extract_pg_data(ip, port):
    scanner = PostgreSQLScanner(host=ip, port=port, max_workers=5)
    scanner.scan()
    results_file = scanner.save_results()
    print(f"[SUCCESS] Scan results saved to {results_file}")
    scanner.print_summary()
    return scanner.results


if __name__ == "__main__":
    extract_pg_data(ip="10.0.0.10", port=5433)
