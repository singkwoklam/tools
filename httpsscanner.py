import requests
import urllib3
import ipaddress
import concurrent.futures
import csv
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================
# CONFIG
# ===========================
TIMEOUT = 1
THREADS = 100
CSV_FILE = "headers_443.csv"
# ===========================


def scan_ip(ip):
    url = f"https://{ip}"
    result = {"ip": ip, "status": "", "headers": ""}

    try:
        r = requests.head(url, timeout=TIMEOUT, verify=False)

        # Convert headers to a readable string
        header_str = "; ".join([f"{k}: {v}" for k, v in r.headers.items()])

        result["status"] = "OK"
        result["headers"] = header_str

    except requests.exceptions.RequestException as e:
        result["status"] = "No HTTPS / timeout"
        result["headers"] = ""

    return result


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scan.py <CIDR>")
        print("Example: python3 scan.py 192.168.1.0/24")
        sys.exit(1)

    CIDR = sys.argv[1]
    print(f"\n=== 443 Header Scanner ===")
    print(f"Scanning subnet: {CIDR}\n")

    network = ipaddress.ip_network(CIDR, strict=False)
    ips = [str(ip) for ip in network.hosts()]

    results = []
    total = len(ips)
    completed = 0

    # Threaded scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        for res in executor.map(scan_ip, ips):
            completed += 1
            print(f"\rProgress: {completed}/{total}", end="")
            results.append(res)

    print("\n\n[+] Exporting all 443 headers to CSV...")

    # Write to CSV
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["ip", "status", "headers"])
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"[✔] Export complete → {CSV_FILE}\n")


if __name__ == "__main__":
    main()
