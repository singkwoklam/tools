import requests
import urllib3
import ipaddress
import concurrent.futures
import csv
import sys
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===========================
# CONFIG
# ===========================
TIMEOUT = 3
THREADS = 50
CSV_FILE = "nextjs_detected.csv"

NEXTJS_INDICATORS = [
    "next.js",
    "next-router",
    "rsc",
    "react",
    "server-components"
]


def scan_ip(ip):
    url = f"https://{ip}"
    result = {"ip": ip, "details": ""}

    try:
        r = requests.head(url, timeout=TIMEOUT, verify=False)
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}

        hits = []
        for key, value in headers.items():
            for ind in NEXTJS_INDICATORS:
                if ind in key or ind in value:
                    hits.append(f"{key}: {value}")

        if hits:
            result["details"] = "; ".join(hits)
            return result   # Detected
        else:
            return None

    except requests.exceptions.RequestException:
        return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scan.py <CIDR>\nExample: python3 scan.py 192.168.1.0/24")
        sys.exit(1)

    CIDR = sys.argv[1]
    print(f"\n=== Next.js CIDR Scanner ===")
    print(f"Scanning subnet: {CIDR}\n")

    network = ipaddress.ip_network(CIDR, strict=False)
    ips = [str(ip) for ip in network.hosts()]

    detections = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = list(tqdm(executor.map(scan_ip, ips), total=len(ips), desc="Scanning"))

        for res in results:
            if res is not None:  # Only detections
                detections.append(res)
                print(f"\n⚠️  DETECTED: {res['ip']}")
                print(f"    → {res['details']}")

    # export detected only
    if detections:
        print(f"\n[+] Exporting detections to {CSV_FILE} ...")
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["ip", "details"])
            writer.writeheader()
            for row in detections:
                writer.writerow(row)
        print("[✔] CSV export complete.\n")
    else:
        print("\n✔ No Next.js detected in this CIDR.\n")


if __name__ == "__main__":
    main()
