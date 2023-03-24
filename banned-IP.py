import argparse
import requests
import socket
from ipwhois import IPWhois


def get_ips_from_asn(asn):
    url = f"https://api.hackertarget.com/aslookup/?q=AS{asn}"
    resp = requests.get(url)
    if resp.ok:
        ips = resp.text.splitlines()
        return ips
    else:
        return []


def get_asn_from_domain(domain_or_company):
    try:
        ip_address = socket.gethostbyname(domain_or_company)
    except socket.gaierror:
        ip_address = None
    if ip_address:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        return results["asn"]
    else:
        url = f"https://api.hackertarget.com/aslookup/?q={domain_or_company}"
        resp = requests.get(url)
        if resp.ok:
            results = resp.text.splitlines()
            for result in results:
                if "AS" in result:
                    return result.split("AS")[1]
            print(f"No ASNs found for {domain_or_company}: {results}")
    return None


def get_ips_from_company_name(company_name):
    asn = get_asn_from_domain(company_name)
    ips = get_ips_from_asn(asn)
    return ips


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get IP addresses associated with a company')
    parser.add_argument('company_name', type=str, help='Name of the company')
    args = parser.parse_args()

    ips = get_ips_from_company_name(args.company_name)

    with open(f"{args.company_name}_ips.txt", "w") as f:
        for ip in ips:
            f.write(f"{ip}\n")

    print(f"IP addresses associated with {args.company_name} have been written to {args.company_name}_ips.txt")
