import ipaddress
import json
import os
from pathlib import Path

import dns.asyncquery
import dns.resolver
import geoip2.database
import geoip2.errors
import maxminddb
from dotenv import load_dotenv

load_dotenv()

DATABASES_FOLDER = Path(os.getenv("IP_DATABASES"))
COUNTRY_DB = "GeoLite2-Country.mmdb"
CITY_DB = "GeoLite2-City.mmdb"
ASN_DB = "GeoLite2-ASN.mmdb"
IPINFO_LITE_DB = "ipinfo_lite.mmdb"

# https://ipinfo.io/data/ipinfo_lite.mmdb
# https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz
# https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz
# https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz

class DNSUtils:
    def __init__(
        self,
        timeout: float = 1.0,
        nameservers: list[str] | None = None,
    ):
        """
        DNS Utility based on dnspython.

        :param timeout: single DNS query timeout
        :param nameservers: DNS servers
        """
        self.timeout = timeout

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        if nameservers:
            self.resolver.nameservers = nameservers

    def reverse_dns(self, ip: str) -> str | None:
        """
        Returns the IP's PTR record (reverse DNS).
        """
        try:
            reverse_name = dns.reversename.from_address(ip)

            answer = self.resolver.resolve(
                reverse_name,
                "PTR",
            )

            return str(answer[0]).rstrip(".")

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            ValueError,
        ):
            return None

    def forward_matches(self, ip: str, hostname: str) -> bool:
        """
        Forward-Confirmed Reverse DNS (FCrDNS) Verification.

        True if the hostname resolution corresponds to the original IP.
        """
        if not hostname:
            return False

        try:
            addresses = set()

            # A record IPv4
            try:
                answers = self.resolver.resolve(hostname, "A")
                addresses.update(
                    str(rdata)
                    for rdata in answers
                )
            except dns.exception.DNSException:
                pass

            # AAAA record IPv6
            try:
                answers = self.resolver.resolve(hostname, "AAAA")
                addresses.update(
                    str(rdata)
                    for rdata in answers
                )
            except dns.exception.DNSException:
                pass

            target = ipaddress.ip_address(ip)

            return any(
                target == ipaddress.ip_address(addr)
                for addr in addresses
            )

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            ValueError,
        ):
            return False

    def lookup(self, ip: str) -> dict:

        ptr = self.reverse_dns(ip)
        return {
            "ptr": ptr,
            "forward_matches": self.forward_matches(ip, ptr)
        }

class IPLookup:

    def __init__(
            self,
            city_db: Path = DATABASES_FOLDER / CITY_DB,
            country_db: Path = DATABASES_FOLDER / COUNTRY_DB,
            asn_db: Path = DATABASES_FOLDER / ASN_DB,
            ipinfo_db: Path = DATABASES_FOLDER / IPINFO_LITE_DB
    ):

        self.city_reader = geoip2.database.Reader(city_db)
        self.country_reader = geoip2.database.Reader(country_db)
        self.asn_reader = geoip2.database.Reader(asn_db)
        self.ipinfo_reader = maxminddb.open_database(ipinfo_db)

        self.dns_utils = DNSUtils(
            timeout=1.0,
            nameservers=[
                "1.1.1.1",  # Cloudflare
                "8.8.8.8",  # Google
                "9.9.9.9",  # Quad9
                "208.67.222.222"  # OpenDNS
            ]
        )


    def lookup(self, ip: str) -> dict:

        result = {
            "ip": ip,
            "geo": {},
            "location": {},
            "network": {},
            "dns": {},
            "meta": {"errors": []},
        }

        # --- GeoLite2-City: geo + location + network (pt. 2) ---
        try:
            city = self.city_reader.city(ip)

            result["geo"] = {
                "continent": city.continent.name,
                "continent_code": city.continent.code,
                "country": city.country.name,
                "country_iso": city.country.iso_code,
                "country_is_eu": city.country.is_in_european_union,
                "region": city.subdivisions.most_specific.name,
                "region_iso": city.subdivisions.most_specific.iso_code,
                "city": city.city.name,
                "postal_code": city.postal.code,
                "registered_country": city.registered_country.name,
                "registered_country_iso": city.registered_country.iso_code,
                "represented_country": city.represented_country.name,
                "represented_country_type": city.represented_country.type,
            }

            result["location"] = {
                "latitude": city.location.latitude,
                "longitude": city.location.longitude,
                "accuracy_radius_km": city.location.accuracy_radius,
                "timezone": city.location.time_zone,
                "metro_code": city.location.metro_code,
                # "average_income": city.location.average_income,
                # "population_density": city.location.population_density,
            }

            result["network"] = {
                "cidr": str(city.traits.network) if city.traits.network else None,
                "is_anycast": city.traits.is_anycast,
            }

        except geoip2.errors.AddressNotFoundError:
            result["meta"]["errors"].append("GeoLite City DB: IP not found")

        """
        # --- GeoLite2-ASN: network (pt. 1) ---
        try:
            asn = self.asn_reader.asn(ip)
            
            result["network"]["as_number"] = asn.autonomous_system_number
            result["network"]["as_name"] = asn.autonomous_system_organization
            result["network"]["as_domain"] = None

        except geoip2.errors.AddressNotFoundError:
            result["network"]["as_number"] = None
            result["network"]["as_name"] = None
            result["network"]["as_domain"] = None
            result["meta"]["errors"].append("GeoLite ASN DB: IP not found")
        """

        # --- IPinfo Lite: network (pt. 1) ---

        ipinfo_data = self.ipinfo_reader.get(ip)
        if ipinfo_data:
            result["network"]["as_number"] = ipinfo_data.get("asn")
            result["network"]["as_name"] = ipinfo_data.get("as_name")
            result["network"]["as_domain"] = ipinfo_data.get("as_domain")
        else:
            result["network"]["as_number"] = None
            result["network"]["as_name"] = None
            result["network"]["as_domain"] = None
            result["meta"]["errors"].append("IPinfo Lite DB: IP not found")

        # --- DNSUtils: dns ---
        result["dns"] = self.dns_utils.lookup(ip)

        if not result["meta"]["errors"]:
            del result["meta"]["errors"]

        return result

    def close(self):
        self.city_reader.close()
        self.country_reader.close()
        self.asn_reader.close()
        self.ipinfo_reader.close()