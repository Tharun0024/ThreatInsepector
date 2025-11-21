import geoip2.database
import os
import sys

def country_flag(country_name):
    flags = {
        "India": "🇮🇳",
        "United States": "🇺🇸",
        "United Kingdom": "🇬🇧",
        # Add more country-emoji mappings as needed
    }
    return flags.get(country_name, "")

def lookup_ip(ip_addr):
    base_dir = os.path.dirname(__file__)
    city_db = os.path.join(base_dir, "GeoLite2-City.mmdb")
    asn_db = os.path.join(base_dir, "GeoLite2-ASN.mmdb")

    geo_result = {
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "flag": ""
    }
    isp_result = {
        "provider": "Unknown ISP",
        "asn": "Unknown"
    }

    # City and location lookup
    if os.path.exists(city_db):
        try:
            with geoip2.database.Reader(city_db) as city_reader:
                response = city_reader.city(ip_addr)
                geo_result["country"] = response.country.name or "Unknown"
                geo_result["city"] = response.city.name or "Unknown"
                geo_result["lat"] = response.location.latitude or 0.0
                geo_result["lon"] = response.location.longitude or 0.0
                geo_result["flag"] = country_flag(geo_result["country"])
        except Exception as e:
            print(f"City DB error: {e}")

    # ASN lookup (for ISP/provider)
    if os.path.exists(asn_db):
        try:
            with geoip2.database.Reader(asn_db) as asn_reader:
                asn = asn_reader.asn(ip_addr)
                isp_result["provider"] = asn.autonomous_system_organization or "Unknown ISP"
                isp_result["asn"] = str(asn.autonomous_system_number or "Unknown")
        except Exception as e:
            print(f"ASN DB error: {e}")

    return geo_result, isp_result

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python geoip.py <IP_ADDRESS>")
        sys.exit(1)
    ip_input = sys.argv[1]
    geo, isp = lookup_ip(ip_input)
    print(f"IP: {ip_input}")
    print(f"Country: {geo['country']} {geo['flag']}")
    print(f"City: {geo['city']}")
    print(f"Latitude: {geo['lat']}")
    print(f"Longitude: {geo['lon']}")
    print(f"ISP: {isp['provider']}")
    print(f"ASN: {isp['asn']}")
