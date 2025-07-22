import requests
import csv
import os
import logging
import time
from datetime import datetime

# Constants
CLERK_BASE = "https://clerk.spur.us"
APP_BASE = "https://app.spur.us"
OUTPUT_DIR = "output"

# Setup logging
logging.basicConfig(
    filename='spur_osint.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

session = None  # Global session object

def get_session():
    global session
    if session is None:
        session = requests.Session()
    return session

def start_sign_in(email):
    url = f"{CLERK_BASE}/v1/client/sign_ins?__clerk_api_version=2025-04-10&_clerk_js_version=5.74.0"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": APP_BASE,
        "Referer": APP_BASE,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }
    data = {"identifier": email}
    resp = get_session().post(url, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()

def submit_password(sign_in_id, password):
    url = f"{CLERK_BASE}/v1/client/sign_ins/{sign_in_id}/attempt_first_factor?__clerk_api_version=2025-04-10&_clerk_js_version=5.74.0"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": APP_BASE,
        "Referer": APP_BASE,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }
    data = {
        "strategy": "password",
        "password": password,
    }
    resp = get_session().post(url, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()

def set_auth_cookies(password_response):
    response = password_response.get("response", {})
    client = password_response.get("client", {})
    sessions = client.get("sessions", [])

    jwt_token = None
    if "last_active_token" in response:
        jwt_token = response["last_active_token"].get("jwt")
    elif sessions and "last_active_token" in sessions[0]:
        jwt_token = sessions[0]["last_active_token"].get("jwt")

    if not jwt_token:
        logging.error("Missing last_active_token JWT token in login response")
        raise ValueError("Missing last_active_token JWT token in login response")

    session_id = response.get("created_session_id")
    if not session_id and sessions:
        session_id = sessions[0].get("id")

    user_data = response.get("user_data")
    org_id = None
    if user_data and "organization_memberships" in user_data and len(user_data["organization_memberships"]) > 0:
        org_id = user_data["organization_memberships"][0]["organization"]["id"]
    else:
        if sessions and "last_active_organization_id" in sessions[0]:
            org_id = sessions[0]["last_active_organization_id"]

    get_session().cookies.set("__session", jwt_token, domain="app.spur.us", path="/")
    if session_id and org_id:
        context_value = f"{session_id}:{org_id}"
        get_session().cookies.set("clerk_active_context", context_value, domain="app.spur.us", path="/")

def graphql_search(ip):
    url = f"{APP_BASE}/api/graphql"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/graphql-response+json",
        "Origin": APP_BASE,
        "Referer": f"{APP_BASE}/search?q={ip}",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }
    query = """
    query Search($q: String!) {
      search(q: $q) {
        __typename
        ... on IPContext {
          ip
          location { country }
          as { number organization }
          risks
          infrastructure
          timeline { date count }
        }
        ... on AutonomousSystem {
          activeIPs
          averageDeviceCount
          distinctProxyServices
          distinctVPNServices
          number
          organization
          relatedServiceTags {
            tag
            name
            categories
            metrics {
              churnRate
              distinctIPs
            }
          }
          serviceTagCounts {
            label
            count
          }
          totalIPs
        }
        ... on ServiceTag {
          allowsCrypto
          categories
          description
          history {
            count
            date
          }
          isInactive
          isNoLog
          metrics {
            averageDeviceCount
            churnRate
            distinctASNs
            distinctCountries
            distinctIPs
            distinctISPs
          }
          name
          platforms
          protocols
          tag
          history {
            date
            count
          }
          ipCountSparkline
          hostingCountries {
            label
            count
          }
          userCountries {
            label
            count
          }
          relatedServices {
            tag
            name
            categories
          }
        }
      }
    }
    """
    variables = {"q": ip}
    payload = {
        "query": query,
        "variables": variables,
    }
    resp = get_session().post(url, headers=headers, json=payload)
    resp.raise_for_status()
    json_resp = resp.json()
    logging.info(f"Raw JSON response for IP {ip}: {json_resp}")
    return json_resp

def parse_response(ip, data):
    try:
        raw_results = str(data)
        search = data.get("data", {}).get("search")
        if not search:
            return {
                "IP": ip,
                "Raw Spur.US results": raw_results,
                "Identified VPN, Tunnel, Etc.": "N/A",
                "IP Type": "N/A",
                "IP Est. Geolocation": "N/A"
            }
        risks = search.get("risks", [])
        risks_str = ", ".join(risks) if risks else "N/A"
        ip_type = search.get("infrastructure", "N/A")
        location = search.get("location", {})
        country = location.get("country", "N/A")
        return {
            "IP": ip,
            "Raw Spur.US results": raw_results,
            "Identified VPN, Tunnel, Etc.": risks_str,
            "IP Type": ip_type,
            "IP Est. Geolocation": country
        }
    except Exception as e:
        logging.error(f"Error parsing response for IP {ip}: {e}")
        return {
            "IP": ip,
            "Raw Spur.US results": "N/A",
            "Identified VPN, Tunnel, Etc.": "N/A",
            "IP Type": "N/A",
            "IP Est. Geolocation": "N/A"
        }

def write_csv(filename, fieldnames, rows, mode='w'):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, mode, newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if mode == 'w':
            writer.writeheader()
        writer.writerows(rows)
    logging.info(f"Wrote results to {filepath}")
    print(f"Results saved to {filepath}")

def reauthenticate(email, password, max_retries=3):
    global session
    delay = 2
    for attempt in range(max_retries):
        try:
            session = requests.Session()  # NEW SESSION on re-auth
            print(f"Re-authenticating (attempt {attempt+1})...")
            sign_in_response = start_sign_in(email)
            sign_in_id = sign_in_response["response"]["id"]
            password_response = submit_password(sign_in_id, password)
            set_auth_cookies(password_response)
            print("Re-authentication successful.")
            return True
        except requests.HTTPError as e:
            if e.response.status_code == 429:
                print("Rate limited during re-authentication, sleeping for 60 seconds...")
                logging.error("Rate limited during re-authentication, sleeping for 60 seconds...")
                time.sleep(60)
            else:
                print(f"HTTP error during re-authentication: {e}, retrying...")
                logging.error(f"HTTP error during re-authentication: {e}")
                time.sleep(delay)
                delay *= 2
        except Exception as e:
            print(f"Error during re-authentication: {e}, retrying...")
            logging.error(f"Error during re-authentication: {e}")
            time.sleep(delay)
            delay *= 2
    print("Failed to re-authenticate after multiple attempts. Exiting.")
    return False

def robust_query_ip(ip, email, password, max_retries=4):
    delay = 2
    reauthed = False
    for attempt in range(max_retries):
        try:
            print(f"Querying IP: {ip} (attempt {attempt+1})")
            data = graphql_search(ip)
            if any(e.get('extensions', {}).get('code') == 'UNAUTHENTICATED' for e in data.get('errors', [])):
                if not reauthed:
                    print(f"Session expired for IP {ip}, re-authenticating...")
                    logging.warning(f"Session expired for IP {ip}, re-authenticating (attempt {attempt+1})...")
                    if not reauthenticate(email, password):
                        break
                    reauthed = True
                    time.sleep(delay)
                    continue
                else:
                    print(f"Still unauthorized after re-authentication for IP {ip}. Skipping.")
                    logging.error(f"Still unauthorized after re-auth for IP {ip}.")
                    break
            return parse_response(ip, data)
        except requests.HTTPError as e:
            if e.response.status_code == 429:
                print(f"Rate limited on IP {ip}, sleeping for 60 seconds...")
                logging.error(f"Rate limited on IP {ip}, sleeping for 60 seconds...")
                time.sleep(60)
                continue
            else:
                print(f"HTTP error for IP {ip}: {e}")
                logging.error(f"HTTP error for IP {ip}: {e}")
                break
        except Exception as e:
            print(f"Error querying IP {ip}: {e}")
            logging.error(f"Error querying IP {ip}: {e}")
            break
        time.sleep(delay)
        delay *= 2
    # If all retries fail
    return {
        "IP": ip,
        "Raw Spur.US results": "N/A",
        "Identified VPN, Tunnel, Etc.": "N/A",
        "IP Type": "N/A",
        "IP Est. Geolocation": "N/A"
    }

def print_summary(total_ips, unique_ips, error_count, reauth_count, rate_limit_count):
    print("\n=== Summary ===")
    print(f"Total IPs processed (including duplicates): {total_ips}")
    print(f"Unique IPs queried: {unique_ips}")
    print(f"IPs with errors or no data: {error_count}")
    print(f"Re-authentication attempts: {reauth_count}")
    print(f"Rate limit pauses: {rate_limit_count}")
    print("================\n")

def main():
    print("Welcome to Spur OSINT Tool")
    email = input("Enter Spur username (email): ").strip()
    password = input("Enter Spur password: ").strip()

    if not reauthenticate(email, password):
        return

    reauth_attempts = 0
    rate_limit_pauses = 0
    error_ips = 0

    while True:
        print("\nChoose input method for IPs:")
        print("1. Enter IPs manually")
        print("2. Upload CSV file")
        print("3. Exit")
        choice = input("Enter choice (1/2/3): ").strip()

        if choice == '1':
            ips_input = input("Enter IPs separated by space or comma: ").strip()
            ips = [ip.strip() for ip in ips_input.replace(',', ' ').split() if ip.strip()]
            results_cache = {}
            results = []
            unique_ips = list(set(ips))
            total_ips = len(ips)
            print(f"Total IPs entered: {total_ips}, Unique IPs: {len(unique_ips)}")
            for idx, ip in enumerate(unique_ips, 1):
                print(f"Querying unique IP {idx} of {len(unique_ips)}: {ip}")
                result = robust_query_ip(ip, email, password)
                if result["Raw Spur.US results"] == "N/A":
                    error_ips += 1
                results_cache[ip] = result
                time.sleep(2)
            for ip in ips:
                results.append(results_cache[ip])
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"spur_results_manual_{timestamp}.csv"
            fieldnames = ["IP", "Raw Spur.US results", "Identified VPN, Tunnel, Etc.", "IP Type", "IP Est. Geolocation"]
            write_csv(filename, fieldnames, results)
            print_summary(total_ips, len(unique_ips), error_ips, reauth_attempts, rate_limit_pauses)

        elif choice == '2':
            csv_path = input("Enter path to CSV file: ").strip()
            if not os.path.isfile(csv_path):
                print("File not found. Please try again.")
                continue
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                print("Columns found in CSV:")
                for i, h in enumerate(headers):
                    print(f"{i+1}. {h}")
                col_choice = input("Enter the number of the column containing IPs: ").strip()
                try:
                    col_index = int(col_choice) - 1
                    ip_col = headers[col_index]
                except Exception:
                    print("Invalid column choice. Please try again.")
                    continue
                rows = list(reader)
            all_ips = []
            for row in rows:
                ip = row.get(ip_col, '').strip()
                if ip:
                    all_ips.append(ip)
            unique_ips = set(all_ips)
            total_ips = len(all_ips)
            print(f"Total IPs in CSV: {total_ips}, Unique IPs: {len(unique_ips)}")
            results_cache = {}
            for idx, ip in enumerate(unique_ips, 1):
                print(f"Querying unique IP {idx} of {len(unique_ips)}: {ip}")
                result = robust_query_ip(ip, email, password)
                if result["Raw Spur.US results"] == "N/A":
                    error_ips += 1
                results_cache[ip] = result
                time.sleep(2)
            print("\nChoose output option:")
            print("1. Save results to a new CSV")
            print("2. Extend original CSV with results")
            out_choice = input("Enter choice (1/2): ").strip()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if out_choice == '1':
                filename = f"spur_results_csv_{timestamp}.csv"
                fieldnames = ["IP", "Raw Spur.US results", "Identified VPN, Tunnel, Etc.", "IP Type", "IP Est. Geolocation"]
                rows_to_write = [results_cache[ip] for ip in all_ips]
                write_csv(filename, fieldnames, rows_to_write)
            elif out_choice == '2':
                filename = f"spur_results_extended_{timestamp}.csv"
                extended_rows = []
                for row in rows:
                    ip = row.get(ip_col, '').strip()
                    parsed = results_cache.get(ip, {
                        "IP": ip,
                        "Raw Spur.US results": "N/A",
                        "Identified VPN, Tunnel, Etc.": "N/A",
                        "IP Type": "N/A",
                        "IP Est. Geolocation": "N/A"
                    })
                    new_row = row.copy()
                    new_row.update({
                        "IP": parsed["IP"],
                        "Raw Spur.US results": parsed["Raw Spur.US results"],
                        "Identified VPN, Tunnel, Etc.": parsed["Identified VPN, Tunnel, Etc."],
                        "IP Type": parsed["IP Type"],
                        "IP Est. Geolocation": parsed["IP Est. Geolocation"]
                    })
                    extended_rows.append(new_row)
                fieldnames = list(rows[0].keys()) + ["IP", "Raw Spur.US results", "Identified VPN, Tunnel, Etc.", "IP Type", "IP Est. Geolocation"]
                write_csv(filename, fieldnames, extended_rows)
            else:
                print("Invalid choice. Returning to main menu.")
            print_summary(total_ips, len(unique_ips), error_ips, reauth_attempts, rate_limit_pauses)

        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()