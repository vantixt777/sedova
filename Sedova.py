import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import socket
import whois
import re
import os
from bs4 import BeautifulSoup
from colorama import init, Fore
from pystyle import Colors, Colorate
import threading
from googlesearch import search as google_search
from exif import Image
import hashlib
import ssl
import json


init(autoreset=True)
red, green, yellow, reset = Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.RESET


def print_banner():
    banner = Colorate.Horizontal(Colors.green_to_black, """
   ▄████████    ▄████████ ████████▄   ▄██████▄   ▄█    █▄     ▄████████ 
  ███    ███   ███    ███ ███   ▀███ ███    ███ ███    ███   ███    ███ 
  ███    █▀    ███    █▀  ███    ███ ███    ███ ███    ███   ███    ███ 
  ███         ▄███▄▄▄     ███    ███ ███    ███ ███    ███   ███    ███ 
▀███████████ ▀▀███▀▀▀     ███    ███ ███    ███ ███    ███ ▀███████████ 
         ███   ███    █▄  ███    ███ ███    ███ ███    ███   ███    ███ 
   ▄█    ███   ███    ███ ███   ▄███ ███    ███ ███    ███   ███    ███ 
 ▄████████▀    ██████████ ████████▀   ▀██████▀   ▀██████▀    ███    █▀       OSINT TOOLKIT 
""")
    print(banner)


def print_menu():
    menu = Colorate.Horizontal(Colors.green_to_black, """
╔═════════════════════════════════════════════════════╗
║                     MENU OPTIONS                    ║
╠════════════════════════════════════════════════════════════
║ 1.  Get IP Info                16. Email Header Analyzer  ║
║ 2.  Get Phone Number Info      17. Social Media Lookup    ║
║ 3.  Scan Ports                 18. Website Screenshot     ║
║ 4.  Google Dorking             19. Hash Identifier        ║
║ 5.  Check Breaches             20. IP Geolocation         ║
║ 6.  Admin Panel Scan           21. MAC Address Lookup     ║
║ 7.  WHOIS Lookup               22. DNS History Check      ║
║ 8.  Subdomain Finder           23. File Metadata Extractor║
║ 9.  Reverse IP Lookup          24. Pastebin Dump Search   ║
║ 10. Extract Links              25. Dark Web Search        ║
║ 11. MetaData Finder            26. Username Availability  ║
║ 12. Username Checker           27. Website Tech Stack     ║
║ 13. DNS Lookup                 28. SSL Certificate Info   ║
║ 14. Email Breach Checker       29. IP Blacklist Check     ║
║ 15. Website Crawler            30. Exit                   ║
╚═══════════════════════════════════════════════════════════╝
                 🛠️ by vantixt
""")
    print(menu)


def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        print(f"{green}IP Info:{reset}")
        print(f"Country: {data.get('country')}")
        print(f"Region: {data.get('regionName')}")
        print(f"City: {data.get('city')}")
        print(f"ISP: {data.get('isp')}")
        print(f"Latitude: {data.get('lat')}")
        print(f"Longitude: {data.get('lon')}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def get_phone_info(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number)
        print(f"{green}Phone Info:{reset}")
        print(f"Country: {geocoder.description_for_number(parsed_number, 'en')}")
        print(f"Carrier: {carrier.name_for_number(parsed_number, 'en')}")
        print(f"Timezone: {timezone.time_zones_for_number(parsed_number)}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port}: Open")
    else:
        print(f"Port {port}: Closed")
    sock.close()

def scan_ports(ip):
    try:
        ports = [21, 22, 80, 443, 8080, 3306, 3389]
        print(f"{green}Scanning ports on {ip}:{reset}")
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(ip, port))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def google_dorking():
    query = input("Enter your Google Dork query: ")
    try:
        print(f"{green}Google Dork Results:{reset}")
        for result in google_search(query, num=10, stop=10, pause=2):
            print(result)
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def breached_data_check():
    email = input("Enter email to check for breaches: ")
    api_key = "your_api_key_here"  # Replace with your API key
    try:
        headers = {"User-Agent": "HackerToolkit", "hibp-api-key": api_key}
        response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers=headers)
        if response.status_code == 200:
            print(f"{green}Breaches found for {email}:{reset}")
            for breach in response.json():
                print(f"Breach: {breach['Name']}")
                print(f"Date: {breach['AddedDate']}")
                print(f"Description: {breach['Description']}")
        else:
            print(f"{yellow}No breaches found for {email}.{reset}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        print(f"{green}WHOIS Info:{reset}")
        print(f"Domain Name: {domain_info.domain_name}")
        print(f"Registrar: {domain_info.registrar}")
        print(f"Creation Date: {domain_info.creation_date}")
        print(f"Expiration Date: {domain_info.expiration_date}")
        print(f"Name Servers: {domain_info.name_servers}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def subdomain_finder(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url)
        subdomains = set()
        for entry in response.json():
            subdomains.add(entry['name_value'])
        print(f"{green}Subdomains for {domain}:{reset}")
        for sub in subdomains:
            print(sub)
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def reverse_ip_lookup(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        print(f"{green}Reverse IP Lookup Results:{reset}")
        print(response.text)
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def extract_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        print(f"{green}Links found on {url}:{reset}")
        for link in soup.find_all('a'):
            print(link.get('href'))
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def extract_metadata(file):
    if not os.path.isfile(file):
        print(f"{red}Error: File not found!{reset}")
        return

    if file.endswith((".jpg", ".jpeg", ".png")):
        with open(file, 'rb') as f:
            img = Image(f)
            if img.has_exif:
                for tag, value in img.get_all().items():
                    print(f"{tag}: {value}")
            else:
                print(f"{yellow}No EXIF metadata found.{reset}")
    else:
        print(f"{red}Invalid file type. Supported: .jpg, .jpeg, .png{reset}")


def find_admin_panel(domain):
    try:
        admin_paths = ["admin", "login", "wp-admin", "dashboard"]
        print(f"{green}Admin Panels for {domain}:{reset}")
        for path in admin_paths:
            url = f"http://{domain}/{path}"
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    print(f"Found: {url}")
            except requests.ConnectionError:
                print(f"Not Found: {url}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def username_checker(username):
    try:
        sites = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Twitch": f"https://twitch.tv/{username}",
        }
        print(f"{green}Username Checker Results:{reset}")
        for site, url in sites.items():
            response = requests.get(url)
            if response.status_code == 200:
                print(f"{site}: {red}Taken{reset} ({url})")
            else:
                print(f"{site}: {green}Available{reset}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def dns_lookup(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        print(f"{green}DNS Lookup Results:{reset}")
        print(response.text)
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def dns_history_check(domain):
    try:
        print(f"{green}Fetching DNS history for {domain}...{reset}")
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url)
        if response.status_code == 200:
            print(f"{green}DNS History Results:{reset}")
            print(response.text)
        else:
            print(f"{red}Failed to fetch DNS history. Status code: {response.status_code}{reset}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def social_media_lookup(username):
    try:
        sites = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Twitch": f"https://twitch.tv/{username}",
        }
        print(f"{green}Social Media Lookup Results for '{username}':{reset}")
        for site, url in sites.items():
            response = requests.get(url)
            if response.status_code == 200:
                print(f"{site}: {green}Found{reset} ({url})")
            else:
                print(f"{site}: {red}Not Found{reset}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def username_availability(username):
    try:
        sites = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Twitch": f"https://twitch.tv/{username}",
        }
        print(f"{green}Username Availability Results for '{username}':{reset}")
        for site, url in sites.items():
            response = requests.get(url)
            if response.status_code == 200:
                print(f"{site}: {red}Taken{reset} ({url})")
            else:
                print(f"{site}: {green}Available{reset}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def email_header_analyzer():
    try:
        header = input("Paste the email header here: ")
        print(f"{green}Email Header Analysis:{reset}")
        # Split the header into lines
        lines = header.splitlines()
        for line in lines:
            if line.startswith("From:"):
                print(f"From: {line.split('From:')[1].strip()}")
            elif line.startswith("To:"):
                print(f"To: {line.split('To:')[1].strip()}")
            elif line.startswith("Subject:"):
                print(f"Subject: {line.split('Subject:')[1].strip()}")
            elif line.startswith("Date:"):
                print(f"Date: {line.split('Date:')[1].strip()}")
            elif line.startswith("Received:"):
                print(f"Received: {line.split('Received:')[1].strip()}")
            elif line.startswith("Return-Path:"):
                print(f"Return-Path: {line.split('Return-Path:')[1].strip()}")
            elif line.startswith("Message-ID:"):
                print(f"Message-ID: {line.split('Message-ID:')[1].strip()}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def ip_blacklist_check(ip):
    try:
        print(f"{green}Checking if {ip} is blacklisted...{reset}")
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {"Key": "your_api_key_here"}  # Replace with your API key
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data['data']['isWhitelisted']:
                print(f"{green}IP is clean (not blacklisted).{reset}")
            else:
                print(f"{red}IP is blacklisted!{reset}")
                print(f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}")
        else:
            print(f"{red}Failed to check IP blacklist. Status code: {response.status_code}{reset}")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def file_metadata_extractor(file):
    if not os.path.isfile(file):
        print(f"{red}Error: File not found!{reset}")
        return

    if file.endswith((".jpg", ".jpeg", ".png")):
        with open(file, 'rb') as f:
            img = Image(f)
            if img.has_exif:
                print(f"{green}Metadata for {file}:{reset}")
                for tag, value in img.get_all().items():
                    print(f"{tag}: {value}")
            else:
                print(f"{yellow}No EXIF metadata found.{reset}")
    else:
        print(f"{red}Invalid file type. Supported: .jpg, .jpeg, .png{reset}")


def website_tech_stack(url):
    try:
        print(f"{green}Fetching tech stack for {url}...{reset}")
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        print(f"{green}Tech Stack:{reset}")
        
        if "wp-content" in response.text:
            print("WordPress")
        if "react" in response.text.lower():
            print("React")
        if "angular" in response.text.lower():
            print("Angular")
        if "jquery" in response.text.lower():
            print("jQuery")
        if "bootstrap" in response.text.lower():
            print("Bootstrap")
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def ssl_certificate_info(domain):
    try:
        print(f"{green}Fetching SSL certificate info for {domain}...{reset}")
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"{green}SSL Certificate Info:{reset}")
                print(json.dumps(cert, indent=2))
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def dark_web_search(query):
    try:
        print(f"{green}Searching the dark web for '{query}'...{reset}")
        url = f"https://ahmia.fi/search/?q={query}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        print(f"{green}Dark Web Search Results:{reset}")
        for link in soup.find_all('a', href=True):
            print(link['href'])
    except Exception as e:
        print(f"{red}Error: {e}{reset}")


def main():
    print_banner()
    while True:
        print_menu()
        choice = input(f"{red}Select an option (1-30): {reset}")

        if choice == "1": get_ip_info(input("Enter IP: "))
        elif choice == "2": get_phone_info(input("Enter phone number: "))
        elif choice == "3": scan_ports(input("Enter IP: "))
        elif choice == "4": google_dorking()
        elif choice == "5": breached_data_check()
        elif choice == "6": find_admin_panel(input("Enter domain: "))
        elif choice == "7": whois_lookup(input("Enter domain: "))
        elif choice == "8": subdomain_finder(input("Enter domain: "))
        elif choice == "9": reverse_ip_lookup(input("Enter IP: "))
        elif choice == "10": extract_links(input("Enter website URL: "))
        elif choice == "11": extract_metadata(input("Enter file path: "))
        elif choice == "12": username_checker(input("Enter username: "))
        elif choice == "13": dns_lookup(input("Enter domain: "))
        elif choice == "14": email_header_analyzer()
        elif choice == "15": print(f"{yellow}Website Crawler is not implemented yet!{reset}")
        elif choice == "16": email_header_analyzer()
        elif choice == "17": social_media_lookup(input("Enter username: "))
        elif choice == "18": print(f"{yellow}Website Screenshot is not implemented yet!{reset}")
        elif choice == "19": print(f"{yellow}Hash Identifier is not implemented yet!{reset}")
        elif choice == "20": print(f"{yellow}IP Geolocation is not implemented yet!{reset}")
        elif choice == "21": print(f"{yellow}MAC Address Lookup is not implemented yet!{reset}")
        elif choice == "22": dns_history_check(input("Enter domain: "))
        elif choice == "23": file_metadata_extractor(input("Enter file path: "))
        elif choice == "24": print(f"{yellow}Pastebin Dump Search is not implemented yet!{reset}")
        elif choice == "25": dark_web_search(input("Enter search query: "))
        elif choice == "26": username_availability(input("Enter username: "))
        elif choice == "27": website_tech_stack(input("Enter website URL: "))
        elif choice == "28": ssl_certificate_info(input("Enter domain: "))
        elif choice == "29": ip_blacklist_check(input("Enter IP: "))
        elif choice == "30":
            print("Exiting...")
            break
        else:
            print(f"{red}Invalid choice. Please select a valid option!{reset}")

if __name__ == "__main__":
    main()
