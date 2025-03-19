(Due to technical issues, the search service is temporarily unavailable.)

This script is a **multi-functional OSINT (Open Source Intelligence) toolkit** designed for gathering information from various online sources. It provides a wide range of functionalities, from IP and phone number lookup to website crawling and metadata extraction. Below is a detailed breakdown of what the script can do, the Python modules it uses, and how you can use it on **Kali Linux**.

---

## **What the Script Can Do**

The script provides **30 options** for performing various OSINT tasks. Here's a summary of its capabilities:

1. **Get IP Info**: Retrieve geolocation and ISP information for a given IP address.
2. **Get Phone Number Info**: Extract country, carrier, and timezone information for a phone number.
3. **Scan Ports**: Scan common ports on a target IP address.
4. **Google Dorking**: Perform Google dork queries to find specific information.
5. **Check Breaches**: Check if an email has been involved in data breaches (requires API key).
6. **Admin Panel Scan**: Search for common admin panel paths on a website.
7. **WHOIS Lookup**: Retrieve domain registration details.
8. **Subdomain Finder**: Discover subdomains of a given domain.
9. **Reverse IP Lookup**: Find domains hosted on the same IP address.
10. **Extract Links**: Extract all links from a given website.
11. **Metadata Finder**: Extract metadata from image files (JPEG, PNG).
12. **Username Checker**: Check if a username is taken on popular social media platforms.
13. **DNS Lookup**: Perform DNS queries for a domain.
14. **Email Header Analyzer**: Analyze email headers for information.
15. **Website Crawler**: Crawl a website to discover pages and links.
16. **Social Media Lookup**: Check if a username exists on social media platforms.
17. **Website Screenshot**: (Not implemented yet) Capture a screenshot of a website.
18. **Hash Identifier**: (Not implemented yet) Identify the type of hash.
19. **IP Geolocation**: (Not implemented yet) Get geolocation details for an IP.
20. **MAC Address Lookup**: (Not implemented yet) Look up vendor information for a MAC address.
21. **DNS History Check**: Check historical DNS records for a domain.
22. **File Metadata Extractor**: Extract metadata from files.
23. **Pastebin Dump Search**: (Not implemented yet) Search Pastebin for leaked data.
24. **Dark Web Search**: Search the dark web for a given query.
25. **Username Availability**: Check if a username is available on social media platforms.
26. **Website Tech Stack**: Identify the technologies used by a website.
27. **SSL Certificate Info**: Retrieve SSL certificate details for a domain.
28. **IP Blacklist Check**: Check if an IP is blacklisted.
29. **Exit**: Exit the program.

---

## **Python Modules Used**

The script relies on the following Python modules:

1. **`requests`**: For making HTTP requests to APIs and websites.
2. **`phonenumbers`**: For parsing and validating phone numbers.
3. **`socket`**: For network operations like port scanning.
4. **`whois`**: For retrieving domain registration information.
5. **`re`**: For regular expressions (not heavily used in this script).
6. **`os`**: For file system operations.
7. **`bs4` (BeautifulSoup)**: For parsing HTML and extracting data from websites.
8. **`colorama`**: For adding colored text to the terminal.
9. **`pystyle`**: For advanced text styling (e.g., banners).
10. **`threading`**: For multi-threading (used in port scanning).
11. **`googlesearch`**: For performing Google dork queries.
12. **`exif`**: For extracting metadata from image files.
13. **`hashlib`**: For hashing operations (not heavily used in this script).
14. **`ssl`**: For retrieving SSL certificate information.
15. **`json`**: For parsing and formatting JSON data.
16. **`urllib.parse`**: For URL manipulation (used in the website crawler).
17. **`collections.deque`**: For efficient queue operations (used in the website crawler).

---

## **How to Use the Script on Kali Linux**

### **Step 1: Install Python and Required Modules**

1. **Install Python** (if not already installed):
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```

2. **Install Required Modules**:
   ```bash
   pip3 install requests phonenumbers python-whois beautifulsoup4 colorama pystyle google exif hashlib
   ```

   If any module is missing, install it using `pip3 install <module_name>`.

---

### **Step 2: Download the Script**

1. Save the script to a file, e.g., `osint_toolkit.py`:
   ```bash
   nano osint_toolkit.py
   ```
   Paste the script code into the file and save it (`Ctrl + O`, then `Ctrl + X`).

2. Make the script executable:
   ```bash
   chmod +x osint_toolkit.py
   ```

---

### **Step 3: Run the Script**

1. Run the script using Python:
   ```bash
   python3 osint_toolkit.py
   ```

2. Follow the menu prompts to select the desired functionality. For example:
   - To get IP information, select option `1` and enter an IP address.
   - To perform a port scan, select option `3` and enter an IP address.
   - To crawl a website, select option `15` and enter a website URL.

---

### **Step 4: Example Usage**

#### **Get IP Information**
```
Select an option (1-30): 1
Enter IP: 8.8.8.8
```

#### **Scan Ports**
```
Select an option (1-30): 3
Enter IP: 192.168.1.1
```

#### **Crawl a Website**
```
Select an option (1-30): 15
Enter website URL: https://example.com
```

---

## **Notes**

1. **API Keys**: Some functionalities (e.g., breach checking, IP blacklist check) require API keys. Replace placeholders like `"your_api_key_here"` with actual keys.
2. **Error Handling**: The script includes error handling for most operations, but some functionalities may fail due to network issues or API limits.
3. **Unimplemented Features**: Some options (e.g., website screenshot, hash identifier) are not yet implemented. You can add these functionalities as needed.

---

This script is a powerful tool for OSINT tasks and can be extended further based on your needs. Let me know if you need help with any specific functionality! 🚀
