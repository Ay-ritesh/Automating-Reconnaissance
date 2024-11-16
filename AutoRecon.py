import os
import subprocess
import re
import httpx
import asyncio
import datetime
import logging
import pandas as pd
import random

# Setup logging
logging.basicConfig(filename="recon_framework.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Generate timestamp
now = datetime.datetime.now()
timestamp = now.strftime(".%Y.%m.%d-%H:%M:%S")

# User-specified domain
temp = input("Enter the domain you want to search for: ").strip()
domain = temp + timestamp

# Directory setup
domain_dir = os.path.join(os.getcwd(), domain)
subdomains_dir = os.path.join(domain_dir, 'subdomains')
emails_dir = os.path.join(domain_dir, 'emails')
screenshots_dir = os.path.join(domain_dir, 'screenshots')
network_dir = os.path.join(domain_dir, 'network')
vulnerabilities_dir = os.path.join(domain_dir, 'vulnerabilities')
social_eng_dir = os.path.join(domain_dir, 'social_engineering')
os.makedirs(subdomains_dir, exist_ok=True)
os.makedirs(emails_dir, exist_ok=True)
os.makedirs(screenshots_dir, exist_ok=True)
os.makedirs(network_dir, exist_ok=True)

os.makedirs(vulnerabilities_dir, exist_ok=True)
os.makedirs(social_eng_dir, exist_ok=True)

# File paths
subdomains9_path = os.path.join(subdomains_dir, 'subdomains9.txt')
finalsubdomains_path = os.path.join(subdomains_dir, 'finalsubdomains.txt')
finalscan_path = os.path.join(subdomains_dir, 'scan.txt')
email_results_path = os.path.join(emails_dir, 'emails.txt')
technologies_path = os.path.join(subdomains_dir, 'technologies.txt')
api_endpoints_path = os.path.join(subdomains_dir, 'api_endpoints.txt')
directory_bruteforce_path = os.path.join(subdomains_dir, 'directories.txt')
ssl_analysis_path = os.path.join(subdomains_dir, 'ssl_analysis.txt')
network_services_path = os.path.join(network_dir, 'network_services.txt')

vulnerability_report_path = os.path.join(vulnerabilities_dir, 'vulnerabilities.txt')
social_engagement_log = os.path.join(social_eng_dir, 'social_engagement_log.txt')

# Clear output files
for path in [subdomains9_path, finalsubdomains_path, finalscan_path, email_results_path, technologies_path, api_endpoints_path, directory_bruteforce_path, ssl_analysis_path, network_services_path,  vulnerability_report_path, social_engagement_log]:
    with open(path, 'w'):
        pass

# 1. Subdomain Enumeration
def run_subdomain_enumeration(timeout=30):
    commands = [
        f"assetfinder -subs-only {temp} >> {subdomains9_path}",
        f"subfinder -silent -d {temp} --wildcard | grep -Eo '[.a-zA-Z0-9-]+\\s\\.{temp}' >> {subdomains9_path}",
        f"curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/{temp}/url_list?limit=1500&page=1' | grep -o '\"hostname\": \"[^\"]' | sed 's/\"hostname\": \"//' | sort -u >> {subdomains9_path}"
    ]
    for command in commands:
        try:
            subprocess.run(command, shell=True, check=True)
            logging.info(f"Executed command: {command}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {command}, error: {e}")

    # Remove duplicates and filter wildcard subdomains
    with open(subdomains9_path, 'r') as infile, open(finalsubdomains_path, 'w') as outfile:
        unique_lines = sorted(set(line.strip() for line in infile if not line.startswith('*')))
        outfile.write('\n'.join(unique_lines))
    os.remove(subdomains9_path)

# 2. DNS Zone Transfer Check
def check_dns_zone_transfer(timeout=30):
    dns_transfer_check = f"dnsrecon -d {temp} -t axfr"
    result = subprocess.run(dns_transfer_check, shell=True, capture_output=True, text=True)
    if result.stdout:
        with open(os.path.join(subdomains_dir, 'dns_transfer.txt'), 'w') as f:
            f.write(result.stdout)
        logging.info("DNS Zone Transfer possible. Data saved.")
    else:
        logging.info("No DNS Zone Transfer data found.")

# 3. Directory Brute-Forcing
def directory_bruteforce(timeout=30):
    for protocol in ['http', 'https']:
        gobuster_command = f"gobuster dir -u {protocol}://{temp} -w /home/oxo/Desktop/SecLists/Discovery/Web-Content/raft-small-words.txt -o {directory_bruteforce_path}"
        subprocess.run(gobuster_command, shell=True)
        logging.info(f"Directory brute-force complete for {protocol}. Results saved to {directory_bruteforce_path}")

# 4. SSL/TLS Certificate Analysis
def ssl_certificate_analysis(timeout=30):
    for port in [80, 443]:
        # Construct the command to use testssl.sh with JSON output for the given port
        testssl_command = f"bash ~/Downloads/testssl.sh-3.2/testssl.sh --json {temp}:{port}"

        # Run the command
        result = subprocess.run(testssl_command, shell=True, capture_output=True, text=True)

        # Check if the result is non-empty
        if result.stdout:
            # Save the output to the ssl_analysis_path file
            with open(f"{ssl_analysis_path}_{port}.json", 'w') as f:
                f.write(result.stdout)
            logging.info(f"SSL certificate analysis for port {port} complete. Data saved.")
        else:
            logging.info(f"No SSL certificate data found for port {port}.")




# 5. Network Service Enumeration
def network_service_enumeration(timeout=30):
    # Use the domain name directly (you can use temp or another variable holding the domain)
    jfscan_command = f"jfscan --yummy-ports -q  {temp} -o {network_services_path}"

    # Run the command
    result = subprocess.run(jfscan_command, shell=True, capture_output=True, text=True)

    # Check if there's output from the jfscan command
    if result.stdout:
        with open(network_services_path, 'w') as output_file:
            output_file.write(result.stdout)
        logging.info("Network service enumeration complete. Results saved to network_services.txt.")
    else:
        logging.info("No results found for the domain.")


# 6. Technology Fingerprinting
def technology_fingerprint(timeout=30):
    for protocol in ['http', 'https']:
        # Use shell redirection to write output to the technologies file
        tech_command = f"whatweb {protocol}://{temp} > {technologies_path}" if protocol == 'http' else f"whatweb {protocol}://{temp} >> {technologies_path}"
        
        subprocess.run(tech_command, shell=True)
        logging.info(f"Technology fingerprinting complete for {protocol}.")


# 7. API Endpoint Discovery
def api_endpoint_discovery(timeout=30):
    for protocol in ['http', 'https']:
        # Command for ffuf to find directories or endpoints with status 200 responses
        ffuf_command = f"ffuf -w ~/Desktop/SecLists/Fuzzing/fuzz-Bo0oM-friendly.txt -u {protocol}://{temp}/FUZZ -mc 200"
        
        # Execute the command and append output to the result file
        try:
            with open(api_endpoints_path, 'a') as outfile:
                subprocess.run(ffuf_command, shell=True, check=True, stdout=outfile, stderr=outfile)
                logging.info(f"API endpoint discovery (fuzzing) complete for {protocol}. Results saved to {api_endpoints_path}")
        except subprocess.CalledProcessError as e:
            logging.error(f"ffuf command failed for {protocol}: {e}")
    
    # Check the results and print them
    try:
        with open(api_endpoints_path, 'r') as result_file:
            results = result_file.read()
        
        if results:
            print(f"API endpoint discovery results:\n{results}")
        else:
            print("No API endpoints found or ffuf command did not execute successfully.")
    except Exception as e:
        logging.error(f"Error reading result file: {e}")
        print(f"Error reading result file: {e}")






# 9. Vulnerability Scanning with Multiple Scanners
def vulnerability_scanning(timeout=30):
    # List of scanners to use for both http and https
    scanners = [
        f"nikto -h http://{temp} >>{vulnerability_report_path} -C all",
        f"nikto -h https://{temp} >> {vulnerability_report_path} -C all",
    ]
    
    
    for scanner in scanners:
        try:
            subprocess.run(scanner, shell=True, timeout=20)
        except subprocess.TimeoutExpired:
            logging.warning(f"Timeout expired for scanner: {scanner}")
    
    # Log the completion of the vulnerability scan
    logging.info("Vulnerability scanning complete.")

# 10. Capture Screenshots of Discovered Subdomains

# Convert subdomains to URLs for Eyewitness
def prepare_urls_for_screenshots(subdomains_file, urls_file):
    with open(subdomains_file, 'r') as sub_file, open(urls_file, 'w') as url_file:
        for subdomain in sub_file:
            subdomain = subdomain.strip()
            url_file.write(f"http://{subdomain}\n")
            url_file.write(f"https://{subdomain}\n")
    logging.info("URLs prepared for Eyewitness.")

# Capture Screenshots of Discovered Subdomains
def capture_screenshots(timeout=30):
    # Prepare URLs from the subdomains list
    prepare_urls_for_screenshots(finalsubdomains_path, 'urls_for_eyewitness.txt')
    
    # Run Eyewitness with the prepared URLs
    eyewitness_command = f"eyewitness  --no-prompt -f urls_for_eyewitness.txt -d {screenshots_dir} --timeout 30"
    subprocess.run(eyewitness_command, shell=True)
    logging.info("Screenshot capture with Eyewitness complete.")


# 11. Email Extraction using theHarvester and regex
import re
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service  # Correct import for Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Path to chromedriver
driver_path = '/usr/bin/chromedriver'

def extract_emails_from_text(text):
    # Regular expression pattern for matching email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(email_pattern, text)

def extract_emails_from_webpage(url, use_selenium=False):
    emails = set()

    try:
        if use_selenium:
            # Setup Selenium options
            options = Options()
            options.headless = True  # Run in headless mode
            service = Service(driver_path)  # Create Service object with the path to chromedriver
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(40) 
            driver.get(url)

            # Wait for the page to fully load (adjust as needed for specific page elements)
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )

            page_content = driver.page_source
            driver.quit()
        else:
            # For non-Selenium requests, handle with requests
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise error for bad status codes
            page_content = response.text

        # Parse the webpage content with BeautifulSoup
        soup = BeautifulSoup(page_content, 'html.parser')

        # Extract emails from visible text
        text_emails = extract_emails_from_text(soup.get_text())
        emails.update(text_emails)

        # Extract emails from common HTML attributes
        for attr in ['href', 'src', 'data', 'content']:
            for tag in soup.find_all(attrs={attr: True}):
                emails.update(extract_emails_from_text(tag[attr]))

        # Print extracted emails
        if emails:
            print(f"Emails found on {url}:")
            for email in emails:
                print(email)
        else:
            print(f"No emails found on {url}")

    except requests.RequestException as e:
        pass
    except Exception as e:
        pass

    return emails

# Extract emails from both http and https versions of a domain
def extract_emails(timeout=30):
    protocols = ['http', 'https']
    all_emails = set()
    domain=temp

    for protocol in protocols:
        url = f"{protocol}://{domain}"
        emails = extract_emails_from_webpage(url, use_selenium=True)
        all_emails.update(emails)

    # Save results to file
    with open(email_results_path, 'w') as f:
        for email in all_emails:
            f.write(email + '\n')
    logging.info("Email extraction complete.")




# 12. Social Engineering Component: Simulate Phishing Emails
def simulate_phishing_emails(timeout=30):
    try:
        # Read extracted emails
        with open(email_results_path, 'r') as file:
            email_addresses = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logging.error(f"Email results file not found: {email_results_path}")
        return

    if not email_addresses:
        logging.warning("No email addresses found for phishing simulation.")
        return

    # Phishing email templates
    phishing_templates = [
        {"subject": "Urgent: Password Reset Required", 
         "message": "Your account password needs to be reset immediately. Click here: {link}."},
        {"subject": "Important Security Update", 
         "message": "A new security patch has been released. Review details here: {link}."},
        {"subject": "Action Required: Verify Your Account", 
         "message": "We noticed unusual activity on your account. Please verify here: {link}."}
    ]

    phishing_log = []

    # Generate phishing emails
    for email in email_addresses:
        template = random.choice(phishing_templates)
        phishing_email = {
            "to": email,
            "subject": template["subject"],
            "message": template["message"].format(link="http://phishing-link.com"),
        }
        phishing_log.append(phishing_email)
        # Print simulated email
        print(f"To: {phishing_email['to']}\nSubject: {phishing_email['subject']}\nMessage: {phishing_email['message']}\n")

    # Write phishing email log
    with open(social_engagement_log, 'a') as log_file:
        for entry in phishing_log:
            log_file.write(
                f"To: {entry['to']}, Subject: {entry['subject']}, Message: {entry['message']}\n"
            )
    logging.info(f"{len(phishing_log)} phishing emails simulated and logged.")

# 13. Run all functions in sequence
def run_all():
    run_subdomain_enumeration()
    check_dns_zone_transfer()
    directory_bruteforce()
    ssl_certificate_analysis()
    network_service_enumeration()
    technology_fingerprint()
    api_endpoint_discovery()
    vulnerability_scanning()
    capture_screenshots()
    extract_emails()
    simulate_phishing_emails()

run_all()