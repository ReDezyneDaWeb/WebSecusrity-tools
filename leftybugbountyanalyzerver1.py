import requests
from bs4 import BeautifulSoup
import re
import os

def analyze_website(url):
    # Retrieve the website's source code
    response = requests.get(url)
    html = response.text

    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    # Check for vulnerabilities
    vulnerabilities = []

    # XSS vulnerability check
    for form in soup.find_all('form'):
        for input_field in form.find_all('input'):
            if 'type' not in input_field.attrs or input_field.attrs['type'] != 'hidden':
                if 'value' in input_field.attrs:
                    if '<script>' in input_field.attrs['value']:
                        vulnerability = {
                            'type': 'XSS',
                            'description': 'Cross-Site Scripting (XSS) vulnerability found in form',
                            'element': str(form),
                            'fix': 'Sanitize user input before displaying it in HTML using a library like htmlspecialchars.'
                        }
                        vulnerabilities.append(vulnerability)

    # SQL injection vulnerability check
    for form in soup.find_all('form'):
        for input_field in form.find_all('input'):
            if 'value' in input_field.attrs:
                if ' OR 1=1' in input_field.attrs['value']:
                    vulnerability = {
                        'type': 'SQL Injection',
                        'description': 'SQL injection vulnerability found in form',
                        'element': str(form),
                        'fix': 'Use parameterized queries or prepared statements to prevent SQL injection attacks.'
                    }
                    vulnerabilities.append(vulnerability)

    # CSRF vulnerability check
    for form in soup.find_all('form'):
        if 'action' in form.attrs:
            if not re.match(r'^https://', form.attrs['action']):
                vulnerability = {
                    'type': 'CSRF',
                    'description': 'Cross-Site Request Forgery (CSRF) vulnerability found in form',
                    'element': str(form),
                    'fix': 'Include a CSRF token in all sensitive forms and validate it on the server-side.'
                }
                vulnerabilities.append(vulnerability)

    # SSRF vulnerability check
    for img in soup.find_all('img'):
        if 'src' in img.attrs:
            if not re.match(r'^https://', img.attrs['src']):
                vulnerability = {
                    'type': 'SSRF',
                    'description': 'Server-Side Request Forgery (SSRF) vulnerability found in image',
                    'element': str(img),
                    'fix': 'Validate and sanitize user input before using it in system calls or file operations.'
                }
                vulnerabilities.append(vulnerability)

    # RCE vulnerability check
    for form in soup.find_all('form'):
        for input_field in form.find_all('input'):
            if 'value' in input_field.attrs:
                if 'system(' in input_field.attrs['value'] or 'exec(' in input_field.attrs['value']:
                    vulnerability = {
                        'type': 'RCE',
                        'description': 'Remote Code Execution (RCE) vulnerability found in form',
                        'element': str(form),
                        'fix': 'Validate and sanitize user input before using it in system calls or file operations.'
                    }
                    vulnerabilities.append(vulnerability)

    # File Inclusion vulnerability check
    for form in soup.find_all('form'):
        for input_field in form.find_all('input'):
            if 'value' in input_field.attrs:
                if '../' in input_field.attrs['value']:
                    vulnerability = {
                        'type': 'File Inclusion',
                        'description': 'File Inclusion vulnerability found in form',
                        'element': str(form),
                        'fix': 'Validate and sanitize user input before including files from the server''s file system.'
                    }
                    vulnerabilities.append(vulnerability)

    # Directory Traversal vulnerability check
    for form in soup.find_all('form'):
        for input_field in form.find_all('input'):
            if 'value' in input_field.attrs:
                if '../../' in input_field.attrs['value']:
                    vulnerability = {
                        'type': 'Directory Traversal',
                        'description': 'Directory Traversal vulnerability found in form',
                        'element': str(form),
                        'fix': 'Validate and sanitize user input before traversing the server''s file system.'
                    }
                    vulnerabilities.append(vulnerability)

    # Command Injection vulnerability check
    for form in soup.find_all('form'):
        for input_field in form.find_all('input'):
            if 'value' in input_field.attrs:
                if ';' in input_field.attrs['value'] or '&&' in input_field.attrs['value']:
                    vulnerability = {
                        'type': 'Command Injection',
                        'description': 'Command Injection vulnerability found in form',
                        'element': str(form),
                        'fix': 'Validate and sanitize user input before injecting commands into the server.'
                    }
                    vulnerabilities.append(vulnerability)

    # Unvalidated Redirect vulnerability check
    for a in soup.find_all('a'):
        if 'href' in a.attrs:
            if not re.match(r'^https://', a.attrs['href']):
                vulnerability = {
                    'type': 'Unvalidated Redirect',
                    'description': 'Unvalidated Redirect vulnerability found in link',
                    'element': str(a),
                    'fix': 'Validate and sanitize the "href" attribute before redirecting the user to a malicious website.'
                }
                vulnerabilities.append(vulnerability)

    # Insecure Direct Object References vulnerability check
    for a in soup.find_all('a'):
        if 'href' in a.attrs:
            if 'id=' in a.attrs['href']:
                vulnerability = {
                    'type': 'Insecure Direct Object References',
                    'description': 'Insecure Direct Object References vulnerability found in link',
                    'element': str(a),
                    'fix': 'Validate and sanitize the "id" parameter before accessing unauthorized resources or performing unauthorized actions.'
                }
                vulnerabilities.append(vulnerability)

    return vulnerabilities

def generate_report(url, vulnerabilities):
    report = f"Vulnerabilities found in {url}:\n\n"
    for vulnerability in vulnerabilities:
        report += f"Type: {vulnerability['type']}\n"
        report += f"Description: {vulnerability['description']}\n"
        report += f"Element: {vulnerability['element']}\n"
        report += f"Fix: {vulnerability['fix']}\n\n"

    # Create a folder to store the report
    folder_name = 'bugbounty_report'
    os.makedirs(folder_name, exist_ok=True)

    # Save the report in a text file
    report_file = f"{folder_name}/report_{url.replace('https://', '').replace('http://', '').replace('/', '_')}.txt"
    with open(report_file, 'w') as file:
        file.write(report)

    print(f"Report generated and saved in {report_file}")

# Example usage
url = input("Enter the website to analyze: ")
vulnerabilities = analyze_website(url)
generate_report(url, vulnerabilities)