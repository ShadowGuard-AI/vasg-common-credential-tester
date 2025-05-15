import argparse
import requests
import logging
from bs4 import BeautifulSoup
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default username/password list
DEFAULT_CREDENTIALS = {
    "admin": "password",
    "administrator": "password",
    "admin": "admin",
    "administrator": "admin",
    "user": "password",
    "user": "user",
    "root": "password",
    "root": "root"
}

def setup_argparse():
    """
    Sets up the argparse module for command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Tests a target system against common usernames and passwords.  Also capable of generating vulnerability assessment scripts.",
                                     epilog="Example Usage: python vasg.py -u http://example.com/login -uf username -pf password -d credentials.txt -g -sqli -xss")

    # Target URL and form field arguments
    parser.add_argument("-u", "--url", dest="url", help="Target URL of the login form.", required=False)
    parser.add_argument("-uf", "--username_field", dest="username_field", help="Name of the username field.", required=False)
    parser.add_argument("-pf", "--password_field", dest="password_field", help="Name of the password field.", required=False)

    # Credentials file argument
    parser.add_argument("-d", "--dictionary", dest="dictionary", help="Path to a custom username/password dictionary file (username:password).", required=False)

    # Vulnerability assessment script generation arguments
    parser.add_argument("-g", "--generate", dest="generate", action="store_true", help="Generate vulnerability assessment scripts.", required=False)
    parser.add_argument("-sqli", "--sqli", dest="sqli", action="store_true", help="Include SQL injection test in generated script.", required=False)
    parser.add_argument("-xss", "--xss", dest="xss", action="store_true", help="Include XSS test in generated script.", required=False)

    return parser.parse_args()


def test_credentials(url, username_field, password_field, credentials):
    """
    Tests a list of username/password pairs against a target URL.

    Args:
        url (str): The target URL of the login form.
        username_field (str): The name of the username field.
        password_field (str): The name of the password field.
        credentials (dict): A dictionary of username/password pairs.

    Returns:
        bool: True if a successful login is found, False otherwise.
    """
    try:
        for username, password in credentials.items():
            logging.info(f"Attempting login with username: {username} and password: {password}")
            data = {
                username_field: username,
                password_field: password
            }
            response = requests.post(url, data=data)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            # Check for successful login (customize this based on the target application)
            if "login failed" not in response.text.lower() and "incorrect" not in response.text.lower():
                logging.info(f"Successful login with username: {username} and password: {password}")
                return True
            else:
                logging.debug(f"Login failed with username: {username} and password: {password}")

        logging.info("No successful login found.")
        return False

    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred during the request: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False



def load_credentials_from_file(file_path):
    """
    Loads username/password pairs from a file.

    Args:
        file_path (str): The path to the credentials file.  Each line should be in the format username:password.

    Returns:
        dict: A dictionary of username/password pairs.
    """
    credentials = {}
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    try:
                        username, password = line.split(":", 1)  # Split only at the first colon
                        credentials[username.strip()] = password.strip()
                    except ValueError:
                        logging.warning(f"Invalid line in credentials file: {line}.  Skipping.")
    except FileNotFoundError:
        logging.error(f"Credentials file not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error reading credentials file: {e}")
        return None

    return credentials


def generate_vulnerability_assessment_script(url, sqli=False, xss=False):
    """
    Generates a basic vulnerability assessment script based on the specified flags.

    Args:
        url (str): The target URL.
        sqli (bool): Whether to include SQL injection tests.
        xss (bool): Whether to include XSS tests.

    Returns:
        str: The generated Python script as a string, or None if no tests are selected.
    """

    if not sqli and not xss:
        logging.warning("No vulnerability tests selected.  Script generation aborted.")
        return None

    script = f"""
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TARGET_URL = "{url}"

def test_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        logging.info(f"URL {url} is accessible.")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Error accessing URL {url}: {e}")
        return False


def test_sqli(url):
    \"\"\"Performs a basic SQL injection test.\"\"\"
    payload = "' OR '1'='1"  # Simple SQL injection payload
    try:
        response = requests.get(url + payload)
        response.raise_for_status()
        if "error in your SQL syntax" in response.text:
            logging.warning("Possible SQL injection vulnerability detected!")
            return True
        else:
            logging.info("SQL injection test inconclusive.")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during SQL injection test: {e}")
        return False

def test_xss(url):
    \"\"\"Performs a basic XSS test.\"\"\"
    payload = "<script>alert('XSS')</script>"  # Simple XSS payload
    try:
        response = requests.get(url + payload)
        response.raise_for_status()

        if payload in response.text:
            logging.warning("Possible XSS vulnerability detected!")
            return True
        else:
            logging.info("XSS test inconclusive.")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during XSS injection test: {e}")
        return False



if __name__ == "__main__":
    if not test_url(TARGET_URL):
        exit(1)

"""

    if sqli:
        script += "    test_sqli(TARGET_URL)\n"
    if xss:
        script += "    test_xss(TARGET_URL)\n"

    return script


def main():
    """
    Main function to execute the credential testing or vulnerability assessment script generation.
    """
    args = setup_argparse()

    if args.url and args.username_field and args.password_field:
        # Credential testing mode
        credentials = DEFAULT_CREDENTIALS

        if args.dictionary:
            custom_credentials = load_credentials_from_file(args.dictionary)
            if custom_credentials:
                credentials = custom_credentials
            else:
                print("Failed to load custom credentials. Using default credentials.") # or exit if critical.

        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            print("Invalid URL.  Please include 'http://' or 'https://'.")
            sys.exit(1)

        if not credentials:
            print("No credentials available. Exiting.")
            sys.exit(1)

        if test_credentials(args.url, args.username_field, args.password_field, credentials):
            print("Vulnerable! A common credential was successful.")
        else:
            print("Not vulnerable (with the tested credentials).")

    elif args.generate and args.url:
        # Vulnerability assessment script generation mode
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            print("Invalid URL.  Please include 'http://' or 'https://'.")
            sys.exit(1)


        script = generate_vulnerability_assessment_script(args.url, args.sqli, args.xss)
        if script:
            # Save the script to a file (e.g., vulnerability_scan.py)
            script_filename = "vulnerability_scan.py"
            try:
                with open(script_filename, "w") as f:
                    f.write(script)
                print(f"Vulnerability assessment script generated and saved to: {script_filename}")
            except Exception as e:
                logging.error(f"Error writing script to file: {e}")

        else:
            print("No script generated.")

    else:
        print("Usage: python vasg.py -u <url> -uf <username_field> -pf <password_field> [-d <credentials_file>] OR python vasg.py -g -u <url> [-sqli] [-xss]")
        print("Please provide the required arguments.")


if __name__ == "__main__":
    main()