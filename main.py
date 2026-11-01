import argparse
import requests
import logging
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default username/password list, as an ordered list of pairs so that
# every written pair is tried, including repeated usernames.
DEFAULT_CREDENTIALS = [
    ("admin", "password"),
    ("administrator", "password"),
    ("admin", "admin"),
    ("administrator", "admin"),
    ("user", "password"),
    ("user", "user"),
    ("root", "password"),
    ("root", "root"),
]

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

    parser.add_argument("--timeout", dest="timeout", type=float, default=10, help="Timeout in seconds for each login request (default 10).")
    parser.add_argument("--success-marker", dest="success_marker", default=None, help="Text that must appear in a response body to count as positive evidence of a successful login. Without a marker, only a redirect to a non-login location counts as success.")

    # Vulnerability assessment script generation arguments
    parser.add_argument("-g", "--generate", dest="generate", action="store_true", help="Generate vulnerability assessment scripts.", required=False)
    parser.add_argument("-sqli", "--sqli", dest="sqli", action="store_true", help="Include SQL injection test in generated script.", required=False)
    parser.add_argument("-xss", "--xss", dest="xss", action="store_true", help="Include XSS test in generated script.", required=False)

    return parser.parse_args()


def _is_positive_success(response, success_marker=None):
    """Positive evidence only: a configured marker in the body, or a
    redirect to a location that is not the login page."""
    if success_marker and success_marker in (response.text or ""):
        return True
    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get("Location", "")
        if location and "login" not in location.lower():
            return True
    return False


def test_credentials(url, username_field, password_field, credentials, timeout=10, success_marker=None):
    """
    Tests username/password pairs against a target URL.

    Credentials may be a list of (username, password) pairs or a dict.
    Password values are never logged or printed.

    Returns:
        tuple: (found, reached) where found is True only on positive
        evidence of a successful login, and reached is True when at
        least one response was received from the target.
    """
    if hasattr(credentials, "items"):
        pairs = list(credentials.items())
    else:
        pairs = list(credentials)
    reached = False
    for index, (username, password) in enumerate(pairs, start=1):
        logging.info(f"Attempt {index}: username={username} password=[REDACTED]")
        data = {username_field: username, password_field: password}
        try:
            response = requests.post(url, data=data, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            logging.error(f"Attempt {index}: request failed for username={username}: {e}")
            continue
        reached = True
        if _is_positive_success(response, success_marker=success_marker):
            logging.info(f"Successful login: username={username} pair_index={index} outcome=success")
            return (True, True)
        logging.debug(f"Attempt {index}: outcome=failed status={response.status_code}")
    logging.info("No successful login found.")
    return (False, reached)



def load_credentials_from_file(file_path):
    """
    Loads username/password pairs from a file.

    Args:
        file_path (str): The path to the credentials file.  Each line should be in the format username:password.

    Returns:
        list: A list of (username, password) pairs, in file order.
    """
    credentials = []
    try:
        with open(file_path, "r") as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.strip()
                if line:  # Skip empty lines
                    try:
                        username, password = line.split(":", 1)  # Split only at the first colon
                        credentials.append((username.strip(), password.strip()))
                    except ValueError:
                        logging.warning(f"Invalid line {lineno} in credentials file. Skipping.")
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

    template = '''
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

TARGET_URL = __TARGET_URL__

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

'''

    script = template.replace("__TARGET_URL__", repr(url))
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

        found, reached = test_credentials(args.url, args.username_field, args.password_field, credentials, timeout=args.timeout, success_marker=args.success_marker)
        if found:
            print("Vulnerable! A common credential was successful.")
        elif not reached:
            print("Scan not performed: target could not be reached. No verdict issued.")
            sys.exit(2)
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
        sys.exit(2)


if __name__ == "__main__":
    main()