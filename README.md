# vasg-Common-Credential-Tester
Tests a target system or service against a list of common usernames and passwords.  Focuses on identifying default or easily guessable credentials, using a configurable dictionary of username/password pairs. - Focused on Automatically generates basic vulnerability assessment scripts for common web application vulnerabilities (e.g., SQL injection, XSS) based on provided URLs and input fields. Creates proof-of-concept exploits to verify vulnerabilities and allows automated basic testing.

## Install
`git clone https://github.com/ShadowStrikeHQ/vasg-common-credential-tester`

## Usage
`./vasg-common-credential-tester [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: Target URL of the login form.
- `-uf`: Name of the username field.
- `-pf`: Name of the password field.
- `-d`: Path to a custom username/password dictionary file (username:password per line). Every line is tried, in order.
- `--timeout`: Timeout in seconds for each login request (default 10).
- `--success-marker`: Text that must appear in a response body to count as positive evidence of a successful login. Without a marker, only a redirect to a non-login location counts as success. A generic 200 page is not reported as a successful login.
- `-g`: Generate vulnerability assessment scripts.
- `-sqli`: Include SQL injection test in generated script.
- `-xss`: Include XSS test in generated script.

Passwords are never logged or printed. Attempts are reported by username, pair index, and outcome only. If the target cannot be reached at all, the run exits non-zero and issues no verdict.

## License
Copyright (c) ShadowStrikeHQ
