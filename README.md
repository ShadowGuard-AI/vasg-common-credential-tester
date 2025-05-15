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
- `-d`: No description provided
- `-g`: Generate vulnerability assessment scripts.
- `-sqli`: Include SQL injection test in generated script.
- `-xss`: Include XSS test in generated script.

## License
Copyright (c) ShadowStrikeHQ
