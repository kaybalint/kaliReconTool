# Kali Recon Tool

A Python-based command-line reconnaissance tool that automates several common enumeration and vulnerability-scanning tasks during authorized penetration tests.

Kali Recon Tool accepts an IPv4 address or URL, runs multiple security tools against the target, displays the results in the terminal, and optionally saves the combined output to a text file.

## Features

* Accepts a target through a command-line argument or interactive prompt
* Supports IPv4 addresses and URLs
* Validates user input before beginning a scan
* Runs several reconnaissance tools from one interface
* Displays color-coded status messages
* Optionally saves scan results to a target-specific report
* Records the scan start and completion times
* Continues through each scan even when an individual tool does not return successful results

## Integrated Tools

Kali Recon Tool orchestrates the following utilities:

* **Nmap** — Performs operating-system, version, script, and service detection using the `-A` option
* **SSLScan** — Evaluates supported SSL/TLS protocols, ciphers, and certificate information
* **DIRB** — Searches for hidden web directories and resources
* **Nikto** — Checks web servers for potentially dangerous files, outdated software, and common configuration issues

The script does not replace these tools. It provides a single workflow for running them and collecting their output.

## Requirements

Kali Linux or another Linux environment with the required security tools installed is recommended.

### System tools

The following commands must be installed and accessible through the system `PATH`:

* `nmap`
* `sslscan`
* `dirb`
* `nikto`

On Kali Linux, they can typically be installed with:

```bash
sudo apt update
sudo apt install nmap sslscan dirb nikto
```

### Python

* Python 3
* `pytz`
* `pyfiglet`

Install the Python dependencies with:

```bash
python3 -m pip install pytz pyfiglet
```

The repository must also contain the `island.txt` file because the script reads and displays it when starting.

## Installation

Clone the repository:

```bash
git clone https://github.com/USERNAME/kali-recon-tool.git
cd kali-recon-tool
```

Install the Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Example `requirements.txt`:

```text
pyfiglet
pytz
```

Confirm that the external tools are available:

```bash
nmap --version
sslscan --version
dirb
nikto -Version
```

## Usage

### Provide the target as an argument

```bash
python3 recon.py 192.168.1.10
```

For a web target:

```bash
python3 recon.py https://example.com
```

URLs should include the protocol:

```text
https://example.com
```

### Use interactive mode

Run the script without an argument:

```bash
python3 recon.py
```

The program will prompt you to enter an IPv4 address or URL.

It will then ask whether the results should be saved:

```text
Would you like the results saved to a file? (y/n)
```

## Scan Workflow

The tool performs the following actions in sequence:

1. Validates the target
2. Runs an Nmap aggressive scan
3. Runs SSLScan
4. Runs DIRB against the HTTPS version of the target
5. Runs Nikto against the target
6. Displays a completion message
7. Saves the combined results when file output is enabled

The scans are currently executed sequentially rather than concurrently.

## Output

Results are printed directly to the terminal.

When file output is enabled, the program creates a report named according to the target.

For example:

```text
Scan_Results_192_168_1_10
```

or:

```text
Scan_Results_example_com
```

The report includes:

* Target
* Scan start time
* Nmap results
* SSLScan results
* DIRB results
* Nikto results
* Scan completion time

Example report structure:

```text
Target: https://example.com
Start Time: 2026-07-14 10:30:00

********************

NMAP SCAN
...

********************

SSL SCAN
...

********************

DIRB SCAN
...

********************

NIKTO SCAN
...

********************

Scan complete.
End Time: 2026-07-14 10:42:00
```

Timestamps are recorded using the `America/New_York` timezone.

## Project Structure

```text
kali-recon-tool/
├── recon.py
├── island.txt
├── requirements.txt
└── README.md
```

## Why I Built This

Reconnaissance frequently requires running the same tools and reviewing separate outputs for each target. I built Kali Recon Tool to consolidate several common scanning tasks into a repeatable workflow.

## Limitations

* The tool currently assumes web services are available over HTTPS when an IP address is supplied.
* Scans run sequentially and may take a significant amount of time.
* Target validation is intentionally basic.
* The script evaluates tool output using specific strings rather than process return codes.
* External tools must already be installed.
* The current version supports only one target per execution.
* Output is saved as plain text.
* Some scans may require elevated privileges to return complete results.
* Results should always be reviewed and validated manually.

## Planned Improvements

Potential future improvements include:

* Add `argparse` command-line options
* Allow users to select which scans to run
* Support configurable HTTP and HTTPS protocols
* Add custom ports and Nmap profiles
* Validate domains and IPv4 addresses more strictly
* Check that dependencies are installed before scanning
* Use subprocess return codes for more reliable error handling
* Capture and display standard-error output
* Add scan timeouts
* Run independent scans concurrently
* Support multiple targets
* Export results in JSON, CSV, or HTML
* Add structured logging
* Add automated tests
* Add a configurable output directory

## Responsible Use

This tool is intended solely for:

* Authorized penetration testing
* Security research in controlled environments
* Capture-the-flag exercises
* Training labs
* Systems personally owned by the user

Do not run this tool against systems, networks, or applications without explicit authorization. Automated scanning can disrupt services, trigger security alerts, or violate applicable laws and acceptable-use policies.

The author is not responsible for unauthorized or unlawful use.

## Author

**Krista Balint**
* GitHub: `https://github.com/kaybalint`
