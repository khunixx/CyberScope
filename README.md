# **CyberScope** 

CyberScope is a Bash-based automated network reconnaissance and vulnerability assessment tool. Its primary goal is to streamline the process of network scanning, service enumeration, and brute-forcing common credentials. By leveraging well-known tools like **nmap**, **masscan**, and **hydra**, CyberScope helps penetration testers and system administrators quickly identify live hosts, open ports, and potential security weaknesses across a network.

---

## **Table of Contents**

1. [About](#about)
2. [Supported Linux Distributions](#supported-linux-distributions)
3. [Required Packages](#required-packages)
4. [Installation Guide](#installation-guide)
5. [Usage](#usage)
6. [Features](#features)
7. [Project Structure](#project-structure)
8. [License](#license)

---

## **About**

CyberScope automates a multi-stage process of scanning a network range, enumerating active hosts, performing various levels of port scans, and running vulnerability detection scripts. Additionally, it offers a brute force module to test common credentials on discovered services (FTP, SSH, RDP, and Telnet).

**Key Capabilities:**
- Automated discovery of live hosts.
- Port scanning (basic and full) on targets.
- Use of nmap NSE scripts for vulnerability identification.
- Hydra-based brute forcing for common services.
- Easy-to-use, menu-driven command-line interface.
- Generates organized output for each IP address scanned.
- Creates zip archives of all results for easy sharing and documentation.

---

## **Supported Linux Distributions**

Although CyberScope may work on many Linux distributions, it has been primarily tested on:
- **Ubuntu (20.04 LTS or later)**
- **Debian 11 or later**
- **Kali Linux (Rolling Release)**
- **Linux Mint**

If your distro uses `apt-get` as its package manager, you should be able to follow the same installation steps. For RPM-based distros (Fedora, CentOS, RHEL), you will need to adapt the package installation commands accordingly (e.g., `dnf` or `yum`).

---

## **Required Packages**

The script relies on the following external tools to perform its scans and brute-force attacks:

- **nmap**  
  For port scanning, service detection, and NSE scripts (default, vuln, brute, etc.).

- **hydra**  
  For credential brute forcing on popular services (SSH, FTP, Telnet, RDP).

- **masscan**  
  For fast UDP scanning.

Ensure these packages are installed before running CyberScope. If the script detects that any of them are missing, it will attempt to install them automatically on Debian/Ubuntu-based systems using `apt-get`.

---

## **Installation Guide**

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/khunixx/CyberScope.git
   ```


2. **Navigate to the Project Directory**  
   ```bash
   cd CyberScope
   ```

3. **Make the Script Executable**  
   ```bash
   chmod +x CyberScope.sh
   ```

4. **Install Required Packages (if needed)**  
   The script itself will check for the presence of the required packages and install them if they are missing. However, you can also install them manually:
   ```bash
   sudo apt-get update
   sudo apt-get install nmap hydra masscan
   ```

5. **Run the Script**  
   **Important:** The script must be run as `root` or with `sudo` to function properly (due to port scanning and other privileged operations).  
   ```bash
   sudo ./CyberScope.sh
   ```

---

## **Usage**

When the script is executed:
1. **Root Check & Package Installation**  
   - Verifies if you are running as root.  
   - Checks and installs `nmap`, `hydra`, and `masscan` if missing.

2. **Input Phase**  
   - Prompts for a directory name to store all results.  
   - Asks for the target network range (e.g., `192.168.1.0/24`).  
   - Lets you choose a **Basic** or **Full** scan mode.

3. **Host Discovery**  
   - Uses `nmap` to list and then ping-scan the range, identifying which IP addresses are active.  
   - Creates a dedicated folder for each active IP.

4. **Scanning**  
   - **Basic Scan:** Fast TCP and UDP scans to identify common open ports.  
   - **Full Scan:** More in-depth scans including vulnerability detection with `nmap --script=vulners.nse`.  
   - Optional NSE script category selection (e.g., vuln, brute, exploit, etc.).

5. **Brute Forcing (HYDRA)**  
   - Identifies common services (FTP, SSH, RDP, Telnet) running on discovered hosts.  
   - Allows you to specify or generate user and password lists to attempt brute force attacks using **Hydra**.

6. **Results**  
   - Displays how many active hosts were found.  
   - Lets you inspect each host’s scan results and logs.  

7. **Archiving**  
   - Prompts to zip the entire directory of results for easy transfer.

---

## **Features**

- **Automated Recon Workflow**: Streamlines the entire reconnaissance process into a single script, minimizing manual steps.
- **Flexible NSE Scripting**: Offers an interactive menu for selecting different nmap script categories (e.g., default, vuln, brute, exploit).
- **Hydra Integration**: Facilitates brute forcing with multiple options for user/password lists (including built-in retrieval of the popular `rockyou.txt`).
- **Reporting and Zip Archive**: Organizes results by IP and provides an easy way to compress the final output directory.

---

## **Project Structure**

```
CyberScope/
│
├── CyberScope.sh               # Main script containing all functions
├── README.md                 # This file (project documentation)
├── LICENSE                   # Project license (optional)
└── ...                       # Additional files if needed
```

**Key Functions** within `CyberScope.sh`:
- `CHECK()`: Ensures script runs as root and required tools are installed.
- `INPUT()`: Prompts for a directory name and target network range.
- `UP()`: Identifies which hosts are up in the range.
- `BASIC()`: Performs basic TCP/UDP scans.
- `FULL()`: Performs full scans, vulnerability checks, and optional NSE script categories.
- `HYDRA()`: Conducts brute force attempts on discovered services.
- `RESULTS()`: Displays and lets you inspect results.
- `ZIP()`: Archives all scan results into a zip file.

---

## **License**

You may include your chosen license here (e.g., MIT, GPL v3, etc.). If you choose not to add one, the project defaults to no explicit license.
