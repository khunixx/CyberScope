#!/bin/bash

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
PURPLE="\e[35m"
CYAN="\e[36m"
RESET="\e[0m"

# Function to check if the script is run as root and to check/install necessary packages
function CHECK () {
    echo
    echo -e "${PURPLE}[*] Function (1) CHECK${RESET}"
    
	# Check if the current user is root
    if [ "$(whoami)" != "root" ]; then
        echo "Must be root to run, exiting now..."
        exit
    else
        echo "You are root, continuing..."
    fi

	# Function to check if a package is installed
    CHECK-PACKAGE () {
        dpkg -l | grep -qw "$1"
        return $?
    }

    tools="nmap hydra masscan"
    
    # Checks if the package is installed and if not installs it
    for i in $tools; do 
        if CHECK-PACKAGE $i; then
            echo "$i is installed"
        else 
            echo "Installing $i..."
            sudo apt-get install $i
        fi
        sleep 1
    done
}

# Function to handle user input for directory creation and scan configuration
function INPUT () {
    echo
    echo -e "${PURPLE}[*] Function (2) INPUT${RESET}"
    
	# Loop to get a valid directory name from the user
    while true; do
        read -p "[?] Please enter the name of the directory you wish to create. All results will be saved in this directory: " OUT_DIR
        read -p "[?] You have chosen the name '$OUT_DIR'. Is this input correct? (y/n): " ANS
        # Check if the user confirmed the directory name
        if [[ $ANS == "y" || $ANS == "Y" ]]; then
			# Check if the directory already exists
            if [[ -d "$OUT_DIR" ]]; then
                echo "[-] Directory '$OUT_DIR' already exists. Please choose another name."
            else
                echo "[*] Creating the directory '$OUT_DIR'..."
                mkdir "$OUT_DIR"  # Create the directory
                cd "$OUT_DIR"     # Change to the new directory
                break
            fi
        elif [[ $ANS == "n" || $ANS == "N" ]]; then
            echo "[-] Input is incorrect. Please try again."
        else
            echo "[-] Invalid answer. Please type 'y' or 'n'."
        fi
    done

	# Loop to get a valid network range from the user
    while true; do
        read -p "[?] Please enter the network range you wish to scan: " RANGE
        nmap $RANGE -sL 2>.check 1>.scan
        
        # Check if the range is valid
        if [ ! -z "$(cat .check)" ]; then
            echo "[-] Range is not valid, please enter a correct range"
        else 
            echo "[+] Range is valid, continuing..."
            break
        fi
    done

	# Loop to get the scan mode from the user
    while true; do
        read -p "[?] Choose a basic or full scan. 1 will be a basic scan, 2 will be a full scan: " MODE
        if [[ "$MODE" == "1" ]]; then
            echo "[*] Commencing a basic scan on $RANGE"
            break
        elif [[ "$MODE" == "2" ]]; then
            echo "[*] Commencing a full scan on $RANGE"
            break
        else
            echo "[-] Invalid input. Please choose 1 (basic) or 2 (full)."
        fi
    done
}

# Function to check which devices in the specified range are up
function UP () {
    echo
    echo -e "${PURPLE}[*] Function (3) UP${RESET}"
    echo "[*] Checking which devices in the range are up"
	echo "[*] Creating a directory for each IP"
    nmap $RANGE -sL | grep for | awk '{print $(NF)}' > range_ip.lst
    nmap -sn -iL range_ip.lst > /dev/null 2>&1 -oG up_hosts.txt
    cat up_hosts.txt | grep Up | awk '{print $2}' > ip.lst
    rm up_hosts.txt
    
    # Create a directory for each IP that is up
    for i in $(cat ip.lst); do
        mkdir $i
    done
}

# Create a directory for each IP that is up
function BASIC () {
    echo
    echo -e "${PURPLE}[*] Function (4) BASIC${RESET}"
    echo "[*] Starting the basic scan"
    
    # Loop through each IP address in the ip.lst file
    for i in $(cat ip.lst); do
        cd $i  # Change to the directory for the current IP
        nmap -sS -sV $i -p- > /dev/null 2>&1 -oN basic_tcp_scan    # Perform a TCP scan using nmap and save the output
        masscan -pU:0-65535 $i --rate 1000 -oG basic_udp_scan > /dev/null 2>&1   # Perform a UDP scan using masscan and save the output
        cd ..  # Exiting the IP directory
    done
}

# Function to perform full scans and vulnerability mapping on the discovered IP addresses
function FULL () {
    echo
    echo -e "${PURPLE}[*] Function (4) FULL${RESET}"
    echo "[*] Scanning the network"
    echo "[*] Mapping vulnerabilities"
    for i in $(cat ip.lst); do
        cd $i
        nmap -sS -sV $i -p- > /dev/null 2>&1 -oN basic_tcp_scan
        masscan -pU:0-65535 $i --rate 1000 -oG basic_udp_scan > /dev/null 2>&1
        nmap $i -sV --script=vulners.nse > /dev/null 2>&1 -oN vulnerabilities
        cd ..
    done

	# Function to execute nmap scripts based on user choice
    function NSE () {
        echo 
        echo -e "${PURPLE}[*] Function (4.1) NSE${RESET}"
        echo "[?] Please choose the nmap script category you wish to use:"
        echo "1) Default"
        echo "2) Vuln"
        echo "3) Brute"
        echo "4) Exploit"
        echo "5) Malware"
        echo "6) Dos"
        echo "7) Intrusive"
        echo "8) Safe"
        echo "9) Discovery"
        echo "10) Version"
        echo "11) External"
        echo "12) Broadcast"
        echo "13) Fuzzer"

        read -p "Please enter the number of the script category you wish to use (1-13): " CHOICE
        
        # Case statement to execute the chosen nmap script category
        case $CHOICE in
            1)
                echo "[*] Starting nmap with the scripts in the Default category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=default > /dev/null 2>&1 -oN nse_default
                    cd ..
                done
                ;;
            2)
                echo "[*] Starting nmap with the scripts in the Vuln category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=vuln > /dev/null 2>&1 -oN nse_vuln
                    cd ..
                done
                ;;
            3)
                echo "[*] Starting nmap with the scripts in the Brute category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=brute > /dev/null 2>&1 -oN nse_brute
                    cd ..
                done
                ;;
            4)
                echo "[*] Starting nmap with the scripts in the Exploit category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=exploit > /dev/null 2>&1 -oN nse_exploit
                    cd ..
                done
                ;;
            5)
                echo "[*] Starting nmap with the scripts in the Malware category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=malware > /dev/null 2>&1 -oN nse_malware
                    cd ..
                done
                ;;
            6)
                echo "[*] Starting nmap with the scripts in the Dos category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=dos > /dev/null 2>&1 -oN nse_dos
                    cd ..
                done
                ;;
            7)
                echo "[*] Starting nmap with the scripts in the Intrusive category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=intrusive > /dev/null 2>&1 -oN nse_intrusive
                    cd ..
                done
                ;;
            8)
                echo "[*] Starting nmap with the scripts in the Safe category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=safe > /dev/null 2>&1 -oN nse_safe
                    cd ..
                done
                ;;
            9)
                echo "[*] Starting nmap with the scripts in the Discovery category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=discovery > /dev/null 2>&1 -oN nse_discovery
                    cd ..
                done
                ;;
            10)
                echo "[*] Starting nmap with the scripts in the Version category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=version > /dev/null 2>&1 -oN nse_version
                    cd ..
                done
                ;;
            11)
                echo "[*] Starting nmap with the scripts in the External category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=external > /dev/null 2>&1 -oN nse_external
                    cd ..
                done
                ;;
            12)
                echo "[*] Starting nmap with the scripts in the Broadcast category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=broadcast > /dev/null 2>&1 -oN nse_broadcast
                    cd ..
                done
                ;;
            13)
                echo "[*] Starting nmap with the scripts in the Fuzzer category"
                for ip in $(cat ip.lst); do
                    cd $ip
                    nmap $ip -sV --script=fuzzer > /dev/null 2>&1 -oN nse_fuzzer
                    cd ..
                done
                ;;
        esac
    }

	# Call the NSE function and prompt for additional scans
    NSE
    while true; do
        read -p "[?] Would you like to choose another category? (y/n): " ANSWER
        if [[ $ANSWER == "y" || $ANSWER == "Y" ]]; then
            NSE
        elif [[ $ANSWER == "n" || $ANSWER == "N" ]]; then
            echo "[*] Continuing..."
            break
        else
            echo "[!] Invalid input. Please enter 'y' or 'n'."
        fi
    done
}

# Function to perform brute force attacks on specified services using Hydra
function HYDRA () {
    echo 
    echo -e "${PURPLE}[*] Function (5) HYDRA${RESET}"

	# Inner function to identify services running on IP addresses
    function SERVICES () {
        for i in $(cat ip.lst); do
            echo "$i"
            cd $i
            cat *scan | grep -E "ftp|ssh|rdp|telnet"  # Identify specific services
            cd ..
        done >> services

		# Filter the identified services and save to services.lst
        cat services | grep -E "ftp|ssh|rdp|telnet" -B 1 > services.lst
        rm services
        cat services.lst | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' > services_ip.lst  # Extract IPs
    }

    SERVICES  # Call the SERVICES function

    echo "Please choose a password and user list from the following options: "
    echo "1) User input password list & user input user list"
    echo "2) Generated password list & generated user list"
    echo "3) User input password list & generated user list"
    echo "4) Generated password list & user input user list"
    read -p "Please enter the number of the option you wish to choose: " OPTION

	# Case statement for user-selected options
    case $OPTION in
        1)
            read -p "[?] Please enter the full path of the password list you wish to use: " PASSLIST
            read -p "[?] Please enter the full path of the user list you wish to use: " USERLIST
           
            SERVICES=("ftp" "telnet" "rdp" "ssh")
            for ip in $(cat services_ip.lst); do
                cd "$ip" 

                for SERVICE in "${SERVICES[@]}"; do
					# Execute Hydra with specified user and password lists
                    hydra -L "$USERLIST" -P "$PASSLIST" "$ip" "$SERVICE" -o "brute_$SERVICE.txt" > /dev/null 2>&1
                    
                    if grep -qi "host:" "brute_$SERVICE.txt"; then
                        echo "[+] Found credentials for $ip on $SERVICE: "
                        grep "host:" "brute_$SERVICE.txt"
                    else
                        echo "[-] No valid credentials found for $ip on $SERVICE"
                    fi
                done

                cd .. 
            done
            ;;
        
        2) 
            echo "[*] Generating User and password list..."
            wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
            SERVICES=("ftp" "telnet" "rdp" "ssh")
            for ip in $(cat services_ip.lst); do
                cd "$ip" 

                for SERVICE in "${SERVICES[@]}"; do
					# Execute Hydra using the generated rockyou.txt for both user and password
                    hydra -L ../rockyou.txt -P ../rockyou.txt "$ip" "$SERVICE" -o "brute_$SERVICE.txt" > /dev/null 2>&1
                    
                    if grep -qi "host:" "brute_$SERVICE.txt"; then
                        echo "[+] Found credentials for $ip on $SERVICE: "
                        grep "host:" "brute_$SERVICE.txt"
                    else
                        echo "[-] No valid credentials found for $ip on $SERVICE"
                    fi
                done

                cd .. 
            done
            ;;
        
        3)
            read -p "[?] Please enter the full path of the password list you wish to use: " PASSLIST
            echo "[*] Generating user list..."
          
            SERVICES=("ftp" "telnet" "rdp" "ssh")
            for ip in $(cat services_ip.lst); do
                cd "$ip" 

                for SERVICE in "${SERVICES[@]}"; do
					# Execute Hydra using the generated rockyou.txt for user and specified password list
                    hydra -L ../rockyou.txt -P "$PASSLIST" "$ip" "$SERVICE" -o "brute_$SERVICE.txt" > /dev/null 2>&1
                    
                    if grep -qi "host:" "brute_$SERVICE.txt"; then
                        echo "[+] Found credentials for $ip on $SERVICE: "
                        grep "host:" "brute_$SERVICE.txt"
                    else
                        echo "[-] No valid credentials found for $ip on $SERVICE"
                    fi
                done

                cd .. 
            done
            ;;     
        
        4)
            echo "[*] Generating password list..."
            read -p "[?] Please enter the full path of the user list you wish to use: " USERLIST
            wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
            SERVICES=("ftp" "telnet" "rdp" "ssh")
            for ip in $(cat services_ip.lst); do
                cd "$ip" 

                for SERVICE in "${SERVICES[@]}"; do
					# Execute Hydra using specified user list and generated rockyou.txt for password
                    hydra -L "$USERLIST" -P ../rockyou.txt "$ip" "$SERVICE" -o "brute_$SERVICE.txt" > /dev/null 2>&1
                    
                    if grep -qi "host:" "brute_$SERVICE.txt"; then
                        echo "[+] Found credentials for $ip on $SERVICE: "
                        grep "host:" "brute_$SERVICE.txt"
                    else
                        echo "[-] No valid credentials found for $ip on $SERVICE"
                    fi
                done

                cd .. 
            done
            ;;    
    esac
}

# Function to display scan results and allow inspection of specific IPs
function RESULTS () {
    echo
    echo -e "${PURPLE}[*] Function (6) RESULTS${RESET}"

    echo "[*] Showing the results of the scan"
    echo "[*] Found $(ls -l | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l) open devices"
    echo "[*] Displaying their IP's:"
    ls -l | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'

	# Inner function to inspect specific IP directories
    function INSPECT() {
        echo
        echo -e "${PURPLE}[*] Function (6.1) INSPECT${RESET}"
		
		# Function to choose an IP for inspection
        function IP_CHOICE () {
            while true; do
                read -p "[?] Please choose an IP you wish to inspect: " IPI
                if [ -d "$IPI" ]; then
                    echo "[+] IP exists continuing to the inspection..."
                    break 
                else 
                    echo "[-] IP does not exist, Please specify a valid IP"
                fi
            done
        }

		# Function to display the contents of the chosen IP directory
        function DISPLAY () {
            cd "$IPI"  # Change to the chosen IP directory

            echo "[*] Displaying the contents of the $IPI directory: "
            ls -l | grep - | awk '{print $(NF)}'  # List files in the directory
            while true; do
                read -p "[?] Please choose a file you wish to display from the directory: " ANSWER
                if [ -f "$ANSWER" ]; then
                    echo "[*] Displaying the contents of $ANSWER: "
                    cat "$ANSWER"  # Display the file content
                    break
                else 
                    echo "[-] File does not exist, Please choose a valid file name"
                fi
            done
        }

        IP_CHOICE  # Call the IP_CHOICE function
        DISPLAY    # Call the DISPLAY function

        while true; do
            read -p "[?] Would you like to inspect another file in the directory? (y/n) " CHOICE
            if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
                DISPLAY  # Call DISPLAY to inspect another file
            elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
                break  # Exit the file inspection loop
            else
                echo "[-] Invalid option, Please choose (y/n) "
            fi
        done
    }

    INSPECT  # Call the INSPECT function

    while true; do
        read -p "[?] Would you like to inspect another IP? (y/n) " CHOICE
        if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
            INSPECT  # Call INSPECT to choose another IP
        elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
            break  # Exit the IP inspection loop
        else
            echo "[-] Invalid option, Please choose (y/n) "
        fi
    done
}

# Function to zip the output directory
function ZIP () {
    echo
    echo -e "${PURPLE}[*] Function (7) ZIP${RESET}"
    echo "[*] Zipping the $OUT_DIR directory"
    cd ..  # Change to the parent directory
    zip -r "$OUT_DIR.zip" "$OUT_DIR"  # Create a zip archive of the output directory
}

CHECK  # Call the CHECK function
INPUT  # Call the INPUT function
UP     # Call the UP function

if [[ $MODE == "1" ]];  # If statement to check whether to do a full or basic scan
then
BASIC
else 
FULL
fi

HYDRA   # Call the HYDRA function 
RESULTS # Call the RESULTS function
ZIP     # Call the ZIP function
