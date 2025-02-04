#!/bin/bash

################################
## TODO 
##
################################
# https://github.com/BeetleChunks/SpoolSploit : A collection of Windows print spooler exploits containerized with other utilities for practical exploitation.



# Ensure we are running under bash
if [ "$BASH_SOURCE" = "" ]; then
    /bin/bash "$0"
    exit 0
fi

# Time for sleep command
time=0

################################
## Introduction
##
################################
    if ! command -v lolcat &> /dev/null
    then
        sudo apt-get install lolcat
    fi
    if ! command -v figlet &> /dev/null
    then
        sudo apt-get install figlet
    fi
    if ! command -v toilet &> /dev/null
    then
        sudo apt-get install toilet
    fi
    if ! command -v pipx &> /dev/null
    then
        sudo apt-get install pipx
    fi
    if ! command -v go &> /dev/null
    then
        sudo apt-get install golang-go
    fi
    if ! command -v jq &> /dev/null
    then
        sudo apt-get install jq
    fi
    if ! command -v bpytop &> /dev/null
    then
        sudo apt-get install bpytop
    fi
    if ! command -v xterm &> /dev/null
    then
        sudo apt-get install xterm
    fi


    # Printing messages
    figlet "Bounty KID :)" | lolcat
	sleep $time
	echo "‍             ☠️ USE THIS TOOL WITH CAUTION ‍☠️"
	echo "‍             "
    sleep `echo $(($time*2))`
    echo "🤸 Hi $USER, time is : $(date +"%r")" | lolcat
    sleep `echo $(($time/2))`
    tput bold;echo -n "🦜 Machine state : " && uptime -p | lolcat
    sleep `echo $(($time/2))`
    # Check internet connection
    tput bold;echo -n "🎪 Checking internet connection...   " | lolcat
    wget -q --spider https://google.com
    if [ $? -ne 0 ];then
        echo "/!\ NO INTERNET CONNECTION !"
        exit 1
    fi
    tput bold;echo "Internet OK" | lolcat
    tput bold;echo "📖 Starting......" | lolcat


################################
## Company selection
##
################################
# Path to the CSV file containing information about companies
companies_csv="companies.csv"

create_company() {
    # Company name creation
    echo "Name of the new company (eg. extia) :"
    read -r name
    echo "URL of the new company (eg. extia.fr) :"
    read -r url
    echo "$name,$url" >> "$companies_csv"
    # Saving the selection company
    COMPANY_NAME_SELECTED=$name
    COMPANY_URL_SELECTED=$url
    echo "Company created: $name, URL: $url" | lolcat
    # Folders creation
    mkdir "$COMPANY_NAME_SELECTED" tools "$COMPANY_NAME_SELECTED"/urls "$COMPANY_NAME_SELECTED"/secrets "$COMPANY_NAME_SELECTED"/vuln "$COMPANY_NAME_SELECTED"/subdomains "$COMPANY_NAME_SELECTED"/params "$COMPANY_NAME_SELECTED"/fuzzing "$COMPANY_NAME_SELECTED"/ips "$COMPANY_NAME_SELECTED"/tmp
    # Going to the selected dir
    cd "$COMPANY_NAME_SELECTED"
    # A created company means checking if toolings are installed 
    . "../core_scan.sh"
    Check-dependencies
    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

if ! test -f $companies_csv; then
    create_company
else
    # Read the CSV file into an array
    IFS=$'\n' read -d '' -r -a companies < "$companies_csv"

    # While loop to display the menu and read user input
    while true
    do
    # Display the menu
	echo "Select a company:" | toilet --metal -f pagga -F border| lolcat 
    for i in "${!companies[@]}"
    do
        # Use awk to extract the company name
        name=$(echo "${companies[$i]}" | awk -F',' '{print $1}')
        echo "$((i+1)). $name"
    done
    echo "$((i+2)). Create a new company"
    echo "$((i+3)). Quit"
    
    # Read user input
    read -r choice
    
    # Verify that the input is a number and that it is valid
    if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#companies[@]}+3)) then
        # Quit the script if "Quit" option is selected
        if ((choice == ${#companies[@]}+2)) then
            exit 0
        fi
        
        # Create a new company if the corresponding option is selected
        if ((choice == ${#companies[@]}+1)) then
            create_company
            break
        fi
        
        # Process the selected option
        # Use awk to extract the URL of the company
        url=$(echo "${companies[$choice-1]}" | awk -F',' '{print $2}')
        name=$(echo "${companies[$choice-1]}" | awk -F',' '{print $1}')
        COMPANY_NAME_SELECTED=$name
        COMPANY_URL_SELECTED=$url
        cd $COMPANY_NAME_SELECTED
        echo "Selected company: $name => $url" | lolcat
        # Add code to process the selected company here
        break
    else
        echo "Invalid input"
    fi
    done
fi
printf "%s\n" "--------------------------------------------------"
sleep `echo $(($time*3))`


################################
#
# Load bash-menu script
#
# NOTE: Ensure this is done before using
#       or overriding menu functions/variables.
#
. "../bash-menu.sh"
################################
## Example Menu Actions
##
## They should return 1 to indicate that the menu
## should continue, or return 0 to signify the menu
## should exit.
################################
action1() {
    toilet "Enumeration"
    sed -i 's/EnumerationMenu="Enumeration"/EnumerationMenu="Enumeration 💯"/' menuState.txt
    source menuState.txt
    . "../core_scan.sh"
    Enumeration

    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

action2() {
    echo "Content Discovery"
    sed -i 's/ContentDiscoveryMenu="Content-discovery"/ContentDiscoveryMenu="Content-discovery 💯"/' menuState.txt
    source menuState.txt
    . "../core_scan.sh"
    Content-discovery
    
    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

action3() {
    echo "Params Analysis"
    sed -i 's/Params_analysisMenu="Params_analysis"/Params_analysisMenu="Params_analysis 💯"/' menuState.txt
    source menuState.txt
    . "../core_scan.sh"
    Params_analysis

    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

action4() {
    echo "Nuclei Simple"
    sed -i 's/Nuclei_simple_scanMenu="Nuclei_simple_scan"/Nuclei_simple_scanMenu="Nuclei_simple_scan 💯"/' menuState.txt
    source menuState.txt
    . "../core_scan.sh"
    # Nuclei_simple_scan
    Nuclei_full_scan

    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

action5() {
    echo "Port scanning"
    sed -i 's/Port_scanningMenu="Port-scanning"/Port_scanningMenu="Port Scanning 💯"/' menuState.txt
    source menuState.txt
    . "../core_scan.sh"
    Port-scanning

    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

action6() {
    echo "Finding CVEs"
    sed -i 's/Finding_CVESMenu="Finding CVEs"/Finding_CVESMenu="Finding CVEs 💯"/' menuState.txt
    source menuState.txt
    . "../core_scan.sh"
    Finding_CVES

    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

action_Dependencies() {
    echo "Check all dependencies"
    sed -i 's/CheckDependenciesMenu="Check all dependencies"/CheckDependenciesMenu="Check all dependencies 💯"/' menuState.txt
    source menuState.txt
    . "../core_scan.sh"
    Check-dependencies

    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}
action_Monitoring() {
    echo "Monitoring"
        xterm -hold -e 'bpytop' &

    echo -n "🔁 Press enter to continue ... "
    read response

    return 1
}

actionX() {
    return 0
}


################################
## Menu for core_scan.sh
##
################################
if ! test -f "menuState.txt"; then
    echo "EnumerationMenu=\"Enumeration\"" > menuState.txt
    echo "ContentDiscoveryMenu=\"Content-discovery\"" >> menuState.txt
    echo "Params_analysisMenu=\"Params_analysis\"" >> menuState.txt
    echo "CheckDependenciesMenu=\"Check all dependencies\"" >> menuState.txt
    echo "Nuclei_simple_scanMenu=\"Nuclei Simple scan\"" >> menuState.txt
    echo "Port_scanningMenu=\"Port Scanning\"" >> menuState.txt
    echo "Finding_CVESMenu=\"Finding CVEs\"" >> menuState.txt

fi
source menuState.txt

echo $discoveryMenu
menuItems=(
    "1. $EnumerationMenu"
    "2. $ContentDiscoveryMenu"
    "3. $Params_analysisMenu"
    "4. $Nuclei_simple_scanMenu"
    "5. $Port_scanningMenu"
    "6. $Finding_CVESMenu"
    "A. $CheckDependenciesMenu"
    "B. Monitor mode"
    "Q. Exit  "
)

## Menu Item Actions
menuActions=(
    action1
    action2
    action3
    action4
    action5
    action6
    action_Dependencies
    action_Monitoring
)

## Override some menu defaults
menuTitle=" BountyKid - vulnerability scanner - $COMPANY_NAME_SELECTED"
menuFooter=" Enter=Select, Navigate via Up/Down/First number/letter"
menuWidth=60
menuLeft=25
menuHighlight=$DRAW_COL_BLUE


################################
## Run Menu
################################
menuInit
menuLoop


exit 0
