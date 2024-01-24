#!/bin/bash

if [[ "${1}" == '-h' ]] || [[ "${1}" == '--help' ]]; then
    echo "Usage: ${0} [port] [auth]"
    echo "  port    Port number for squid to lisen to (by default 3128)"
    echo "  auth    Optional string ('auth') to force user basic authentification (autherwise no authentification is required)"
    exit 0
fi

conf_file="squid${2:-}.conf"

echo "http_port 127.0.0.1:${1:-3128}"            >"${conf_file}"
echo 'pid_filename ${service_name}.pid'         >>"${conf_file}"

echo '# Send Logs to stdout'                    >>"${conf_file}"
echo 'logfile_rotate 0'                         >>"${conf_file}"
echo 'logfile_daemon stdio:/dev/stdout'         >>"${conf_file}"
echo 'access_log stdio:/dev/stdout'             >>"${conf_file}"
echo 'cache_log stdio:/dev/stdout'              >>"${conf_file}"
echo 'cache_store_log stdio:/dev/stdout'        >>"${conf_file}"


if [[ "${2}" == "auth" ]]; then
    # User 'john' with password 'doe'
    echo 'john:$apr1$dalj9e7s$AhqY28Hvl3EcNblNJMiXa0' >squid_users

    if [[ "$(uname)" == "Darwin" ]]; then
        squid_version="$(squid --version | head -n1 | grep -o 'Version [^ ]*' | cut -d ' ' -f 2)"
        auth_basic_program="/usr/local/Cellar/squid/${squid_version}/libexec/basic_ncsa_auth"
    else
        auth_basic_program="/usr/lib/squid/basic_ncsa_auth"
    fi

    echo '# Add authentification options'       >>"${conf_file}"
    echo "auth_param basic program ${auth_basic_program} squid_users" >>"${conf_file}"
    echo 'auth_param basic children 3'          >>"${conf_file}"
    echo 'auth_param basic realm Squid BA'      >>"${conf_file}"
    echo 'acl auth_users proxy_auth REQUIRED'   >>"${conf_file}"
    echo 'http_access allow auth_users'         >>"${conf_file}"
    echo 'http_access deny all'                 >>"${conf_file}"
else
    echo 'http_access allow localhost'          >>"${conf_file}"
fi

cat "${conf_file}"

exec squid -N -f "${conf_file}" 
