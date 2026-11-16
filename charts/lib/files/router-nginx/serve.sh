#!/bin/sh
set -eu
interval=5
watched="/etc/c8s/certs/tls.crt /etc/c8s/certs/tls.key /etc/c8s/certs/ca.crt"
# The launch file's front-door mode picks the certificate tls.conf names.
# In cds mode the acme sidecar stands by and writes no ACME files.
front_door_mode=cds
mode_file=/run/c8s-node/router/front-door-mode
if [ -r "$mode_file" ]; then
    front_door_mode=$(cat "$mode_file")
fi
if [ "$front_door_mode" = acme ]; then
    watched="$watched /etc/c8s-acme-tls/cert.pem /etc/c8s-acme-key/key.pem"
fi

withdrawn() {
    for file in $watched; do
        if [ ! -r "$file" ]; then
            echo "router: $file is not readable" >&2
            return 0
        fi
    done
    return 1
}

nginx_pid=
stop_nginx() {
    if [ -n "$nginx_pid" ]; then
        kill -TERM "$nginx_pid" 2>/dev/null || true
        wait "$nginx_pid" || true
        nginx_pid=
    fi
}

quit_nginx() {
    if [ -n "$nginx_pid" ]; then
        kill -QUIT "$nginx_pid" 2>/dev/null || true
        wait "$nginx_pid" || true
    fi
    exit 0
}

start_nginx() {
    # Each start has distinct connection identifiers, even when PIDs repeat.
    start="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    if [ "${#start}" -ne 16 ]; then
        echo "router: cannot name this nginx start" >&2
        exit 1
    fi
    printf 'map $pid $nginx_start {\n    default "%s";\n}\n' "$start" > /tmp/nginx-start.conf
    nginx -c /usr/lib/c8s/router-nginx/nginx.conf -g 'daemon off;' &
    nginx_pid=$!
}

trap 'stop_nginx; exit 0' TERM INT
trap quit_nginx QUIT

while :; do
    while withdrawn; do sleep "$interval"; done
    start_nginx
    while kill -0 "$nginx_pid" 2>/dev/null; do
        sleep "$interval"
        if ! kill -0 "$nginx_pid" 2>/dev/null; then break; fi
        if withdrawn; then
            stop_nginx
            continue 2
        fi
    done
    wait "$nginx_pid"
    exit $?
done
