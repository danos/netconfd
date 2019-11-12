#!/opt/vyatta/bin/cliexec
call_home_stop () {
    systemctl stop call-home
    call-home --cleanup
}

if [[ "$COMMIT_ACTION" == "DELETE" || -n "$VAR(./disable)" ]]; then
    # Netconf not configured or is disabled
    call_home_stop
elif [[ -z "$VAR(./call-home/netconf-client/@@)" ]]; then
    # No clients configured
    call_home_stop
elif [[ $(echo "$VAR(./call-home/netconf-client/@@)" | wc -w) == $(echo "$VAR(./call-home/netconf-client/@@/disable)" | wc -w) ]]; then
    # No clients enabled
    call_home_stop
else
    call-home --config && systemctl --no-block restart call-home
fi
