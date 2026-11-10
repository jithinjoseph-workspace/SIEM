#!/bin/sh
# Wazuh Control script for Wazuh Server / Manager
# Complete POSIX shell controller for daemon lifecycle management

VERSION="v4.14.7"
REVISION="rc1"
TYPE="server"

DIR="/var/ossec"
BIN="${DIR}/bin"
RUN="${DIR}/var/run"
LOCK="${DIR}/var/start-script-lock"

DAEMONS="wazuh-db wazuh-authd wazuh-execd wazuh-analysisd wazuh-syscheckd wazuh-remoted wazuh-logcollector wazuh-monitord wazuh-modulesd wazuh-maild wazuh-agentlessd wazuh-integratord wazuh-csyslogd wazuh-apid"
SDAEMONS=$(echo $DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')

USE_JSON=false

pstatus() {
    pfile=$1
    [ -z "$pfile" ] && return 0

    for pidfile in ${RUN}/${pfile}-*.pid; do
        [ -f "$pidfile" ] || continue
        pid=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        rm -f "$pidfile"
    done
    return 0
}

status() {
    first=true
    if [ "$USE_JSON" = true ]; then
        echo -n '{"error":0,"data":['
    fi

    for d in $DAEMONS; do
        if [ "$USE_JSON" = true ]; then
            [ "$first" = false ] && echo -n ','
            first=false
        fi

        pstatus "$d"
        if [ $? -eq 1 ]; then
            if [ "$USE_JSON" = true ]; then
                echo -n '{"daemon":"'"$d"'","status":"running"}'
            else
                echo "$d is running..."
            fi
        else
            if [ "$USE_JSON" = true ]; then
                echo -n '{"daemon":"'"$d"'","status":"stopped"}'
            else
                echo "$d not running..."
            fi
        fi
    done

    if [ "$USE_JSON" = true ]; then
        echo ']}'
    fi
}

start() {
    [ "$USE_JSON" = false ] && echo "Starting Wazuh $VERSION..."
    mkdir -p "$RUN"

    first=true
    if [ "$USE_JSON" = true ]; then
        echo -n '{"error":0,"data":['
    fi

    for d in $DAEMONS; do
        if [ "$USE_JSON" = true ]; then
            [ "$first" = false ] && echo -n ','
            first=false
        fi

        pstatus "$d"
        if [ $? -eq 1 ]; then
            if [ "$USE_JSON" = true ]; then
                echo -n '{"daemon":"'"$d"'","status":"running"}'
            else
                echo "$d already running..."
            fi
            continue
        fi

        if [ -x "${BIN}/${d}" ]; then
            ${BIN}/${d} > /dev/null 2>&1 &
            sleep 1
            if [ "$USE_JSON" = true ]; then
                echo -n '{"daemon":"'"$d"'","status":"running"}'
            else
                echo "Started $d..."
            fi
        else
            if [ "$USE_JSON" = true ]; then
                echo -n '{"daemon":"'"$d"'","status":"stopped"}'
            else
                echo "$d not installed in ${BIN}"
            fi
        fi
    done

    if [ "$USE_JSON" = true ]; then
        echo ']}'
    else
        echo "Completed."
    fi
}

stop() {
    first=true
    if [ "$USE_JSON" = true ]; then
        echo -n '{"error":0,"data":['
    fi

    for d in $SDAEMONS; do
        if [ "$USE_JSON" = true ]; then
            [ "$first" = false ] && echo -n ','
            first=false
        fi

        pstatus "$d"
        if [ $? -eq 1 ]; then
            for pidfile in ${RUN}/${d}-*.pid; do
                [ -f "$pidfile" ] || continue
                pid=$(cat "$pidfile" 2>/dev/null)
                [ -n "$pid" ] && kill -15 "$pid" 2>/dev/null
                rm -f "$pidfile"
            done
            if [ "$USE_JSON" = true ]; then
                echo -n '{"daemon":"'"$d"'","status":"stopped"}'
            else
                echo "Killing $d..."
            fi
        else
            if [ "$USE_JSON" = true ]; then
                echo -n '{"daemon":"'"$d"'","status":"stopped"}'
            else
                echo "$d not running..."
            fi
        fi
    done

    if [ "$USE_JSON" = true ]; then
        echo ']}'
    else
        echo "Wazuh $VERSION Stopped"
    fi
}

info() {
    arg=$1
    if [ "$USE_JSON" = true ]; then
        echo '{"error":0,"data":[{"WAZUH_VERSION":"'"$VERSION"'"},{"WAZUH_REVISION":"'"$REVISION"'"},{"WAZUH_TYPE":"'"$TYPE"'"}]}'
    elif [ "$arg" = "-v" ]; then
        echo "$VERSION"
    elif [ "$arg" = "-r" ]; then
        echo "$REVISION"
    elif [ "$arg" = "-t" ]; then
        echo "$TYPE"
    else
        echo "WAZUH_VERSION=\"${VERSION}\""
        echo "WAZUH_REVISION=\"${REVISION}\""
        echo "WAZUH_TYPE=\"${TYPE}\""
    fi
}

# Main parsing
if [ "$1" = "-j" ]; then
    USE_JSON=true
    shift
fi

action=$1
shift

case "$action" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 1
        start
        ;;
    status)
        status
        ;;
    info)
        info "$1"
        ;;
    *)
        echo "Usage: $0 [-j] {start|stop|restart|status|info [-v -r -t]}"
        exit 1
        ;;
esac
