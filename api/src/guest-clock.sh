#!/bin/bash
# KVM microVM guest clock discipline.
#
# The libkrun guest reads the host clock once at boot and then free-runs on its
# own counter. The host keeps its clock right with NTP; the guest has nothing,
# so it drifts by the host's frequency correction (6 ppm on the Optale AX41:
# 30.5 s behind after 56 days). The sandbox API verifies execution manifests
# signed on the host with a 30-second window, so once the lag passes 30 s
# fresh manifests look like they come from the future (`not_yet_valid`).
#
# This wrapper runs chrony against the guest's KVM virtual PTP clock, which
# reads the host's CLOCK_REALTIME through the hypervisor. It waits for the
# first synchronization before starting the sandbox API, then supervises the
# clock: if chronyd exits or reports itself unsynchronized for too long, the
# API stops and the runner restarts instead of drifting. No network NTP
# source, host capability or manifest tolerance changes. Adapted from
# LibreChat-AI/code-interpreter#379.
#
# The launcher runs this script, without arguments, as the guest command
# (LAUNCHER_EXEC default). Direct NsJail and Lambda run entrypoint.sh.

GUEST_CLOCK_PTP_NAME='KVM virtual PTP'
GUEST_CLOCK_DEFAULT_COMMAND='/sandbox_api/entrypoint.sh'
GUEST_CLOCK_USER='_chrony'
# Seconds between sync checks, and consecutive unsynchronized checks before
# the API stops. 60 s unsynchronized costs microseconds at host drift rates.
GUEST_CLOCK_CHECK_INTERVAL_SECONDS="${GUEST_CLOCK_CHECK_INTERVAL_SECONDS:-10}"
GUEST_CLOCK_MAX_UNSYNCED_CHECKS="${GUEST_CLOCK_MAX_UNSYNCED_CHECKS:-6}"

# Prints the /dev path of the KVM virtual PTP clock. The guest kernel may
# expose other PTP clocks, so select by name rather than assuming /dev/ptp0.
find_kvm_ptp_device() {
    local root="$1" clock
    for clock in "$root"/sys/class/ptp/ptp*; do
        [ -r "$clock/clock_name" ] || continue
        if [ "$(cat "$clock/clock_name")" = "$GUEST_CLOCK_PTP_NAME" ]; then
            printf '/dev/%s\n' "${clock##*/}"
            return 0
        fi
    done
    return 1
}

# chronyd creates the socket directory itself (0770, owned by its user) as
# root, opens the PTP device and binds the socket, then drops to that user.
write_guest_chrony_conf() {
    local clock_dir="$1" ptp_device="$2"
    cat > "$clock_dir/chrony.conf" <<EOF
# Host CLOCK_REALTIME through the KVM virtual PTP clock; no network sources.
refclock PHC $ptp_device poll 0 dpoll -2
# Only the first update may step: the API starts after synchronization, and
# later corrections slew so running jobs never see time jump.
makestep 0.1 1
# No NTP server or UDP command port; control only through the private socket.
port 0
cmdport 0
bindcmdaddress $clock_dir/chrony/chronyd.sock
pidfile $clock_dir/chrony/chronyd.pid
EOF
}

# Exits non-zero once chronyd has reported an unsynchronized clock (or not
# answered) for GUEST_CLOCK_MAX_UNSYNCED_CHECKS checks in a row, e.g. after
# the PTP source stops delivering samples.
monitor_clock_sync() {
    local socket_file="$1" unsynced=0 leap
    while :; do
        sleep "$GUEST_CLOCK_CHECK_INTERVAL_SECONDS"
        leap="$(timeout -k 1 5 chronyc -h "$socket_file" -c tracking 2>/dev/null | awk -F, 'NR == 1 { print $NF }')" || leap=""
        if [ "$leap" = "Normal" ]; then
            unsynced=0
            continue
        fi
        unsynced=$((unsynced + 1))
        echo "WARNING: guest clock is not synchronized (chrony leap status: ${leap:-no answer}), check ${unsynced}/${GUEST_CLOCK_MAX_UNSYNCED_CHECKS}" >&2
        [ "$unsynced" -lt "$GUEST_CLOCK_MAX_UNSYNCED_CHECKS" ] || exit 1
    done
}

# Own the bootstrap shell: libkrun signals this PID, not a supervisor subshell.
# Like an exec of the guest command, this function exits rather than returns.
# `root` is empty in the guest; tests pass a scratch directory.
run_clock_synchronized_guest() {
    set -euo pipefail
    local root="${1?root argument required (empty for the guest)}"
    shift
    [ "$#" -gt 0 ] || { echo 'ERROR: guest command required' >&2; exit 1; }
    export PATH="${PATH:-/usr/local/bin:/usr/bin:/bin}:/usr/sbin"

    local clock_dir="$root/run/codeapi-clock"
    local socket_file="$clock_dir/chrony/chronyd.sock"
    local chrony_pid="" guest_pid="" sync_pid="" monitor_pid="" ptp_device=""

    ptp_device="$(find_kvm_ptp_device "$root")" || {
        echo "ERROR: guest has no '$GUEST_CLOCK_PTP_NAME' clock; the host must run KVM on a TSC clocksource (README: KVM guest time)" >&2
        exit 1
    }

    # Root-owned and not listable; chronyd's own socket directory inside it
    # admits only root and the chrony user.
    if [ -z "$root" ]; then
        # The guest root may be read-only. A fresh tmpfs on the baked
        # mountpoint cannot be pre-seeded by a sandbox UID.
        mount -t tmpfs -o size=1m,mode=0711 tmpfs "$clock_dir" || exit 1
    else
        # mkdir refuses existing entries, including dangling symlinks.
        (umask 066; mkdir "$clock_dir") || exit 1
    fi

    stop_child() {
        local pid="$1"
        [ -n "$pid" ] || return 0
        kill -TERM "$pid" 2>/dev/null || true
        local attempt
        for attempt in {1..20}; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.05
        done
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    }

    cleanup() {
        trap - EXIT INT TERM
        stop_child "$sync_pid"
        stop_child "$monitor_pid"
        stop_child "$guest_pid"
        stop_child "$chrony_pid"
        if [ -z "$root" ]; then
            umount "$clock_dir" 2>/dev/null || true
        else
            rm -rf -- "$clock_dir"
        fi
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    write_guest_chrony_conf "$clock_dir" "$ptp_device"
    chronyd -d -u "$GUEST_CLOCK_USER" -F 1 -f "$clock_dir/chrony.conf" &
    chrony_pid=$!

    # Allow socket creation before chronyc connects; refuse a dead daemon.
    local attempt
    for attempt in {1..100}; do
        kill -0 "$chrony_pid" 2>/dev/null || {
            echo 'ERROR: guest clock daemon exited during startup' >&2
            exit 1
        }
        [ ! -e "$socket_file" ] || break
        sleep 0.05
    done
    [ -e "$socket_file" ] || {
        echo 'ERROR: guest clock control socket did not become ready' >&2
        exit 1
    }

    # Bound both clock acquisition and a stuck control client. Backgrounding
    # the wait lets INT/TERM interrupt startup and clean up the whole group.
    timeout -k 1 15 chronyc -h "$socket_file" waitsync 100 0.05 0 0.1 &
    sync_pid=$!
    local status=0
    wait "$sync_pid" || status=$?
    sync_pid=""
    if [ "$status" -ne 0 ] || ! kill -0 "$chrony_pid" 2>/dev/null; then
        echo "ERROR: guest clock did not synchronize with the host through $ptp_device" >&2
        exit 1
    fi
    echo "Guest clock synchronized with the host through $ptp_device"

    monitor_clock_sync "$socket_file" &
    monitor_pid=$!

    "$@" <&0 &
    guest_pid=$!
    local finished=""
    status=0
    wait -n -p finished "$chrony_pid" "$monitor_pid" "$guest_pid" 2>/dev/null || status=$?
    if [ "${finished:-}" = "$chrony_pid" ]; then
        chrony_pid=""
        echo 'ERROR: guest clock daemon exited; stopping the sandbox API' >&2
        exit 1
    fi
    if [ "${finished:-}" = "$monitor_pid" ]; then
        monitor_pid=""
        echo 'ERROR: guest clock lost synchronization with the host; stopping the sandbox API' >&2
        exit 1
    fi
    if [ "${finished:-}" = "$guest_pid" ]; then
        guest_pid=""
        exit "$status"
    fi

    # Bash can cache a very short-lived child's exit before wait -n starts.
    # Read its status once without swallowing failures or spinning on ECHILD.
    kill -0 "$chrony_pid" 2>/dev/null || exit 1
    kill -0 "$monitor_pid" 2>/dev/null || exit 1
    status=0
    wait "$guest_pid" || status=$?
    guest_pid=""
    exit "$status"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    # The launcher passes no arguments (libkrun would append them to this
    # path). Refuse any, so a wrong caller fails visibly instead of nesting.
    if [ "$#" -ne 0 ]; then
        echo "ERROR: guest-clock.sh takes no arguments; got: $*" >&2
        exit 2
    fi
    run_clock_synchronized_guest "" "$GUEST_CLOCK_DEFAULT_COMMAND"
fi
