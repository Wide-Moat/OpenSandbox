#!/bin/sh

# Copyright 2025 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

EXECD_WATCHDOG_PID=""
LIFECYCLE_STATUS_DIR=""
LIFECYCLE_STATUS_FILE=""
LIFECYCLE_WATCHDOG_TIMEOUT_FILE=""
LIFECYCLE_WATCHDOG_READY_FILE=""

_forward_signal() {
	sig="$1"
	pid="$2"
	if [ -z "$pid" ]; then
		return
	fi
	kill "-$sig" "$pid" 2>/dev/null || true
}

_process_state() {
	if [ -r "/proc/$1/stat" ]; then
		sed -e 's/^.*) //' -e 's/ .*$//' "/proc/$1/stat" 2>/dev/null || true
	else
		ps -o stat= -p "$1" 2>/dev/null \
			| sed -n '1{s/^[[:space:]]*//; s/^\(.\).*$/\1/; p;}' \
			|| true
	fi
}

_stop_execd_watchdog() {
	if [ -n "${EXECD_WATCHDOG_PID:-}" ]; then
		if [ -n "${LIFECYCLE_WATCHDOG_READY_FILE:-}" ] \
			&& [ ! -s "$LIFECYCLE_WATCHDOG_READY_FILE" ]; then
			kill -KILL "$EXECD_WATCHDOG_PID" 2>/dev/null || true
		else
			kill -TERM "$EXECD_WATCHDOG_PID" 2>/dev/null || true
		fi
		wait "$EXECD_WATCHDOG_PID" 2>/dev/null || true
		EXECD_WATCHDOG_PID=""
	fi
}

_start_execd_watchdog() {
	_watchdog_delay="$1"
	_watchdog_message="$2"
	_watchdog_mark_timeout="${3:-1}"
	_watchdog_grace_delay="${4:-0}"
	_watchdog_signal="${5-TERM}"
	_watchdog_execd_pid="$EXECD_PID"
	_watchdog_timeout_file="${LIFECYCLE_WATCHDOG_TIMEOUT_FILE:-}"
	_watchdog_ready_file="${LIFECYCLE_WATCHDOG_READY_FILE:-}"
	_stop_execd_watchdog
	if [ "$_watchdog_mark_timeout" -eq 1 ] \
		&& [ -n "$_watchdog_timeout_file" ] \
		&& [ -s "$_watchdog_timeout_file" ]; then
		return 1
	fi
	if [ -n "$_watchdog_ready_file" ] \
		&& ! ( : > "$_watchdog_ready_file" ) 2>/dev/null; then
		return 1
	fi
	(
		# This child must never run the parent's cleanup or shutdown traps.
		trap - EXIT TERM INT
		_watchdog_cancelled=0
		_watchdog_sleep_pid=""
		_watchdog_spawning_sleep=0
		trap '_watchdog_cancelled=1; if [ -n "${_watchdog_sleep_pid:-}" ]; then kill -KILL "$_watchdog_sleep_pid" 2>/dev/null || true; elif [ "${_watchdog_spawning_sleep:-0}" -eq 0 ]; then exit 0; fi' TERM INT
		if [ -n "$_watchdog_ready_file" ] \
			&& ! printf 'ready\n' > "$_watchdog_ready_file"; then
			exit 1
		fi
		_watchdog_sleep() {
			if [ "$_watchdog_cancelled" -ne 0 ]; then
				return 1
			fi
			_watchdog_spawning_sleep=1
			sleep "$1" &
			_watchdog_sleep_pid=$!
			_watchdog_spawning_sleep=0
			if [ "$_watchdog_cancelled" -ne 0 ]; then
				kill -KILL "$_watchdog_sleep_pid" 2>/dev/null || true
			fi
			wait "$_watchdog_sleep_pid" || true
			_watchdog_sleep_pid=""
			if [ "$_watchdog_cancelled" -ne 0 ]; then
				return 1
			fi
		}
		_watchdog_sleep "$_watchdog_delay" || exit 0
		if [ "$_watchdog_grace_delay" != "0" ]; then
			_watchdog_sleep "$_watchdog_grace_delay" || exit 0
		fi
		if [ "$_watchdog_cancelled" -ne 0 ]; then
			exit 0
		fi
		if [ "$_watchdog_mark_timeout" -eq 1 ] && [ -n "$_watchdog_timeout_file" ]; then
			if ! printf 'timed-out\n' > "$_watchdog_timeout_file"; then
				_forward_signal KILL "$_watchdog_execd_pid"
				echo "error: failed to record lifecycle startup watchdog timeout" >&2 || true
				exit 1
			fi
		fi
		if [ -n "$_watchdog_message" ]; then
			echo "error: $_watchdog_message" >&2 || true
		fi
		if [ -n "$_watchdog_signal" ]; then
			_forward_signal "$_watchdog_signal" "$_watchdog_execd_pid"
		fi
		_watchdog_sleep 10 || exit 0
		_forward_signal KILL "$_watchdog_execd_pid"
	) &
	EXECD_WATCHDOG_PID=$!
	if [ -n "$_watchdog_ready_file" ]; then
		_watchdog_ready_attempts=0
		_watchdog_ready_limit=100
		_watchdog_ready_delay=0.1
		while [ ! -s "$_watchdog_ready_file" ] && [ "$_watchdog_ready_attempts" -lt "$_watchdog_ready_limit" ]; do
			_watchdog_state="$(_process_state "$EXECD_WATCHDOG_PID")"
			if [ "$_watchdog_state" = "Z" ]; then
				break
			fi
			if ! kill -0 "$EXECD_WATCHDOG_PID" 2>/dev/null; then
				break
			fi
			if ! sleep "$_watchdog_ready_delay" 2>/dev/null; then
				# POSIX sleep only requires integer operands. Keep the same
				# ten-second total bound when fractional sleep is unavailable.
				_watchdog_ready_delay=1
				_watchdog_ready_limit=10
				sleep 1
			fi
			_watchdog_ready_attempts=$((_watchdog_ready_attempts + 1))
		done
		if [ ! -s "$_watchdog_ready_file" ]; then
			kill -KILL "$EXECD_WATCHDOG_PID" 2>/dev/null || true
			wait "$EXECD_WATCHDOG_PID" 2>/dev/null || true
			EXECD_WATCHDOG_PID=""
			return 1
		fi
	fi
}

_shutdown_children() {
	sig="$1"
	_stop_execd_watchdog
	_forward_signal "$sig" "${CMD_PID:-}"
	_forward_signal "$sig" "${EXECD_PID:-}"
	if [ -n "${EXECD_PID:-}" ] && [ -n "${LIFECYCLE_STATUS_FILE:-}" ]; then
		# The signal was already forwarded above; this watchdog only bounds
		# graceful shutdown before escalating to KILL.
		if ! _start_execd_watchdog 0 "" 0 0 ""; then
			_forward_signal KILL "$EXECD_PID"
		fi
	fi
	if [ -n "${CMD_PID:-}" ]; then
		wait "$CMD_PID" 2>/dev/null || true
	fi
	if [ -n "${EXECD_PID:-}" ]; then
		wait "$EXECD_PID" 2>/dev/null || true
	fi
	_cleanup_lifecycle_status
	exit 0
}

trap '_shutdown_children TERM' TERM
trap '_shutdown_children INT' INT

# Returns 0 if the value looks like a boolean "true" (1, true, yes, on).
is_truthy() {
	case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
	1 | true | yes | on) return 0 ;;
	*) return 1 ;;
	esac
}

has_lifecycle_config() {
	# Keep this in sync with pkg/lifecycle/config.go's transport env, explicit
	# path env, and default persisted path.
	if [ -n "$(printf '%s' "${OPENSANDBOX_LIFECYCLE:-}" | tr -d '[:space:]')" ]; then
		return 0
	fi
	if [ -n "${EXECD_LIFECYCLE_CONFIG:-}" ]; then
		return 0
	fi
	if [ -n "${HOME:-}" ] && [ -e "$HOME/.execd/lifecycle.toml" ]; then
		return 0
	fi
	return 1
}

_cleanup_lifecycle_status() {
	_stop_execd_watchdog
	if [ -n "${LIFECYCLE_STATUS_FILE:-}" ]; then
		rm -f "$LIFECYCLE_STATUS_FILE"
		LIFECYCLE_STATUS_FILE=""
	fi
	if [ -n "${LIFECYCLE_WATCHDOG_TIMEOUT_FILE:-}" ]; then
		rm -f "$LIFECYCLE_WATCHDOG_TIMEOUT_FILE"
		LIFECYCLE_WATCHDOG_TIMEOUT_FILE=""
	fi
	if [ -n "${LIFECYCLE_WATCHDOG_READY_FILE:-}" ]; then
		rm -f "$LIFECYCLE_WATCHDOG_READY_FILE"
		LIFECYCLE_WATCHDOG_READY_FILE=""
	fi
	if [ -n "${LIFECYCLE_STATUS_DIR:-}" ]; then
		rmdir "$LIFECYCLE_STATUS_DIR" 2>/dev/null || true
		LIFECYCLE_STATUS_DIR=""
	fi
}

trap '_cleanup_lifecycle_status' EXIT

_sudo() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo -n "$@"
	else
		"$@"
	fi
}

# Install mitm CA into the system trust store (for non-Python programs)
# and set OPENSANDBOX_MERGED_CA to a PEM bundle containing a full root
# set + mitm CA (for env vars like REQUESTS_CA_BUNDLE that *replace*
# rather than append to the default roots).
OPENSANDBOX_MERGED_CA=""
trust_mitm_ca() {
	cert="$1"
	merged="${OPENSANDBOX_MERGED_CA_FILE:-/opt/opensandbox/merged-ca-certificates.pem}"

	# 1) Try to install into the system trust store (best-effort).
	if command -v update-ca-certificates >/dev/null 2>&1; then
		_sudo mkdir -p /usr/local/share/ca-certificates \
			&& _sudo cp "$cert" /usr/local/share/ca-certificates/opensandbox-mitmproxy-ca.crt \
			&& _sudo update-ca-certificates \
			|| echo "warning: update-ca-certificates failed; system trust store may not include mitm CA" >&2
	elif command -v update-ca-trust >/dev/null 2>&1; then
		_sudo mkdir -p /etc/pki/ca-trust/source/anchors \
			&& _sudo cp "$cert" /etc/pki/ca-trust/source/anchors/opensandbox-mitmproxy-ca.pem \
			&& { _sudo update-ca-trust extract || _sudo update-ca-trust; } \
			|| echo "warning: update-ca-trust failed; system trust store may not include mitm CA" >&2
	else
		echo "warning: no system trust-store tooling found (need update-ca-certificates or update-ca-trust)" >&2
	fi

	# 2) Build a merged bundle (complete root set + mitm CA).
	#    Prefer certifi (full Mozilla root set) over system bundles which
	#    may be incomplete in minimal Docker images.
	certifi_ca=""
	if command -v python3 >/dev/null 2>&1; then
		certifi_ca="$(python3 -c 'import certifi; print(certifi.where())' 2>/dev/null)" || certifi_ca=""
	elif command -v python >/dev/null 2>&1; then
		certifi_ca="$(python -c 'import certifi; print(certifi.where())' 2>/dev/null)" || certifi_ca=""
	fi

	for candidate in \
		"$certifi_ca" \
		/etc/ssl/certs/ca-certificates.crt \
		/etc/pki/tls/certs/ca-bundle.crt \
		/etc/ssl/cert.pem \
		/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
		if [ -n "$candidate" ] && [ -f "$candidate" ] && [ -s "$candidate" ]; then
			cat "$candidate" "$cert" > "$merged"
			OPENSANDBOX_MERGED_CA="$merged"
			return 0
		fi
	done

	echo "warning: could not locate any CA bundle to merge with mitm CA" >&2
	return 0
}

# Chromium/Chrome on Linux do not use only the system trust store: they also honor the per-user
# NSS database at $HOME/.pki/nssdb. Import the same mitm CA there so the browser trusts it.
# Requires certutil (e.g. Alpine: nss-tools, Debian/Ubuntu: libnss3-tools).
trust_mitm_ca_nss() {
	cert="$1"
	[ -f "$cert" ] || return 0
	if ! command -v certutil >/dev/null 2>&1; then
		echo "warning: certutil not found; Chromium/Chrome may not trust the mitm CA in NSS (install nss-tools on Alpine or libnss3-tools on Debian/Ubuntu)" >&2
		return 0
	fi
	[ -n "${HOME:-}" ] && [ -d "$HOME" ] || return 0
	pki="${HOME}/.pki/nssdb"
	if ! mkdir -p "$pki" 2>/dev/null; then
		return 0
	fi
	if [ -f "$pki/cert9.db" ]; then
		nssdb="sql:$pki"
	elif [ -f "$pki/cert8.db" ]; then
		nssdb="dbm:$pki"
	else
		nssdb="sql:$pki"
		if ! certutil -N -d "$nssdb" --empty-password 2>/dev/null; then
			[ -f "$pki/cert9.db" ] || return 0
		fi
	fi
	nick="opensandbox-mitmproxy"
	certutil -D -d "$nssdb" -n "$nick" 2>/dev/null || true
	if ! certutil -A -d "$nssdb" -n "$nick" -t "C,," -i "$cert"; then
		echo "warning: failed to import mitm CA into NSS at $pki (Chrome may still distrust); need certutil" >&2
		return 0
	fi
	return 0
}

# Import the mitm CA into every JDK trust store found on the system so that Java
# tooling (Maven, Gradle, HttpClient) trusts the credential-proxy MITM cert.
# Best-effort: missing keytool or import failure only warns, never blocks.
_jdk_import_ca() {
	jh="$1"
	cert="$2"
	kt="$jh/bin/keytool"
	[ -x "$kt" ] || return 0

	alias_name="opensandbox-mitmproxy"

	# Locate the cacerts keystore — JDK 9+ supports -cacerts flag,
	# JDK 8 and some vendors require an explicit -keystore path.
	ks=""
	if [ -f "$jh/lib/security/cacerts" ]; then
		ks="$jh/lib/security/cacerts"
	elif [ -f "$jh/jre/lib/security/cacerts" ]; then
		ks="$jh/jre/lib/security/cacerts"
	else
		return 0
	fi

	# Remove stale alias first so a regenerated CA cert is always picked up.
	if "$kt" -list -alias "$alias_name" -keystore "$ks" -storepass changeit >/dev/null 2>&1; then
		_sudo "$kt" -delete -alias "$alias_name" -keystore "$ks" -storepass changeit >/dev/null 2>&1
	fi

	if _sudo "$kt" -importcert -noprompt -trustcacerts \
		-alias "$alias_name" \
		-file "$cert" \
		-keystore "$ks" \
		-storepass changeit >/dev/null 2>&1; then
		echo "imported mitm CA into JDK trust store at $ks"
	else
		echo "warning: failed to import mitm CA into $ks" >&2
	fi
}

_SEEN_JDKS=""
_try_jdk() {
	candidate="$1"
	cert="$2"
	[ -d "$candidate" ] || return 0
	# Resolve to real path for dedup (POSIX: cd + pwd -P).
	real="$(cd "$candidate" 2>/dev/null && pwd -P)" || return 0
	case " $_SEEN_JDKS " in
	*" $real "*) return 0 ;;
	esac
	_SEEN_JDKS="$_SEEN_JDKS $real"
	_jdk_import_ca "$real" "$cert"
}

trust_mitm_ca_jdk() {
	cert="$1"
	[ -f "$cert" ] || return 0
	_SEEN_JDKS=""

	# 1) $JAVA_HOME if set.
	if [ -n "${JAVA_HOME:-}" ]; then
		_try_jdk "$JAVA_HOME" "$cert"
	fi

	# 2) Scan well-known JDK directories.
	for search_dir in /usr/lib/jvm /usr/java /opt/java; do
		if [ -d "$search_dir" ]; then
			for d in "$search_dir"/*/; do
				[ -d "$d" ] && _try_jdk "${d%/}" "$cert"
			done
		fi
	done
	# Standalone tarball installs (e.g. /opt/jdk, /opt/jdk-21).
	for d in /opt/jdk*; do
		[ -d "$d" ] && _try_jdk "$d" "$cert"
	done

	# 3) Fallback: resolve `java` on PATH to its JAVA_HOME.
	if command -v java >/dev/null 2>&1; then
		java_bin="$(command -v java)"
		# Follow symlinks (POSIX-portable loop).
		while [ -L "$java_bin" ]; do
			link_target="$(ls -l "$java_bin" 2>/dev/null | sed 's/.* -> //')"
			case "$link_target" in
			/*) java_bin="$link_target" ;;
			*) java_bin="$(dirname "$java_bin")/$link_target" ;;
			esac
		done
		# java_bin is now e.g. /usr/lib/jvm/java-17/bin/java → JAVA_HOME = grandparent
		jh_candidate="$(dirname "$(dirname "$java_bin")")"
		_try_jdk "$jh_candidate" "$cert"
	fi

	_SEEN_JDKS=""
	return 0
}

# The paths below default to where the image puts them. The overrides exist so that a test can run
# this script without root and without touching /opt or /tmp (WM-28).
MITM_CA="${OPENSANDBOX_MITM_CA_FILE:-/opt/opensandbox/mitmproxy-ca-cert.pem}"
OPENSANDBOX_MERGED_CA_FILE="${OPENSANDBOX_MERGED_CA_FILE:-/opt/opensandbox/merged-ca-certificates.pem}"
# THE DONE MARKER (WM-28). A fixed, documented path: /tmp/.opensandbox-ca-trust-done unless
# OPENSANDBOX_CA_TRUST_DONE_FILE says otherwise. It is removed when bootstrap starts and
# written once the trust step has finished, in every path: interception off, the CA never
# appearing, the imports done in the foreground, the imports done in the background. It
# means "the trust step is over, successfully or not" and NOT "the CA is trusted": a
# failed import only warns. A caller that must not run Chromium or Java before then waits
# for the file, with a bound of its own.
CA_TRUST_DONE_FILE="${OPENSANDBOX_CA_TRUST_DONE_FILE:-/tmp/.opensandbox-ca-trust-done}"
# What the background imports print. They cannot share bootstrap's stdout and stderr: a
# caller reading them through a pipe would not see EOF until the imports finished.
CA_TRUST_LOG="${OPENSANDBOX_CA_TRUST_LOG:-/tmp/.opensandbox-ca-trust.log}"

# The redirection runs in a subshell: a failed redirection on a special builtin such as `:`
# aborts a POSIX shell (dash), and the trust step must never be what stops bootstrap.
_ca_trust_done() {
	( : > "$CA_TRUST_DONE_FILE" ) 2>/dev/null || true
}
rm -f "$CA_TRUST_DONE_FILE" 2>/dev/null || true

# Milliseconds since the epoch. Fractional seconds are not POSIX: where date has no %N it
# prints a literal one, which is not a number, and whole seconds are used instead.
_now_ms() {
	_ms="$(date +%s%N 2>/dev/null)"
	case "$_ms" in
	"" | *[!0-9]*) echo $(($(date +%s) * 1000)) ;;
	*) echo $((_ms / 1000000)) ;;
	esac
}

if ! is_truthy "${OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT:-}"; then
	_ca_trust_done
else
	# Poll every 50 ms; the CA usually appears about a second after the container starts, and
	# a 1 s poll costs up to 0.9 s of every sandbox start. Where sleep takes no fraction, poll
	# every second. The budget is 300 s of the clock either way, counted in time and not in
	# tries, so the finer poll does not shrink it; the try count is only a backstop against a
	# clock that moves backwards.
	_wait_budget_ms=300000
	_wait_start_ms="$(_now_ms)"
	# ONE readiness decision, taken where the wait ends: 1 when the CA is there, 0 on timeout.
	# A timeout means no imports and the marker; a CA means the imports and then the marker.
	# Looking at the file a second time would let a CA that arrives in between publish the
	# marker before its imports.
	_ca_ready=0
	_wait_ticks=0
	_wait_step=0.05
	_wait_max_ticks=$((_wait_budget_ms / 50))
	_wait_elapsed_ms=0
	# The probe is the first tick of a wait that is going to happen anyway.
	if [ ! -s "$MITM_CA" ]; then
		if ! sleep "$_wait_step" 2>/dev/null; then
			_wait_step=1
			_wait_max_ticks=$((_wait_budget_ms / 1000))
			sleep 1
		fi
		_wait_ticks=1
	fi
	while [ ! -s "$MITM_CA" ]; do
		_wait_elapsed_ms=$(($(_now_ms) - _wait_start_ms))
		if [ "$_wait_elapsed_ms" -ge "$_wait_budget_ms" ] || [ "$_wait_ticks" -ge "$_wait_max_ticks" ]; then
			break
		fi
		sleep "$_wait_step"
		_wait_ticks=$((_wait_ticks + 1))
	done
	if [ ! -f "$MITM_CA" ] || [ ! -s "$MITM_CA" ]; then
		echo "warning: timed out after $((_wait_elapsed_ms / 1000))s waiting for $MITM_CA (egress mitm CA export); continuing without system CA trust" >&2
		_ca_trust_done
	else
		_ca_ready=1
		_wait_elapsed_ms=$(($(_now_ms) - _wait_start_ms))
		echo "mitm CA ready at $MITM_CA after ${_wait_elapsed_ms}ms"
		if ! trust_mitm_ca "$MITM_CA"; then
			echo "warning: failed to install mitm CA into system trust store; TLS interception may not work for system libraries" >&2
		fi
	fi

	if [ "$_ca_ready" -eq 1 ]; then
		# NSS (Chromium) and the JDK stores cost about a second between them. By default they
		# are imported here, before execd starts, as they always were. With
		# OPENSANDBOX_CA_TRUST_BACKGROUND=true they are imported in a background subshell and
		# execd does not wait for them: a Chromium or Java started in that second can miss
		# the CA, and a caller that cares waits for the done marker. The subshell ignores
		# SIGHUP, takes no input and writes to a file, so it neither dies with this shell nor
		# keeps its stdout open; when bootstrap execs into execd the job carries on under it.
		# A failed import only warns, either way.
		# The log is opened here first: if it cannot be, the async subshell would die on its
		# redirection before importing anything or writing the marker, so the imports are
		# done in the foreground instead.
		_ca_bg=0
		if is_truthy "${OPENSANDBOX_CA_TRUST_BACKGROUND:-}"; then
			if ( : >> "$CA_TRUST_LOG" ) 2>/dev/null; then
				_ca_bg=1
			else
				echo "warning: cannot write $CA_TRUST_LOG; importing the CA into NSS and the JDK in the foreground" >&2
			fi
		fi
		if [ "$_ca_bg" -eq 1 ]; then
			(
				trap '' HUP
				trust_mitm_ca_nss "$MITM_CA" || true
				trust_mitm_ca_jdk "$MITM_CA" || true
				_ca_trust_done
			) </dev/null >"$CA_TRUST_LOG" 2>&1 &
			echo "mitm CA trust for NSS and JDK continues in the background (log $CA_TRUST_LOG, done marker $CA_TRUST_DONE_FILE)"
		else
			trust_mitm_ca_nss "$MITM_CA" || true
			trust_mitm_ca_jdk "$MITM_CA" || true
			_ca_trust_done
		fi
		export NODE_EXTRA_CA_CERTS="$MITM_CA"  # additive — Node appends to built-in roots

		# REQUESTS_CA_BUNDLE and SSL_CERT_FILE replace the default bundle,
		# so use merged roots (certifi/system CA + mitm CA).
		if [ -n "$OPENSANDBOX_MERGED_CA" ] && [ -f "$OPENSANDBOX_MERGED_CA" ]; then
			export REQUESTS_CA_BUNDLE="$OPENSANDBOX_MERGED_CA"
			export SSL_CERT_FILE="$OPENSANDBOX_MERGED_CA"
		else
			echo "warning: merged CA bundle not available; REQUESTS_CA_BUNDLE/SSL_CERT_FILE will only contain the mitm CA" >&2
			export REQUESTS_CA_BUNDLE="$MITM_CA"
			export SSL_CERT_FILE="$MITM_CA"
		fi
	fi
fi

EXECD="${EXECD:=/opt/opensandbox/execd}"

if [ -z "${EXECD_ENVS:-}" ]; then
	EXECD_ENVS="/opt/opensandbox/.env"
fi
if ! mkdir -p "$(dirname "$EXECD_ENVS")" 2>/dev/null; then
	echo "warning: failed to create dir for EXECD_ENVS=$EXECD_ENVS" >&2
fi
if ! touch "$EXECD_ENVS" 2>/dev/null; then
	echo "warning: failed to touch EXECD_ENVS=$EXECD_ENVS" >&2
fi
export EXECD_ENVS

# Run a user-defined pre-script before launching execd. The script is sourced
# with POSIX `.` (not executed as a child process) so any variables it
# `export`s propagate to execd and the chained command below — a subprocess
# would lose those exports the moment it exits.
if [ -n "${EXECD_BOOTSTRAP_PRE_SCRIPT:-}" ]; then
	if [ -f "$EXECD_BOOTSTRAP_PRE_SCRIPT" ] && [ -r "$EXECD_BOOTSTRAP_PRE_SCRIPT" ]; then
		# Force `.` to read the literal path; without a slash it would fall
		# back to a PATH search and could load the wrong file.
		case "$EXECD_BOOTSTRAP_PRE_SCRIPT" in
		*/*) _pre_script="$EXECD_BOOTSTRAP_PRE_SCRIPT" ;;
		*) _pre_script="./$EXECD_BOOTSTRAP_PRE_SCRIPT" ;;
		esac
		echo "sourcing pre-script $EXECD_BOOTSTRAP_PRE_SCRIPT"
		# shellcheck disable=SC1090
		. "$_pre_script"
		unset _pre_script
	else
		echo "warning: EXECD_BOOTSTRAP_PRE_SCRIPT=$EXECD_BOOTSTRAP_PRE_SCRIPT not found or not readable" >&2
	fi
fi

echo "starting OpenSandbox Execd daemon at $EXECD."

# Allow chained shell commands (e.g., /test1.sh && /test2.sh)
# Usage:
#   bootstrap.sh -c "/test1.sh && /test2.sh"
# Or set BOOTSTRAP_CMD="/test1.sh && /test2.sh"
CMD=""
if [ "${BOOTSTRAP_CMD:-}" != "" ]; then
	CMD="$BOOTSTRAP_CMD"
elif [ $# -ge 1 ] && [ "$1" = "-c" ]; then
	shift
	CMD="$*"
fi

SHELL_BIN="${BOOTSTRAP_SHELL:-}"
if [ -z "$SHELL_BIN" ]; then
	if command -v bash >/dev/null 2>&1; then
		SHELL_BIN="$(command -v bash)"
	elif command -v sh >/dev/null 2>&1; then
		SHELL_BIN="$(command -v sh)"
	else
		echo "error: neither bash nor sh found in PATH" >&2
		exit 1
	fi
fi

# Resolve the user command into a concrete argv shared by both branches.
if [ "$CMD" != "" ]; then
	set -- "$SHELL_BIN" -c "$CMD"
elif [ $# -eq 0 ]; then
	set -- "$SHELL_BIN"
fi

# Init mode (OSEP-0018): exec into execd so it becomes PID 1 and supervises
# the user command. The shell must exec, never background, or execd runs as a
# subreaper without the kernel signal shield.
if is_truthy "${EXECD_INIT:-}"; then
	exec "$EXECD" --init -- "$@"
fi

if has_lifecycle_config; then
	if ! LIFECYCLE_STATUS_DIR="$(
		umask 077
		mktemp -d "${TMPDIR:-/tmp}/execd-lifecycle.XXXXXX" 2>/dev/null \
			|| mktemp -d /tmp/execd-lifecycle.XXXXXX 2>/dev/null
	)"; then
		echo "error: failed to create lifecycle startup status directory" >&2
		exit 1
	fi
	LIFECYCLE_STATUS_FILE="${LIFECYCLE_STATUS_DIR}/status"
	LIFECYCLE_WATCHDOG_TIMEOUT_FILE="${LIFECYCLE_STATUS_DIR}/watchdog-timeout"
	LIFECYCLE_WATCHDOG_READY_FILE="${LIFECYCLE_STATUS_DIR}/watchdog-ready"
	if ! (
		umask 077 \
			&& : > "$LIFECYCLE_STATUS_FILE" \
			&& : > "$LIFECYCLE_WATCHDOG_TIMEOUT_FILE" \
			&& : > "$LIFECYCLE_WATCHDOG_READY_FILE"
	); then
		echo "error: failed to create lifecycle startup synchronization files" >&2
		exit 1
	fi
	"$EXECD" --lifecycle-startup-status-file "$LIFECYCLE_STATUS_FILE" &
else
	"$EXECD" &
fi
EXECD_PID=$!

# The same long-running execd starts serving HTTP, executes preStart, then
# reports the result through this private bootstrap synchronization file.
if [ -n "$LIFECYCLE_STATUS_FILE" ]; then
	if ! _start_execd_watchdog 10 "execd did not report lifecycle startup within 10 seconds"; then
		echo "error: failed to arm the lifecycle startup watchdog" >&2
		_forward_signal TERM "$EXECD_PID"
		_forward_signal KILL "$EXECD_PID"
		wait "$EXECD_PID" 2>/dev/null || true
		EXECD_PID=""
		exit 1
	fi
	_lifecycle_running_seen=0
	_lifecycle_done=0
	_prestart_status=""
	while [ "$_lifecycle_done" -eq 0 ]; do
		_lifecycle_status=""
		if [ ! -r "$LIFECYCLE_STATUS_FILE" ]; then
			echo "error: lifecycle startup status file is missing or unreadable" >&2
			_lifecycle_done=1
			_prestart_status=1
		elif ! {
			while IFS= read -r _lifecycle_status_line; do
				_lifecycle_status="$_lifecycle_status_line"
			done < "$LIFECYCLE_STATUS_FILE"
		} 2>/dev/null; then
			echo "error: lifecycle startup status file is missing or unreadable" >&2
			_lifecycle_done=1
			_prestart_status=1
		fi
		case "$_lifecycle_status" in
		"running "*)
			if [ "$_lifecycle_running_seen" -eq 0 ]; then
				_prestart_timeout="${_lifecycle_status#running }"
				# execd reports a validated positive timeout of at most ten digits.
				# Treat any other value as corrupt before passing it to sleep.
				case "$_prestart_timeout" in
				"" | *[!0-9]* | 0* | ???????????*) _lifecycle_done=1; _prestart_status=1 ;;
				*)
					_lifecycle_running_seen=1
					if ! _start_execd_watchdog \
						"$_prestart_timeout" \
						"lifecycle preStart did not report completion after its timeout and 10-second grace" \
						1 10; then
						_lifecycle_done=1
						_prestart_status=1
					fi
					;;
				esac
			fi
			;;
		"done "*)
			_prestart_status="${_lifecycle_status#done }"
			_lifecycle_done=1
			;;
		"") ;;
		*) _lifecycle_done=1; _prestart_status=1 ;;
		esac
		if [ "$_lifecycle_done" -ne 0 ]; then
			break
		fi
		_execd_state="$(_process_state "$EXECD_PID")"
		if ! kill -0 "$EXECD_PID" 2>/dev/null || [ "$_execd_state" = "Z" ]; then
			_stop_execd_watchdog
			set +e
			wait "$EXECD_PID"
			_execd_status=$?
			set -e
			EXECD_PID=""
			_cleanup_lifecycle_status
			if [ "$_execd_status" -eq 0 ]; then
				_execd_status=1
			fi
			exit "$_execd_status"
		fi
		# Execd reports the effective hook timeout before running preStart. The
		# external watchdog also bounds a hung daemon that never reports a result.
		sleep 0.1 2>/dev/null || sleep 1
	done
	_stop_execd_watchdog
	if [ -n "${LIFECYCLE_WATCHDOG_TIMEOUT_FILE:-}" ] \
		&& [ -s "$LIFECYCLE_WATCHDOG_TIMEOUT_FILE" ]; then
		_prestart_status=1
	fi
	case "${_prestart_status:-}" in
	0 | [1-9] | [1-9][0-9] | [1-9][0-9][0-9])
		if [ "$_prestart_status" -gt 255 ]; then
			_prestart_status=1
		fi
		;;
	*) _prestart_status=1 ;;
	esac
	if [ "$_prestart_status" -ne 0 ]; then
		if ! _start_execd_watchdog 0 "" 0; then
			echo "error: failed to start execd shutdown watchdog" >&2
			# Failing to arm the bounded escalation path must not leave execd
			# running or turn this failure path into an unbounded wait.
			_forward_signal TERM "$EXECD_PID"
			_forward_signal KILL "$EXECD_PID"
		fi
		set +e
		wait "$EXECD_PID"
		_execd_status=$?
		_stop_execd_watchdog
		set -e
		EXECD_PID=""
		_cleanup_lifecycle_status
		echo "error: lifecycle preStart failed (status $_prestart_status, execd exit $_execd_status)" >&2
		exit "$_prestart_status"
	fi
	_cleanup_lifecycle_status
	unset _prestart_status _execd_status
fi

unset OPENSANDBOX_LIFECYCLE EXECD_LIFECYCLE_CONFIG
"$@" &
CMD_PID=$!

set +e
wait "$CMD_PID" 2>/dev/null
CMD_STATUS=$?
set -e
_forward_signal TERM "$EXECD_PID"
wait "$EXECD_PID" 2>/dev/null || true
exit "$CMD_STATUS"
