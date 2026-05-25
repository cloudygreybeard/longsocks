#!/usr/bin/env bash
#
# End-to-end tests for longsocks. Starts server and client instances,
# verifies SOCKS5 and HTTP CONNECT proxy modes, and checks authentication
# rejection and acceptance.

set -euo pipefail

BINARY="$(cd "$(dirname "$0")/.." && pwd)/bin/longsocks"
readonly BINARY
AUTH_LOG="$(mktemp)"
readonly AUTH_LOG
PIDS=()

#######################################
# Send an error message to stderr.
# Arguments:
#   Error message string.
#######################################
err() {
  echo "[ERROR] $*" >&2
}

#######################################
# Block until a TCP port accepts connections.
# Arguments:
#   1 - port number
#   2 - timeout in seconds (default: 5)
#######################################
wait_for_port() {
  local port="$1"
  local timeout="${2:-5}"
  local deadline=$(( SECONDS + timeout ))
  while (( SECONDS < deadline )); do
    if (echo >/dev/tcp/127.0.0.1/"${port}") 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  err "port ${port} not ready after ${timeout}s"
  return 1
}

#######################################
# Kill and reap all tracked background processes.
# Globals:
#   PIDS
#######################################
cleanup() {
  local pid
  for pid in "${PIDS[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${PIDS[@]}"; do
    wait "${pid}" 2>/dev/null || true
  done
  PIDS=()
}
trap cleanup EXIT

#######################################
# Run all end-to-end tests.
# Globals:
#   BINARY
#   AUTH_LOG
#   PIDS
#######################################
main() {
  local result
  local failures=0

  echo "=== Test 1: Open proxy (no auth) ==="
  "${BINARY}" server --addr 127.0.0.1:18090 2>/dev/null &
  PIDS+=($!)
  wait_for_port 18090

  "${BINARY}" client --addr 127.0.0.1:11090 --server ws://127.0.0.1:18090 2>/dev/null &
  PIDS+=($!)
  wait_for_port 11090

  result="$(curl -s --max-time 15 -x socks5h://127.0.0.1:11090 https://httpbin.org/ip)"
  if [[ "${result}" =~ origin ]]; then
    echo "PASS: ${result}"
  else
    err "FAIL: ${result}"
    (( failures += 1 ))
  fi

  cleanup

  echo ""
  echo "=== Test 2: Auth rejection (no token, server requires one) ==="
  "${BINARY}" server --addr 127.0.0.1:18091 --token mysecret 2>"${AUTH_LOG}" &
  PIDS+=($!)
  wait_for_port 18091

  "${BINARY}" client --addr 127.0.0.1:11091 --server ws://127.0.0.1:18091 2>/dev/null &
  PIDS+=($!)
  wait_for_port 11091

  curl -s --max-time 5 -x socks5h://127.0.0.1:11091 https://httpbin.org/ip >/dev/null 2>&1 || true
  if [[ -f "${AUTH_LOG}" ]] && grep -q "auth.failure" "${AUTH_LOG}"; then
    echo "PASS: auth.failure logged"
  else
    err "FAIL: no auth.failure in server log"
    (( failures += 1 ))
  fi

  # Kill only the client; keep the server for test 3.
  kill "${PIDS[1]}" 2>/dev/null
  wait "${PIDS[1]}" 2>/dev/null || true
  PIDS=("${PIDS[0]}")

  echo ""
  echo "=== Test 3: Auth acceptance (correct token) ==="
  "${BINARY}" client --addr 127.0.0.1:11092 --server ws://127.0.0.1:18091 --token mysecret 2>/dev/null &
  PIDS+=($!)
  wait_for_port 11092

  result="$(curl -s --max-time 15 -x socks5h://127.0.0.1:11092 https://httpbin.org/ip)"
  if [[ "${result}" =~ origin ]]; then
    echo "PASS: ${result}"
  else
    err "FAIL: ${result}"
    (( failures += 1 ))
  fi

  cleanup

  echo ""
  echo "=== Test 4: HTTP CONNECT mode ==="
  "${BINARY}" server --addr 127.0.0.1:18093 --token mysecret --modes socks5,connect 2>/dev/null &
  PIDS+=($!)
  wait_for_port 18093

  "${BINARY}" client --mode connect --addr 127.0.0.1:11093 --server ws://127.0.0.1:18093 --token mysecret 2>/dev/null &
  PIDS+=($!)
  wait_for_port 11093

  result="$(curl -s --max-time 15 -x http://127.0.0.1:11093 https://httpbin.org/ip)"
  if [[ "${result}" =~ origin ]]; then
    echo "PASS: ${result}"
  else
    err "FAIL: ${result}"
    (( failures += 1 ))
  fi

  cleanup

  echo ""
  echo "=== Test 5: Mux mode ==="
  "${BINARY}" server --addr 127.0.0.1:18094 --token mysecret 2>/dev/null &
  PIDS+=($!)
  wait_for_port 18094

  "${BINARY}" client --mux --addr 127.0.0.1:11094 \
      --server ws://127.0.0.1:18094 --token mysecret 2>/dev/null &
  PIDS+=($!)
  wait_for_port 11094

  result="$(curl -s --max-time 15 -x socks5h://127.0.0.1:11094 https://httpbin.org/ip)"
  if [[ "${result}" =~ origin ]]; then
    echo "PASS: ${result}"
  else
    err "FAIL: ${result}"
    (( failures += 1 ))
  fi

  cleanup

  echo ""
  echo "=== Test 6: Port forward ==="
  "${BINARY}" server --addr 127.0.0.1:18095 --token mysecret 2>/dev/null &
  PIDS+=($!)
  wait_for_port 18095

  "${BINARY}" forward --server ws://127.0.0.1:18095 --token mysecret \
      3095:httpbin.org:80 2>/dev/null &
  PIDS+=($!)
  wait_for_port 3095

  result="$(curl -s --max-time 15 -H 'Host: httpbin.org' http://127.0.0.1:3095/ip)"
  if [[ "${result}" =~ origin ]]; then
    echo "PASS: ${result}"
  else
    err "FAIL: ${result}"
    (( failures += 1 ))
  fi

  cleanup

  echo ""
  echo "=== Test 7: Fingerprint rejection ==="
  "${BINARY}" server --addr 127.0.0.1:18096 --token mysecret 2>/dev/null &
  PIDS+=($!)
  wait_for_port 18096

  local fp_log
  fp_log="$(mktemp)"
  "${BINARY}" client --mux --addr 127.0.0.1:11096 \
      --server ws://127.0.0.1:18096 --token mysecret \
      --fingerprint AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
      --max-retry-count 1 2>"${fp_log}" &
  PIDS+=($!)

  local fp_deadline=$(( SECONDS + 10 ))
  while (( SECONDS < fp_deadline )); do
    if grep -q "fingerprint mismatch" "${fp_log}" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if grep -q "fingerprint mismatch" "${fp_log}"; then
    echo "PASS: fingerprint mismatch detected"
  else
    err "FAIL: no fingerprint mismatch in client log"
    (( failures += 1 ))
  fi
  rm -f "${fp_log}"

  cleanup
  rm -f "${AUTH_LOG}"

  echo ""
  if (( failures > 0 )); then
    err "${failures} test(s) failed"
    exit 1
  fi
  echo "=== All tests passed ==="
}

main "$@"
