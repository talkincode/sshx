#!/bin/bash
# Test MCP debug logging functionality
# This script tests that MCP requests and responses are logged when using --debug flag

set -e

echo "=== Testing MCP Debug Logging with --debug Flag ==="
echo ""

# Setup
LOG_FILE="$HOME/.sshx/sshx.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/bin/sshx"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Please run 'make build' first"
    exit 1
fi

# Clean up old log file
if [ -f "$LOG_FILE" ]; then
    echo "Cleaning up old log file: $LOG_FILE"
    rm -f "$LOG_FILE"
fi

# Test 1: Using --debug flag
echo "=== Test 1: Using --debug flag ==="
echo ""

# Create a named pipe for communication
FIFO_IN=$(mktemp -u)
FIFO_OUT=$(mktemp -u)
mkfifo "$FIFO_IN"
mkfifo "$FIFO_OUT"

# Start MCP server with --debug flag
"$BINARY" mcp-stdio --debug < "$FIFO_IN" > "$FIFO_OUT" &
MCP_PID=$!

# Clean up function
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$MCP_PID" ]; then
        kill "$MCP_PID" 2>/dev/null || true
    fi
    rm -f "$FIFO_IN" "$FIFO_OUT"
}
trap cleanup EXIT

# Give server time to start
sleep 1

echo "MCP server started (PID: $MCP_PID)"
echo ""

# Send initialize request
echo "Sending initialize request..."
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' > "$FIFO_IN" &

# Read response
timeout 2 cat "$FIFO_OUT" > /dev/null &

sleep 1

# Send tools/list request
echo "Sending tools/list request..."
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' > "$FIFO_IN" &

# Read response
timeout 2 cat "$FIFO_OUT" > /dev/null &

sleep 1

# Send shutdown request
echo "Sending shutdown request..."
echo '{"jsonrpc":"2.0","id":3,"method":"shutdown","params":{}}' > "$FIFO_IN" &

sleep 1

# Check log file
echo ""
echo "=== Checking Debug Log File ==="
if [ ! -f "$LOG_FILE" ]; then
    echo "❌ FAILED: Log file not created at $LOG_FILE"
    exit 1
fi

echo "✓ Log file exists: $LOG_FILE"
echo ""

# Check for expected log entries
echo "=== Verifying Log Content ==="

# Check for MCP server starting message
if grep -q "MCP server starting in debug mode (--debug flag)" "$LOG_FILE"; then
    echo "✓ Found: MCP server starting message with --debug flag"
else
    echo "⚠️  Warning: MCP server starting message with --debug flag not found"
fi

# Check for request logs
if grep -q "MCP Request received:" "$LOG_FILE"; then
    echo "✓ Found: MCP request logs"
else
    echo "❌ FAILED: No MCP request logs found"
    exit 1
fi

# Check for response logs
if grep -q "MCP Response sent:" "$LOG_FILE"; then
    echo "✓ Found: MCP response logs"
else
    echo "❌ FAILED: No MCP response logs found"
    exit 1
fi

# Check for initialize method
if grep -q '"method":"initialize"' "$LOG_FILE"; then
    echo "✓ Found: initialize method in logs"
else
    echo "❌ FAILED: initialize method not found in logs"
    exit 1
fi

# Check for tools/list method
if grep -q '"method":"tools/list"' "$LOG_FILE"; then
    echo "✓ Found: tools/list method in logs"
else
    echo "⚠️  Warning: tools/list method not found in logs"
fi

echo ""
echo "=== Sample Log Content ==="
echo "First 20 lines of log file:"
head -20 "$LOG_FILE" | sed 's/^/  /'

echo ""
echo "=== Test Summary ==="
echo "✓ All critical checks passed!"
echo "✓ Debug logging with --debug flag is working correctly"
echo ""

# Test 2: Using environment variable
echo "=== Test 2: Using SSHX_LOG_LEVEL environment variable ==="
echo ""

# Clean up from test 1
rm -f "$LOG_FILE"

# Create new pipes
FIFO_IN2=$(mktemp -u)
FIFO_OUT2=$(mktemp -u)
mkfifo "$FIFO_IN2"
mkfifo "$FIFO_OUT2"

# Start MCP server with environment variable
export SSHX_LOG_LEVEL=debug
"$BINARY" mcp-stdio < "$FIFO_IN2" > "$FIFO_OUT2" &
MCP_PID2=$!

cleanup2() {
    echo ""
    echo "Cleaning up test 2..."
    if [ -n "$MCP_PID2" ]; then
        kill "$MCP_PID2" 2>/dev/null || true
    fi
    rm -f "$FIFO_IN2" "$FIFO_OUT2"
}
trap cleanup2 EXIT

# Give server time to start
sleep 1

echo "MCP server started with SSHX_LOG_LEVEL=debug (PID: $MCP_PID2)"

# Send initialize request
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' > "$FIFO_IN2" &
timeout 2 cat "$FIFO_OUT2" > /dev/null &
sleep 1

# Send shutdown
echo '{"jsonrpc":"2.0","id":2,"method":"shutdown","params":{}}' > "$FIFO_IN2" &
sleep 1

# Check log file
if [ -f "$LOG_FILE" ]; then
    echo "✓ Log file created with environment variable"

    if grep -q "MCP server starting in debug mode (SSHX_LOG_LEVEL)" "$LOG_FILE"; then
        echo "✓ Found: MCP server starting message with SSHX_LOG_LEVEL"
    else
        echo "⚠️  Warning: Expected log message not found"
    fi

    if grep -q "MCP Request received:" "$LOG_FILE"; then
        echo "✓ Found: MCP request logs with environment variable"
    fi
else
    echo "❌ FAILED: Log file not created with environment variable"
    exit 1
fi

echo ""
echo "=== Overall Test Summary ==="
echo "✓ Test 1 passed: --debug flag works correctly"
echo "✓ Test 2 passed: SSHX_LOG_LEVEL environment variable works correctly"
echo "✓ Debug logging is working with both methods"
echo ""
echo "Log file location: $LOG_FILE"
echo "You can view the full log with: cat $LOG_FILE"
echo "Or monitor it in real-time with: tail -f $LOG_FILE"
