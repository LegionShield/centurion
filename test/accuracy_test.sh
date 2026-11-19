#!/bin/bash

# legion-subdomain accuracy test script

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

TEST_DOMAIN="example.com"
TEST_DICT="test/accuracy_dict.txt"
RESOLVERS="test/resolvers.txt"
ORIG_BIN="test/legion-subdomain_orig"
NEW_BIN="./legion-subdomain"
ORIG_OUTPUT="test/results/orig_accuracy.txt"
NEW_OUTPUT="test/results/new_accuracy.txt"
DIFF_OUTPUT="test/results/diff.txt"

mkdir -p "test/results"

if [ ! -f "$ORIG_BIN" ]; then
  echo -e "${RED}Error: original binary not found at $ORIG_BIN${NC}"
  echo "Place the original legion-subdomain binary in the test directory, renamed to legion-subdomain_orig"
  exit 1
fi

if [ ! -f "$RESOLVERS" ]; then
  echo "Creating DNS resolver file..."
  echo "8.8.8.8" > "$RESOLVERS"
  echo "8.8.4.4" >> "$RESOLVERS"
  echo "1.1.1.1" >> "$RESOLVERS"
  echo "114.114.114.114" >> "$RESOLVERS"
fi

if [ ! -f "$TEST_DICT" ]; then
  echo "Creating test dictionary..."
  echo "www.$TEST_DOMAIN" > "$TEST_DICT"
  echo "mail.$TEST_DOMAIN" >> "$TEST_DICT"
  echo "api.$TEST_DOMAIN" >> "$TEST_DICT"
  echo "blog.$TEST_DOMAIN" >> "$TEST_DICT"
  echo "docs.$TEST_DOMAIN" >> "$TEST_DICT"
  for i in {1..95}; do
    echo "test$i.$TEST_DOMAIN" >> "$TEST_DICT"
  done
fi

echo "========================================"
echo "   LΞGION Accuracy Test"
echo "========================================"

echo -e "${YELLOW}Running original binary...${NC}"
$ORIG_BIN v -f "$TEST_DICT" -r "$RESOLVERS" -o "$ORIG_OUTPUT" -b 5m --retry 3 --timeout 6

echo -e "${YELLOW}Running optimized binary...${NC}"
$NEW_BIN v -f "$TEST_DICT" -r "$RESOLVERS" -o "$NEW_OUTPUT" -b 5m --retry 3 --timeout 6

echo -e "${YELLOW}Comparing results...${NC}"
sort "$ORIG_OUTPUT" > "$ORIG_OUTPUT.sorted"
sort "$NEW_OUTPUT" > "$NEW_OUTPUT.sorted"

diff "$ORIG_OUTPUT.sorted" "$NEW_OUTPUT.sorted" > "$DIFF_OUTPUT"

if [ -s "$DIFF_OUTPUT" ]; then
  DIFF_COUNT=$(wc -l < "$DIFF_OUTPUT")
  echo -e "${RED}Differences found! $DIFF_COUNT lines differ${NC}"
  echo "Diff saved to $DIFF_OUTPUT"
  echo "Diff contents:"
  cat "$DIFF_OUTPUT"
else
  echo -e "${GREEN}Test passed! Both versions produce identical results${NC}"
  FOUND_COUNT=$(wc -l < "$NEW_OUTPUT")
  echo "Found $FOUND_COUNT subdomains"
  rm "$DIFF_OUTPUT"
fi

rm "$ORIG_OUTPUT.sorted" "$NEW_OUTPUT.sorted"

echo "Test complete!"
