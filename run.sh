#!/bin/bash

# This is script for extracting experiment data, filtering desired data items and stating average time.
echo "=================== Part 1 functional testing       ==================="
/usr/local/go/bin/go test -v -run TestScheme
echo "=================== Part 1 functional testing done  ==================="

echo "=================== Part 2 benchmark testing        ==================="
file=benchmark.txt
directory=datafile

if [ -f "$file" ]; then
  echo "1.removing old benchmark file ... "
  rm -rf "$file"
fi

if [ -d "$directory" ]; then
  echo "2.removing old data directory ... "
  rm -rf "$directory"
fi


echo 'starting running benchmark'
nohup /usr/local/go/bin/go test -bench=BenchmarkSchemeL*  -cpu=1 -count=1000 -timeout 3500m> $file 2>&1 &
echo "=================== Part 2 benchmark testing done   ==================="
