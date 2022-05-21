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
/usr/local/go/bin/go test -bench=BenchmarkSchemeL*  -cpu=1 -count=1000 -timeout 3500m> $file
echo "=================== Part 2 benchmark testing done   ==================="

echo "=================== Part 3 extracting data          ==================="

if [ ! -d "$directory" ]; then
  echo '3.creating datafile directory'
  mkdir $directory
fi

# level 0
benchmarkFuncName[0]=BenchmarkSchemeL0Setup
benchmarkFuncName[1]=BenchmarkSchemeL0RootWalletKeyGen
benchmarkFuncName[2]=BenchmarkSchemeL0VerifyKeyDerive
benchmarkFuncName[3]=BenchmarkSchemeL0VerifyKeyCheck
benchmarkFuncName[4]=BenchmarkSchemeL0SignKeyDerive
benchmarkFuncName[5]=BenchmarkSchemeL0Sign
benchmarkFuncName[6]=BenchmarkSchemeL0Verify

#level 1
benchmarkFuncName[7]=BenchmarkSchemeL1WalletKeyDelegate
benchmarkFuncName[8]=BenchmarkSchemeL1VerifyKeyDerive
benchmarkFuncName[9]=BenchmarkSchemeL1VerifyKeyCheck
benchmarkFuncName[11]=BenchmarkSchemeL1SignKeyDerive
benchmarkFuncName[12]=BenchmarkSchemeL1Sign
benchmarkFuncName[13]=BenchmarkSchemeL1Verify


echo ${#benchmarkFuncName[@]}
for((i=0;i<${#benchmarkFuncName[@]};i++));
do
   echo ${benchmarkFuncName[$i]}
   awk '$1 ~ /^'${benchmarkFuncName[$i]}'$/ {print $1,$3}' $file > ./$directory/${benchmarkFuncName[$i]}.txt
   cat  ./$directory/${benchmarkFuncName[$i]}.txt
   echo 'extracting' ${benchmarkFuncName[$i]}' data done'
done

for filename in ./$directory/*
do
  echo $filename
  cat $filename | awk '{sum+=$2} END {print "#times = ", NR, ", Average = ", sum/NR, " ns"}'
done

echo BenchmarkSchemeL1Verify
awk '$1 ~ /^'BenchmarkSchemeL1Verify'$/ {print $1,$3}' $file > ./$directory/BenchmarkSchemeL1Verify.txt
cat ./datafile/BenchmarkSchemeL1Verify.txt | awk '{sum+=$2} END {print "#times = ", NR, "Sum = ",sum, "Average = ", sum/NR, " ns"}'

echo "=================== Part 3 extracting data done         ===============" 
