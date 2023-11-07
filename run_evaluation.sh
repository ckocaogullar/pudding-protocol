#!/bin/bash
scenarios="register lookup_identity lookup_anonymous"
numUsers="20"
numServers="4 7 10"

cd "$(dirname "$0")";

set -e;
cd pudding;
cargo build --release;
cd ..;
set +e;

mkdir -p output

# prefix that is the datetime when the evaluation started
prefix=$(date +%Y%m%d-%H%M)
hostname=$(hostname)

for round in {1..2}; do
  for numUser in $numUsers; do
    for numServer in $numServers; do
      for scenario in $scenarios; do
        # We retry each experiment 5 times before declaring game over
        for retry in {1..10}; do
          outputFilename="output/$prefix-$hostname-$scenario-u$numUser-s$numServer-r$round.log";

          set -o pipefail; # Makes the first failed command fail the pipe
          ./pudding/target/release/pudding -u $numUser -s $numServer --runtime-seconds 600 --scenario $scenario --no-color | tee $outputFilename;

          # If we are successful, we can escape the retry loop
          if [ $? -eq 0 ]; then
              break;
          else
              echo "Failed, will wait 30 seconds and retry";
              sleep 30;
          fi;

          # If we failed at the last retry, better let Ceren/Daniel know
          if [ $retry -eq "10" ]; then
              echo "Failed too many times";
              exit 1;
          fi;
        done;
      done
    done
  done
done
