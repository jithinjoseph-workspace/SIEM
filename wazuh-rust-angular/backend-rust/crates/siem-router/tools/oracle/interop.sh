#!/bin/bash
# Router interop test (WSL): builds router_tool on Wazuh's real routerFacade.cpp
# and runs every combination of C++ / Rust broker, provider and subscriber.
# usage: interop.sh <wazuh src> <rust router_tool binary>
set -u
W=$1
RUST=$2
T=$(cd "$(dirname "$0")" && pwd)
D=~/router_oracle
DEPS=${WAZUH_DEPS:-$HOME/wazuh_deps}
mkdir -p $D/inc/external/nlohmann
cp $DEPS/nlohmann/nlohmann/json.hpp $D/inc/external/nlohmann/
cp $T/router_tool.cpp $D/
cd $D
if [ ! -x cpp_tool ] || [ router_tool.cpp -nt cpp_tool ]; then
  g++ -std=c++17 -O1 -w -DPROMISE_TYPE=PromiseType::NORMAL -I$W/shared_modules/router/src -I$W/shared_modules/router/include -I$W/shared_modules/utils \
    -I$W/shared_modules/common -I$W/headers -I$D/inc -I$W \
    -o cpp_tool router_tool.cpp $W/shared_modules/router/src/routerFacade.cpp -lpthread || exit 1
fi
CPP=$D/cpp_tool
run() { # broker provider subscriber
  local B=$1 P=$2 S=$3
  rm -rf home && mkdir -p home && cd home
  $B broker 6 > broker.out &
  sleep 0.5
  $S subscribe deltas-test sub1 5 > sub.out &
  sleep 1.5
  $P provide deltas-test 1 "hello" "world" "{\"a\":1}" > prov.out
  wait
  echo "B=$(basename $B) P=$(basename $P) S=$(basename $S): prov[$(tr '\n' ' ' < prov.out)] sub[$(tr '\n' ' ' < sub.out)]"
  cd ..
}
for B in $CPP $RUST; do for P in $CPP $RUST; do for S in $CPP $RUST; do run $B $P $S; done; done; done
