#!/bin/sh

# standard - 1 sec block time, 10kk gas limit
# fast - 0 sec block time, 10kk gas limit
# mainnet - 15 sec block time, 10kk gas limit

if [ ! -z $PLUGIN_CONFIG ]; then
  CONFIG=$PLUGIN_CONFIG
else
  CONFIG=${1:-standard}
fi


echo config $CONFIG

case $CONFIG in
standard|fast|mainnet)
  ;;
*)
  echo "supported configurations: standard, fast, mainnet";
  exit 1
  ;;
esac

cd /var/lib/geth/data

DEV="$CONFIG"-dev.json

#if [ ! -f ./keystore ]; then 
#    echo initializing dev network
#    cp /seed/$DEV ./
#    cp /seed/password.sec ./
#    geth --datadir . init $DEV
#    cp /seed/keystore/UTC--2019-04-06T21-13-27.692266000Z--8a91dc2d28b689474298d91899f0c1baf62cb85b ./keystore/
#fi
geth --datadir . init $DEV
#geth --dev --http --http.addr "0.0.0.0" --nat "any" --http.api eth,web3,personal,net --http.corsdomain "http://remix.ethereum.org"
geth --dev \
    --datadir "." \
    --http --http.addr "0.0.0.0" --nat "any" \
    --http.api eth,web3,personal,net --http.corsdomain "*" \
    --unlock 0 --password "./password.sec" --allow-insecure-unlock \
    --ws --ws.port 8546 \
    --gcmode archive \
    --ws.origins "*" --http.vhosts=* \
    --miner.gastarget=10000000 --miner.gaslimit=11000000

#geth --networkid 9 --mine --miner.threads 1 \
#    --datadir "." \
#    --nodiscover \
#    --http --http.addr "0.0.0.0" \
#    --http.corsdomain "*" --nat "any" --http.api eth,web3,personal,net \
#    --unlock 0 --password "./password.sec" --allow-insecure-unlock \
#    --ws --ws.port 8546 \
#    --gcmode archive \
#    --ws.origins "*" --http.vhosts=* \
#    --miner.gastarget=10000000 --miner.gaslimit=11000000
