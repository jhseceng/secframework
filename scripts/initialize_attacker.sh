#!/bin/bash
#
# Example initialize_attacker -v VICTIM
#
while getopts 'v:' OPTION;
do
  case "$OPTION" in
    v)
      VICTIM="$OPTARG"
      ;;

    *) echo "usage: $0 [-v]" >&2
       exit 1 ;;
  esac
done

ATTACKER=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)
echo "$ATTACKER"
apt-get update
apt install docker.io python3-pip build-essential libssl-dev libffi-dev -y --force-yes
pip3 install docker-compose
cd /var/tmp
echo "version: '3'" > docker-compose.yml
echo "services:" >> docker-compose.yml
echo "  attacker:" >> docker-compose.yml
echo "    image: jharris10/attacker" >> docker-compose.yml
echo "    environment:" >> docker-compose.yml
echo "      - ATTACKER=$ATTACKER" >> docker-compose.yml
echo "      - VICTIM=$VICTIM">> docker-compose.yml
echo "    ports:" >> docker-compose.yml
echo "      - \"443:443\"" >> docker-compose.yml
echo "      - \"5000:5000\"" >> docker-compose.yml
docker-compose up -d
