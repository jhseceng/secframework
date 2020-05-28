#!/bin/bash
#
# Example initialize_fig -v VICTIM
#
while getopts 'r:' OPTION;
do
  case "$OPTION" in
    r)
      REGION="$OPTARG"
      ;;

    *) echo "usage: $0 [-r]" >&2
       exit 1 ;;
  esac
done

FIG=$(curl http://169.254.169.254/latest/meta-data/public-ipv4)
echo "$FIG"
sudo yum update -y
sudo yum install -y python3-pip python3 python3-setuptools build-essential libssl-dev libffi-dev git
sudo amazon-linux-extras install docker
sudo service docker start
sudo usermod -a -G docker ec2-user
sudo curl -L https://github.com/docker/compose/releases/download/1.22.0/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
cd /var/tmp
echo "version: '3'" > docker-compose.yml
echo "services:" >> docker-compose.yml
echo "  fig:" >> docker-compose.yml
echo "    image: jharris10/securityhubconnector:dev" >> docker-compose.yml
echo "    deploy:">> docker-compose.yml
echo "      restart_policy:" >> docker-compose.yml
echo "        condition: unless-stopped" >> docker-compose.yml
echo "    environment:" >> docker-compose.yml
echo "      - REGION=$REGION" >> docker-compose.yml
echo "    depends_on:" >> docker-compose.yml
echo "      - redis" >> docker-compose.yml
echo "  redis:" >> docker-compose.yml
echo "    image: redis" >> docker-compose.yml

docker-compose up -d
