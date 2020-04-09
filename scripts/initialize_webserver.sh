#!/bin/bash
apt-get update
apt-get update
apt install docker.io python3-pip build-essential libssl-dev libffi-dev -y --force-yes
cd /home/ubuntu
sudo apt install python-pip -y --force-yes
sudo pip install awscli
sudo aws s3 ls
sudo aws s3 cp s3://falcon-bootstrap/sensor/falcon-sensor_5.27.0-9104_amd64.deb /home/ubuntu
sudo dpkg -i falcon-sensor_5.27.0-9104_amd64.deb
sudo apt install -f -y
sudo dpkg -i falcon-sensor_5.27.0-9104_amd64.deb
sudo /opt/CrowdStrike/falconctl -s --cid=797BCD0BF5AE4F39A2B770FF52517125-08
sudo systemctl start falcon-sensor
pip3 install docker-compose
cd /var/tmp
echo "version: '3'" > docker-compose.yml
echo "services:" >> docker-compose.yml
echo "  jenkins:" >> docker-compose.yml
echo "    image: franklinjff/jenkins:version1" >> docker-compose.yml
echo "    environment:" >> docker-compose.yml
echo "      JAVA_OPTS: \"-Djava.awt.headless=true\"" >> docker-compose.yml
echo "      JAVA_OPTS: \"-Djenkins.install.runSetupWizard=false\"" >> docker-compose.yml
echo "    ports:" >> docker-compose.yml
echo "      - \"50000:50000\"" >> docker-compose.yml
echo "      - \"8080:8080\"" >> docker-compose.yml
docker-compose up -d
docker run -it busybox
docker run -it busybox
docker run -it busybox
docker run -it busybox
docker run -it busybox
docker run -it busybox
docker run -it busybox
