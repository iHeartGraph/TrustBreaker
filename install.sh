#!/bin/bash
pip3 install -r requirements.txt
go get github.com/jakejarvis/subtake
wget https://github.com/OWASP/Amass/releases/download/v3.10.5/amass_linux_amd64.zip
mkdir bin
unzip amass_linux_amd64.zip -d amass && rm amass_linux_amd64.zip
cp ./amass/amass_linux_amd64/amass ./bin/amass
wget https://github.com/blechschmidt/massdns/archive/v0.3.zip
unzip v0.3.zip -d massdns && rm v0.3.zip
cd massdns/massdns-0.3
make
cp ./bin/massdns ../../bin/massdns
cd ../../
cp ./bin/* /usr/local/sbin
rm -rf amass && rm -rf massdns