#! /bin/bash

echo "=================================="
echo "Welcome to this setup. This will install local virtual env."
if [ -d ".env" ];
then
	echo ".env folder exists. Installing using pip"
else
	echo "creating .evn and install using pip"
	python3 -m venv .env
fi

. .env/bin/activate

pip install --upgrade pip
pip install flask
pip install flask-sqlalchemy
pip install flask-restful
pip install flask-login
pip install email-validator
pip install flask-wtf
pip install matplotlib

echo "INSTALLED LIBRARIES"
deactivate
