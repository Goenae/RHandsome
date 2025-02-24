# Install all the requirements
sudo apt update -y
sudo apt install python3 python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools nginx ufw -y
pip install wheel uwsgi flask werkzeug datetime flask-sqlalchemy flask-wtf flask-login