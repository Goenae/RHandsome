#!/bin/bash
# ONLY launch this script in your folder c2 (/var/www/c2)
# Have your "main.py" file created and make your own flask script for your C2
# It's better to have a domain name

# Define your domain name and port 
echo "Give us your domain name or server IP: "
read domain

echo "Define the port of your C2: "
read port

# Create wsgi.py file 
echo "from myproject import app

if __name__ == "__main__":\n
    app.run()" > test.py

# Create configuration file
echo "[uwsgi]
module = wsgi:app

master = true
processes = 5

socket = /var/www/c2/c2.sock
chmod-socket = 660
vacuum = true

die-on-term = true" > config.ini

# Create service for the C2
echo "[Unit]
Description=uWSGI instance to serve c2
After=network.target

[Service]
User=$USER
Group=www-data
WorkingDirectory=/var/www/c2
Environment="PATH=/var/www/c2/bin"
ExecStart=/var/www/c2/bin/uwsgi --ini /var/www/c2/config.ini

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/c2.service

# Start service
sudo systemctl start c2

# Configure Ngnix proxy Requests
echo "server {
    listen $port;
    server_name $domain www.$domain;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:///var/www/c2/c2.sock;
    }
}" > /etc/nginx/sites-available/c2

# Link to "sites-enabled"
sudo ln -s /etc/nginx/sites-available/c2 /etc/nginx/sites-enabled

# Check errors
sudo nginx -t

# Restart ngninx to apply changes
sudo systemctl restart nginx

# Allow the request on the C2 port
sudo ufw delete allow $port

# Allow nginx
sudo ufw allow 'Nginx Full'

# If you apply any modifications on your C2, restart nginx & C2 service
# sudo systemctl restart c2
# sudo systemctl restart nginx