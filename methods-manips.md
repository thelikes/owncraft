# Manipulation Methods

## Linux

### Search for email addresses in file

```
$ grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" file.txt
```

### Search for valid IP address
```
$ grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt
```

### Combine user and pass files

```
# input
$ cat users.txt
admin
root
adm
$ cat pass.txt
admin
toor
12345
# combine
$ paste -d" " users.txt pass.txt
admin:admin
root:toor
adm:12345
```

### Combine creds file

```
# input
$ cat creds.txt
admin
admin
root
toor
adm
12345
# combine
$ paste - - -d: < creds.txt
admin:admin
root:toor
adm:12345
```

### Prince (undocumented) flags

[Found here](https://github.com/openwall/john/issues/1428)

```
PRINCE mode options:
--prince-loopback[=FILE]  fetch words from a .pot file
--prince-elem-cnt-min=N   minimum number of elements per chain (1)
--prince-elem-cnt-max=N   maximum number of elements per chain (8)
--prince-skip=N           initial skip
--prince-limit=N          limit number of candidates generated
--prince-wl-dist-len      calculate length distribution from wordlist
                          instead of using built-in table
--prince-wl-max=N         load only N words from input wordlist
--prince-case-permute     permute case of first letter
--prince-mmap             memory-map infile (not available when permuting case)
--prince-keyspace         just show total keyspace that would be produced
                          (disregarding skip and limit)
```

### Print NMAP Top Ports

To print the top 1,000 ports

```
nmap --top-ports 1000 -v -oG -
```