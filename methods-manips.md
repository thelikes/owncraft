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