# LDAP Auxiliary Methods

## User Enumeration

```
# search the base tree
ldapsearch -h $ip -p 389 -x -s base
# search users using the 'defaultnamingcontext'
ldapsearch -h $ip -p 389 -x -b "dc=*,dc=*,dc=*"
```
