# Windows Post Exploitation Methods

## Enumerate

### Enumerate ACL Recursively
- PS commandlet to get file/dir ACLs
    - `Get-Acl -Path "C:\" | Format-List`

### Enumerate Installed .NET Version
```
# developer shell
> CSC
> GACUTIL /l ?
> CLRVER

# wmic
> wmic product get description | findstr /C:".NET Framework"

# dir - note, will list out all the versions (except 4.5)
> dir /b /ad /o-n %systemroot%\Microsoft.NET\Framework\v?.*

# powershell
> [environment]::Version
> $PSVersionTable.CLRVersion

# all versions, including .NET 4.5.
> gci 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | gp -name Version,Release -EA 0 |
     where { $_.PSChildName -match '^(?!S)\p{L}'} | select PSChildName, Version, Release
```

[source](https://stackoverflow.com/a/1565454)