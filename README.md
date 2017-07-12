# Fortinet Interruption Terminator (F.IT)
---  

```
@version: v0.2.0
@email:  lnquy.it@gmail.com / lnquy@tma.com.vn
```
F.IT is a tool to help anyone working under a FortiGuard proxy which requires you to authenticate to have access to the Internet.  
F.IT runs in background and automate the authentication, session keep alive process.  
Currently supports for Linux and Windows.

## Features
- Detect Fortinet session ID.
- Automate authentication and keepalive processes.
- Encrypt plaintext password.
- Terminate old session and retrieve new one at specific time of day.
- Auto start when computer booting up.

## Quick start
 - Download the released binary from [here](#).
 - Edit `fit.conf` configuration file.
 ```
   is_https:            Determine Fortinet server is serving HTTPS or HTTP requests (default true)
   *fortinet_address:   The <IP_address:Port> to the Fortinet server
   *username:           Your username
   *password:           Your plaintext password (the password will be encrypted automatically later)
   max_retries:         Maximum times F.IT should retry before it terminates itself (default 10)
   refresh_time:        Interval time in second F.IT will go to refresh your session (default 10800 - 3 hours
   auto_start:          Allow F.IT to started up with your computer (default false. Not supported for Linux yet)
   session_id:          If you starts F.IT when you're having an active Fortinet session, please paste that session id here. Otherwise, just let it empty by default
   
   * = required
 ```
 - Windows: Double click on `fit.exe` file to run.  
   *F.IT automatically runs in background so you won't see anything. You can check task manager for `fit.exe` process.*
 - Linux: 
 ```
 $ cd /path/to/downloaded/binary
 $ chmod +x fit
 $ ./fit &
 ```
 *Note: You can pass configuration via console arguments instead of edit `fit.conf` file. See `./fit -- help` for more details.*  
 ```
 $ ./fit -d=true -https=true -ip=192.168.10.1:1003 -username=myaccount -password=mypassword -retries=10 -refresh=10800 -start=true -session=0f060b080b60789f &
 ```  
 
## Build from source
- Install Go SDK >= 1.7.
- Set `$GOROOT`, `$GOPATH`.
```
$ go get github.com/lnquy/fit
$ cd $GOPATH/src/github.com/lnquy/fit
$ go build
```  

## TODOs
1. Support auto startup for Linux.
2. Server GUI app. [?]
3. Add option to read specific configuration file and more customized configurations.

## License
Released under the [MIT License](LICENSE.txt).