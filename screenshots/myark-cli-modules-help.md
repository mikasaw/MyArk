# Per-module --help reference

This file consolidates the `--help` output for every myark-cli sub-module.
Captured via `uv run myark-cli <module> --help` on the in-tree code at
S10.1 (commit `622bd4d`).

---

## myark-cli process --help

```
usage: myark-cli process [-h]
                         {enum,detail,threads,token,terminate,suspend,resume,inject,dump} ...

positional arguments:
  {enum,detail,threads,token,terminate,suspend,resume,inject,dump}
    enum                enumerate processes (R3 PSAPI preferred)
    detail              fetch detailed info for a single PID
    threads             list threads in a process
    token               inspect the primary token of a process
    terminate           terminate a process (R3 preferred + R0 fallback)
    suspend             suspend a process (R3 only)
    resume              resume a process (R3 only)
    inject              inject a DLL into a process (R3 preferred + R0 fallback)
    dump                write a process minidump to a file

options:
  -h, --help            show this help message and exit
```

---

## myark-cli memory --help

```
usage: myark-cli memory [-h] {read,write,query,scan,translate} ...

positional arguments:
  {read,write,query,scan,translate}
    read                read process memory (R3)
    write               write process memory (R3)
    query               query memory region info (R3)
    scan                pattern scan (R0)
    translate           virtual to physical address (R0 only)

options:
  -h, --help            show this help message and exit
```

---

## myark-cli registry --help

```
usage: myark-cli registry [-h] {list,get,set,delete,watch} ...

positional arguments:
  {list,get,set,delete,watch}
    list                list values under a registry key
    get                 read a single registry value
    set                 create or update a registry value
    delete              delete a registry value or key
    watch               start a watch session for a key

options:
  -h, --help            show this help message and exit
```

---

## myark-cli thread --help

```
usage: myark-cli thread [-h] {enum,detail,suspend,resume} ...

positional arguments:
  {enum,detail,suspend,resume}
    enum                enumerate threads (R3 preferred)
    detail              fetch detailed info for a single TID
    suspend             suspend a thread
    resume              resume a thread

options:
  -h, --help            show this help message and exit
```

---

## myark-cli file --help

```
usage: myark-cli file [-h] {info,read,write,sd} ...

positional arguments:
  {info,read,write,sd}
    info                query file metadata + size
    read                read raw file bytes
    write               write raw file bytes
    sd                  query the security descriptor (SDDL)

options:
  -h, --help            show this help message and exit
```

---

## myark-cli module --help

```
usage: myark-cli module [-h] {enum,info} ...

positional arguments:
  {enum,info}
    enum                enumerate loaded modules in a process
    info                fetch detailed info for a single module

options:
  -h, --help            show this help message and exit
```

---

## myark-cli network --help

```
usage: myark-cli network [-h] {tcp-list,udp-list,connections} ...

positional arguments:
  {tcp-list,udp-list,connections}
    tcp-list            list active TCP connections (pure R3 IP Helper)
    udp-list            list active UDP endpoints (pure R3 IP Helper)
    connections         unified TCP+UDP listing

options:
  -h, --help            show this help message and exit
```

---

## myark-cli hello --help

```
usage: myark-cli hello [-h] {ping} ...

positional arguments:
  {ping}
    ping                send a hello ping to the driver

options:
  -h, --help            show this help message and exit
```

---

## myark-cli driver --help

(see [myark-cli-driver.txt](myark-cli-driver.txt))

---

## myark-cli callback --help

```
usage: myark-cli callback [-h] {enum,info} ...

positional arguments:
  {enum,info}
    enum                enumerate callback entries (Ps/Cm/Ob/Image/Dbg)
    info                show callback entry detail

options:
  -h, --help            show this help message and exit
```

---

## myark-cli capability --help

```
usage: myark-cli capability [-h] {list,info} ...

positional arguments:
  {list,info}
    list                list driver IOCTL capabilities
    info                show capability detail for a single IOCTL

options:
  -h, --help            show this help message and exit
```

---

## myark-cli dyndata --help

```
usage: myark-cli dyndata [-h] {system-info,handles,processes} ...

positional arguments:
  {system-info,handles,processes}
    system-info         system summary from kernel (R0)
    handles             process handle table (R0)
    processes           lightweight kernel process listing (R0)

options:
  -h, --help            show this help message and exit
```

---

## myark-cli preflight --help

```
usage: myark-cli preflight [-h] {check,list} ...

positional arguments:
  {check,list}
    check               run preflight environment health check
    list                list preflight checks and their outcomes

options:
  -h, --help            show this help message and exit
```

---

## myark-cli safety --help

```
usage: myark-cli safety [-h] {evaluate,gate} ...

positional arguments:
  {evaluate,gate}
    evaluate            run the 6-step safety evaluator for a target
    gate                check whether an action passes the safety gate

options:
  -h, --help            show this help message and exit
```

---

## myark-cli security_audit --help

```
usage: myark-cli security_audit [-h]
                                {defender,secureboot,trustedboot} ...

positional arguments:
  {defender,secureboot,trustedboot}
    defender            query Microsoft Defender status
    secureboot          query Secure Boot state
    trustedboot         query Trusted Boot state (Win11 24H2+)

options:
  -h, --help            show this help message and exit
```

---

## myark-cli trust --help

```
usage: myark-cli trust [-h] {verify,catalog} ...

positional arguments:
  {verify,catalog}
    verify              verify Authenticode signature on a PE file
    catalog             verify catalog-signed PE file

options:
  -h, --help            show this help message and exit
```

---

## myark-cli kernel_ext --help

```
usage: myark-cli kernel_ext [-h] {info-classes,queries} ...

positional arguments:
  {info-classes,queries}
    info-classes        list supported Win11 25H2 info classes
    queries             issue a kernel_ext query

options:
  -h, --help            show this help message and exit
```

---

## myark-cli hwid --help

```
usage: myark-cli hwid [-h] {enumerate-mj,info} ...

positional arguments:
  {enumerate-mj,info}
    enumerate-mj        enumerate MajorFunctions across all drivers
    info                show hardware ID info for a device

options:
  -h, --help            show this help message and exit
```

---

## myark-cli alpc --help

```
usage: myark-cli alpc [-h] {enum-ports} ...

positional arguments:
  {enum-ports}
    enum-ports          enumerate ALPC ports

options:
  -h, --help            show this help message and exit
```

---

## myark-cli wsl --help

```
usage: myark-cli wsl [-h] {enum-silos} ...

positional arguments:
  {enum-silos}
    enum-silos          enumerate WSL silos

options:
  -h, --help            show this help message and exit
```

---

## myark-cli win32k --help

```
usage: myark-cli win32k [-h] {enum-threads,enum-hooks} ...

positional arguments:
  {enum-threads,enum-hooks}
    enum-threads        enumerate GUI threads
    enum-hooks          enumerate GUI hooks

options:
  -h, --help            show this help message and exit
```

---

## myark-cli authentication --help

```
usage: myark-cli authentication [-h] {verify} ...

positional arguments:
  {verify}
    verify              verify authenticode (R3 WinVerifyTrust primary)

options:
  -h, --help            show this help message and exit
```

---

## myark-cli bugcheck --help

```
usage: myark-cli bugcheck [-h] {last,framebuffer} ...

positional arguments:
  {last,framebuffer}
    last                show last BugCheck code + parameters
    framebuffer         render framebuffer dump (R3-side)

options:
  -h, --help            show this help message and exit
```

---

## myark-cli wfp --help

```
usage: myark-cli wfp [-h] {enum-callouts} ...

positional arguments:
  {enum-callouts}
    enum-callouts       enumerate WFP callouts

options:
  -h, --help            show this help message and exit
```

---

## myark-cli mutation --help

```
usage: myark-cli mutation [-h] {eprocess-token,dk} ...

positional arguments:
  {eprocess-token,dk}
    eprocess-token      EPROCESS.Token field inspection
    dk                  DKOM mutation detection

options:
  -h, --help            show this help message and exit
```

---

## myark-cli redirect --help

```
usage: myark-cli redirect [-h] {cmcallback,iocalldriver} ...

positional arguments:
  {cmcallback,iocalldriver}
    cmcallback          CmCallback redirect inspection
    iocalldriver        IoCallDriver redirect inspection

options:
  -h, --help            show this help message and exit
```

---

## myark-cli actions --help

```
usage: myark-cli actions [-h]
                         {kill,terminate,inject,dump,set-token,hide-process,protect-process} ...

positional arguments:
  {kill,terminate,inject,dump,set-token,hide-process,protect-process}
    kill                force kill a process (R3 preferred)
    terminate           graceful terminate (R3 preferred)
    inject              inject a DLL (R3 preferred)
    dump                write a process minidump (R3 preferred)
    set-token           set an EPROCESS Token (R0 only)
    hide-process        hide a process via DKOM (R0 only)
    protect-process     mark a process as protected (R0 only)

options:
  -h, --help            show this help message and exit
```
