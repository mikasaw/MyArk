# Build matrix (Mode A static verification)

| profile     | header                    | size (bytes) | warnings | errors |
|-------------|---------------------------|--------------|----------|--------|
| full        | myark_full.h              | 150016       | 0        | 0      |
| core        | myark_core.h              | 66048        | 0        | 0      |
| mini        | myark_mini.h              | 31232        | 0        | 0      |
| process_only| myark_process_only.h      | 43008        | 0        | 0      |
| safety_audit| myark_safety_audit.h      | 49152        | 0        | 0      |

All five profiles produced a real `MyArkCore.sys` file and reported
`BUILD SUCCEEDED` from MSBuild. Default build configuration: Debug / x64.

Run:

```
scripts\make.bat full Debug
scripts\make.bat core Debug
scripts\make.bat mini Debug
scripts\make.bat process_only Debug
scripts\make.bat safety_audit Debug
```

The hyphen form (`process_only` etc.) and the underscore form
(`process-only`) are interchangeable — `make.bat` normalises before
looking up `config/myark_<profile>.h`.

The sizes above are diagnostic — they show that the gating actually
removes unused module object code (a `full` build is ~5x the size of
a `mini` build).

pytest state at S10.1: 575 passed, 5 skipped, 2 warnings (from
pypinyin's bundled codecs.open shim, not the MyArk codebase).
