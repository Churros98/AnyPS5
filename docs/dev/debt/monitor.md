# monitor technical debt

### Functional

- The [monitor](../../../core/monitor/src/Session.cpp) names threads by host thread id and callers by raw address: the telemetry carries no thread names and the monitor does not map addresses to modules. Import names stay NIDs when no NID database is found, and the monitor never downloads one.
- The [verdict](../../../core/monitor/src/Session.cpp) (`Session::Judge`) compares the mean of the last second against fixed shares of the frame (85% for the GPU and the agc driver, 50% for one thread's time in traced imports). It does not tell waits from work inside an import, adds the time of every agc packet worker into the driver figure, and calls everything else game code or untraced work.
- The [MCP server](../../../core/monitor/src/Mcp.cpp) implements the tools part of the protocol over standard input and output only: no resources, prompts, progress notifications or cancellation, so a `sample` request blocks the server for its whole length. Its [JSON parser](../../../core/monitor/src/Json.cpp) keeps numbers as doubles, so integers above 2^53 lose precision, and accepts leading zeros.
- [Symbols](../../../core/monitor/src/Symbols.cpp) are read from PE images only: on Linux addresses keep a module and offset without a function, and a converted executable has no symbols at all, so title code is named only by offset. The nearest preceding COFF or export symbol is taken without checking the function's size.
- [Memory reads](../../../core/monitor/src/Memory.cpp) go through `ReadProcessMemory` or `process_vm_readv`, which a Linux `ptrace_scope` above 0 refuses; a read stops at the first unreadable page, and a search reads each region in 1 MiB parts while the title keeps running, so it can miss or report a value that changes during the scan.
- [Watched calls](../../../core/monitor/src/Mcp.cpp) carry the six integer argument registers only: floating-point, vector and stack arguments are not recorded, and the return value is `rax`.
- The [window](../../../core/monitor/src/Window.cpp) renders through Vulkan 1.0 with FIFO presentation on the first device ImGui selects; only the text output of `--dump` is checked by a test.
