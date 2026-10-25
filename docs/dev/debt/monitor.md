# monitor technical debt

### Functional

- The [monitor](../../../core/monitor/src/Session.cpp) names threads by host thread id and callers by raw address: the telemetry carries no thread names and the monitor does not map addresses to modules. Import names stay NIDs when no NID database is found, and the monitor never downloads one.
- The [verdict](../../../core/monitor/src/Session.cpp) (`Session::Judge`) compares the mean of the last second against fixed shares of the frame (85% for the GPU and the agc driver, 50% for one thread's time in traced imports). It does not tell waits from work inside an import, adds the time of every agc packet worker into the driver figure, and calls everything else game code or untraced work.
- The [window](../../../core/monitor/src/Window.cpp) renders through Vulkan 1.0 with FIFO presentation on the first device ImGui selects; only the text output of `--dump` is checked by a test.
