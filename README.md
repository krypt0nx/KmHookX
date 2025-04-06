# KmHookX
A comprehensive hooking mechanism that fixes offsets and places a trampoline at the beginning of a function. It writes to an unused function location, then uses a 16-bit displacement offset to jump into the trampoline. This process is guided by disassembly using the Capstone framework for precise analysis.
