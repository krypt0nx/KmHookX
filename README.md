# KmHookX
A comprehensive hooking mechanism that fixes offsets and places a trampoline at the beginning of a function. It writes to an unused function location, then uses a 16-bit displacement offset to jump into the trampoline. This process is guided by disassembly using the Capstone framework for precise analysis.
# How does it work?
KmHookX overrides the untriggered function (CarCopyRuleViolationDetails) with a simple mov rax and jmp rax shellcode:
![CarCopyRuleViolationDetails trampoline]("Images/c1.png")


Then, KmHookX creates an exact copy of a function in an allocated pool, it writes a jmp 16-bit displacement to the untriggered function (CarCopyRuleViolationDetails).
