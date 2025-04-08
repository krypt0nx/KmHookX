# KmHookX
A comprehensive hooking mechanism that fixes offsets and places a trampoline at the beginning of a function. It writes to an unused function location, then uses a 16-bit displacement offset to jump into the trampoline. This process is guided by disassembly using the Capstone framework for precise analysis.
# How does it work?
KmHookX overrides the untriggered function (CarCopyRuleViolationDetails) with a simple mov rax and jmp rax shellcode:


![CarCopyRuleViolationDetails trampoline](Images/c1.png)



Then, KmHookX creates an exact copy of a function in an allocated pool, it writes a jmp 16-bit displacement to the untriggered function (CarCopyRuleViolationDetails) (JMP nt!CarCopyRuleViolationDetails) and shifts the whole function down by 5 bytes overriding the INT3s at the end of the function: 

![JMP trampoline](Images/c2.png)


KmHookX takes that allocated pool, and changes all of the offsets to the correct offset ensuring that the flow wont jump into an invalid address.
After that, KmHookX commits the contents in the pool to the target function with the modifications applied. The original function is stored at nt!target_function+0x5 now.

and thats it, you can monitor all of functions no matter if its in ntoskrnl or win32kfull.sys.

# How to use it?
1. Clone this repo using (git clone https://github.com/krypt0nx/KmHookX.git) and move it to any folder in your favor.
2. Open the cloned repo, and open folder cs_driver.
3. Open cs_driver.sln with visual studio.
4. press Build->Rebuild solution
5. When your done, in solution explorer, right click on "capstone_static" and press "unload project".

And your done! Now you can edit the file main.cpp and use the hooking library. If you need, you can integrate your existing project there. 

# Library usage

### 1. KmHookFunction

![KmHookFunction](Images/c3.png)

### Description:
  A function that hooks any function in ntoskrnl.exe.
#### Parameters:

- **TargetFunction**: Function you want to hook/modify. *(MUST BE IN `NTOSKRNL.exe` or `nt!`...)*
- **HookedFunction**: Your function where the hooked function will jump.
- **originalFunction**: Pointer to your function object that will store the original function. **CAN BE NULL** if you wish to not use the original function. Must be `&(PVOID&)yourfunction`.
- **hookstored**: Pointer to your `PVOID` object where you store the original function backup. *(USABLE IF YOU WILL UNHOOK THE FUNCTION LATER. DO NOT USE IT IF THE FUNCTION IS CALLED FREQUENTLY.)*

#### Example: 

Here we are hooking KeBugCheckEx and printing a message whenever its triggered: 

![KmHookFunction example](Images/c6.png)

### 2. KmHookFunctionEx

![KmHookFunctionEx](Images/c5.png)

### Description:
  A function that hooks any function in any module of your choice.
  You have to find your own untriggered function (A function that never hits a breakpoint/never gets called)
  
#### Parameters:

- **TargetFunction**: Function you want to hook/modify. (CAN BE ANY MODULE)
- **HookedFunction**: Your function where the hooked function will jump.
- **originalFunction**: Pointer to your function object that will store the original function. **CAN BE NULL** if you wish to not use the original function. Must be `&(PVOID&)yourfunction`.
- **KmCusJMP**: A function created by `Deploy_Custom_JMP_Pool` *(SEE UTILS USAGE)* to create a custom JMP
- **hookstored**: Pointer to your `PVOID` object where you store the original function backup. *(USABLE IF YOU WILL UNHOOK THE FUNCTION LATER. DO NOT USE IT IF THE FUNCTION IS CALLED FREQUENTLY.)*

#### Example: 

Here we are hooking KeBugCheckEx and printing a message whenever its triggered: 

![KmHookFunctionEx example](Images/c7.png)
      
