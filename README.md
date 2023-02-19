# NtQueueApcThreadEx NTDLL Gadget Injection
## Introduction
This novel way of using `NtQueueApcThreadEx` by abusing the `ApcRoutine` and `SystemArgument[0-3]` parameters by passing a random `pop r32; ret` gadget can be used for stealthy code injection. Within this PoC, the gadget in this case is picked randomly from `ntdll.dll`'s memory region which matches a specific pattern. This means the gadget _returns into_ the shellcode.

1. Allocate shellcode in target process. For best results, this should be used with the [shellcode-plain-sight](https://github.com/LloydLabs/shellcode-plain-sight) project.
2. Find a random gadget within `IMAGE_SCN_CNT_CODE` and `IMAGE_SCN_MEM_EXECUTE` within `ntdll.dll` in memory.
3. Setup the `NtQueueApcThreadEx` call, `ApcRoutine` = gadget address chosen randomly, `SystemArgument`` = pointer to shellcode
4. The `NtQueueApcThreadEx` will force the IP to the gadget `ntdll.dll!<random pop r32; ret>`, and return into `SystemArgument1`
5. ✨tada✨

There are hundreds gadgets which can be used inside `ntdll.dll` (from my build, at least) - making this tricky to detect. With the nature of the call, `SystemArgument1` is simply

Upon inspecting the call, unlike traditional APC injection, `ApcRoutine` will simply point to a legitimate address inside of `ntdll.dll`.

## Visualization

![example](https://i.imgur.com/QJ43HuW.jpeg)

## Possible Detection Vectors
This is likely a bit tricky to detect. Upon inspecting calls to `NtQueueApcThreadEx`, check if any of the arguments point towards executable memory. Another possible detection avenue is to check if `ApcRoutine` points towards an address inside `ntdll` - however this is likely to trigger a lot of false positives.

This technique was originally detailed in Avast's Raspberry Robin writeup [here](https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/).