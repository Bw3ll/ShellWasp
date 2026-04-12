# ShellWasp 2.1


ShellWasp is a the original tool to faciliate creating shellcode utilizing syscalls. ShellWasp helps build templates for 32-bit WoW64 shellcode that uses Windows syscalls while avoiding the portability problem that comes with hardcoded SSNs across OS builds.

ShellWasp was first released at DEF CON 30 in August 2022. Since then it has expanded considerably. Version 2.0 added alternative ways to discover OSBuild, including User_Shared_Data and PEB via r12, along with three new ways to invoke the syscall through WoW64: one for Windows 7 and two for Windows 10/11. With ShellWasp 2.1, we have added new capabilities to get sample, illustrative values for function parameters - both from a pre-computed, offline mode and generated on the fly from AI (if an OpenAI key is provided). There are plans for additional new features in the coming months. There will be other maintenance updates coming soon as well. 

## Presentations and Background
The primary resource on using Windows syscalls in shellcode can be found in the most recent, definitive conference presentation, from HITB Amsterdam 2023 page for further details, including full-length, hour long video, detailed slides, to learn more about this project: https://conference.hitb.org/hitbsecconf2023ams/session/windows-syscalls-in-shellcode-advanced-techniques-for-malicious-functionality/
Slides are available for download at HITB. This project has evolved tremendously since its initial debut at [DEFCON 30](https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Tarek%20Abdelmotaleb%20%20%20Dr.%20Bramwell%20Brizendine%20-%20Weaponizing%20Windows%20Syscalls%20as%20Modern%2032-bit%20Shellcode.pdf). 
ShellWasp was also presented as part of a Black Hat MEA briefing in 2022, and slides and white paper are available within the GitHub repository. Both the Black Hat and DEF CON presentations were superceded by the Hack in the Box Amsterdam 2023 presetnation, which contains significanlty more new content and several novel features for ShellWasp

## What ShellWasp Does
 ShellWasp is a way to help perform syscalls in WoW64 shellcode, and the latest version features multiple, novel methods of invoking the syscall in a WoW64 environment, as detailed in the HITB Amsterstam 2023 talk. 

 ShellWasp automates building templates of syscall shellcode. The template is intended to be just that - a template. The user still needs to determine what parameter values to use and how to build any required structures. The goal is to make handcrafted syscall shellcode more manageable, especially when multiple syscalls are involved. Nearly all user-mode syscalls supported, including all the ones I could find function prototypes for. ShellWasp also solves the syscall portability problem for syscalls. It identifies the OS build, and ShellWasp creates a syscall arrray in response to user input, allowing the current syscall values (SSNs) to be found at runtime, rather than having to be hardcoded, which can limit how you can use them across OS builds. ShellWasp takes care of managing the syscall array, so if a syscall is used multiple times, there will only be one entry in the syscall array. Thus, ShellWasp will allows syscall values (SSNs) to be obtained dynamically.  If you are building complex syscall shellcode with multiple syscalls being used (not for the faint-hearted), and you want to make sure there is no common way of invoking it, such as fs:0xc0, then these new additions may be of interest. Though for simplicity's sake, I recommend beginning with the "simpler" way of invoking it, via fs:0xc0. 

The shellcode size created by ShellWasp is relatively small in size. Users can select the OS builds to support, and it is recommend to use perhaps just some of the most recent ones from Windows 7/10/11, rather than every possible one. This can help keep size more manageable. Additionall, the way in which syscalls are called differs from Windows 7 and Windows 10/11. ShellWasp will automatically take care of that based on the selections the user makes. We have created syscall shellcode that works across all three OS, using our technique.

To achieve a more compact shellcode size, ShellWasp utilizes precomputed syscall tables in JSON format, as opposed to dynamic SSN resolution techniques, which may lengthen the shellcode. This allows us to keep the shellcode size minimal. 

ShellWasp supports nearly all user-mode syscalls for which I could find function prototypes. It identifies the OS build and creates a syscall array based on user input, allowing the current SSNs to be found at runtime rather than hardcoded. If a syscall is used multiple times, ShellWasp manages that for you so there is only one entry in the syscall array.

## Scope
ShellWasp is geared toward 32-bit WoW64 shellcode. It is not meant as a replacement for SysWhispers2, FreshyCalls, or related work. This is a different direction for utilizing Windows syscalls and is focused on shellcode specifically. The point is not just how to recover the SSN. The point is helping facilitate syscall shellcode in a compact and reliable form.

## Why ShellWasp May Be Useful
If you are building more complex syscall shellcode and do not want to rely only on a common mechanism such as fs:0xc0, the novel WoW64 invocation methods provided by ShellWasp may be useful. That said, for simplicity's sake, I still recommend beginning with the simpler approach via fs:0xc0, before moving onto more advanced techniques. ShellWasp is most useful when you want portability across supported Windows releases, compact output, and a cleaner way to manage repeated syscall use in one piece of shellcode.

ShellWasp 2.0 includes some  alternative ways to discover the OSBuild. ShellWasp 2.0 additionally provides three new ways to invoke the syscall from WoW64, all without syscall, int 0x2e or fs:0xc0 - two for Windows 10/11 and one for Windows 7. These two new methods have not been seen before (see below images).

ShellWasp is not an alternative to SysWhispers2/3 or the work of ElephantSe4l, with Freshycalls, etc. This is a different direction for utilizing Windows syscalls. The method of determing OS build or the SSN is not important. (ShellWasp provides a few ways to determine this.) ShellWasp is about helping faciliate syscall shellcode in a compact and reliable form.

## Optional 2.1 Parameter Support (New)

ShellWasp 2.1 adds the ability to generate sample, illustrative parameter values. These can come either from a precomputed offline mode or, if an OpenAI key is provided, through AI-assisted generation. These are intended as learning aids and starting points, not as finished parameter choices. ShellWasp does not build end-to-end shellcode, but helps you start the process. This can be rather useful, as it might expose some necessary values that might not be easily found.

## Using ShellWasp
The assembly generated by ShellWasp is relatively compact. Users can select the OS builds to support and the syscalls to include. It is usually not necessary to target every supported build. In many cases, selecting only the releases you care about will help keep the resulting shellcode size more manageable. Be realistic - if this is being done for offensive security purposes, is it really necessary to target every os build? It is certainly an option if payload size is not a consideration. The Assembly generated by ShellWasp is intended to be more compact in size. Additionally, as many people have automatic Windows update, it may be desirable to select only more recent OS builds, rather than every possible one, and this helps reduce size as well. Users can easily and quickly rearrange syscalls in shellcode. 

ShellWasp takes care of much of the bookkeeping, but you still need to supply the parameter values and build out any required structures. For hints and tips, use the pre-computed illustrative samples or generate something on the fly with an AI key. Though keep in mind - these are just starting points, which may or may not be appropriate for your project. Working to build syscall shellcode is an iterative process requiring trial and error.

A reminder: ShellWasp only supports Windows 7/10/11 at the moment, as a desing choice. It is easy to select desired Windows releases via config file or UI. Changes can also be saved to the to config.

## Quick Start

Download the repository and run it from the command line: `py shellWasp.py`

You can also use `python shellWasp.py` if that is how Python is configured on your system.

Desired settings for selected OS builds and Windows syscalls can be added to the config file or changed in the UI. Those settings can also be saved back to the config.

## Installation

A setup file is provided to help ensure the needed libraries are installed:

`py setup.py install`

You may substitute `python` for `py` as needed.

This installs the required libraries, including `colorama` and `keystone-engine`. Keystone is used to assemble the generated code so the assembly can be validated. ShellWasp is still intended to produce a template whose parameters need to be customized, so the generated bytes are not the main focus of the tool.

If you do not want to use `setup.py`, you can install the dependencies manually:

`pip install keystone-engine`

`pip install colorama`

![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/shellwasp1.png?raw=true)

![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/shellwasp3.png?raw=true)

![image](https://user-images.githubusercontent.com/49998815/201258739-bc8e4f11-d737-4a1f-a8e5-7f827f701717.png)
Note: You select the OS builds to target--it is not necessary to target every single build--and you select the syscalls to use. The above is just a random illustration. ShellWasp takes care of a lot of the details, but you still need to build out the parameters and required structures.



![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/osbuild3.png?raw=true)

![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/fsyscall.png.png?raw=true)

![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/osbuild2.png?raw=true)
![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/multWays.png?raw=true)
![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/alt_invoke.png?raw=true)
![image](https://github.com/Bw3ll/ShellWasp/blob/main/images/altinvoke2.png?raw=true)

## Repository Layout

* `shellWasp.py` - small launcher for the tool
* `start/shellWasp.py` - main implementation
* `start/config.cfg` - configuration for OS builds and syscall choices
* `start/ui.py` - UI support
* `start/WinSysCalls.json` and related files - syscall tables and related data
* `Samples/` - example files
* `BH Slides-White paper/` - slides and white paper material


## Updates
* March 2026 update: ShellWasp 2.1 has a major usability upgrade to produce clearer and more realistic parameter generation. It can now produce richer illustrative syscall parameters, with optional structure-aware examples and field-level structure expansions where helpful. These are intended as learning aids. I also added chunked processing and automatic aggregation for larger batches of syscalls while preserving call order and supporting repeated uses of the same export in a single run. To make longer sessions easier to manage, ShellWasp now supports a continuously updated working results file, resume capability, and both timestamped JSON snapshots and cleaned-up text exports for review and reuse. More changes are coming.
* April 19, 2023 - ShellWasp 2.0 is released with masssive changes, including alternative ways to identify to the OSBuild, and three previously undocumented ways to invoke the syscall via WoW64 (one for Windows 7 and two for Windows 10/11).
* On Nov. 1, 2022, support was added for Windows 10 22H2 and Windows 11 22H2. These are the newest Windows releases. Note: we do not support Insider preview builds nor Server. 
* On Nov. 1, 2022, the mechanism by which the pointer to the syscall array is preserved has been changed. In testing shellcode with chains of several Windows syscalls, some stability issues were noted with values on the stack. In order to avoid those issues, it was decided to change the stack cleanup (`add esp, 0xXX`) and `pop edi`,  to `mov edi, [esp+0xYY]` - YY being the number of bytes that would have been "cleaned" from the stack. The `push edi` that follows is retained. ShellWasp maintains a pointer to the syscall array at edi, and since the actual syscall itself destroys the value contained in edi, there needs to be a way to restore it, after the return from the far jump to kernel-mode. It was felt this new Assembly would be a more stable way to accomplish this. Of course, another option could be to have a pointer to the syscall array stored at some location on ebp or other memory, and then that could be used to restore EDI. That would in some ways be simpler, as it would be possible to avoiding needing to count the number of bytes to go back. However, it was felt that `mov edi, [esp+0xYY]` would be safer for novices. If it was stored elsewhere in memory at a fixed location, such as the stack, it could be possible to accidentally overwrite it. Both approaches take minimal time and effort. 

## Correction
Please note that previous public comments I made regarding sorting by address techniques no longer working were incorrect. I apologize for the error. Keep in mind this tool is geared for WoW64, 32-bit shellcode, not as a replacement for other syscall techniques. Our efforts remain in that WoW64 realm.

## License
This project is released under the terms of the MIT license.
