# Linux Shellcode Loader PoCs

Educational x86_64 Linux PoCs that compare multiple local shellcode execution and loading techniques. Every demo is self-contained and prints a benign `helloworld from ...` message to the console/stdout.

This repository is organized as a learning map: each numbered directory represents a different execution/loading concept.

## Requirements

- Linux x86_64
- `gcc`
- `make`
- `as` and `ld` from GNU binutils

Some demos depend on kernel or runtime policy. In particular, `userfaultfd_loader` may be blocked by `vm.unprivileged_userfaultfd`, containers, WSL, or seccomp policies.

## Build

```bash
make all
```

## Run all demos

```bash
make test
```

`make test` treats `userfaultfd_loader` as optional. If the kernel blocks unprivileged `userfaultfd`, the test reports it as skipped/blocked instead of failing the whole suite.

## Project layout

```text
.
├── Makefile
├── README.md
├── fixtures/
│   ├── 04_dynamic_linker/
│   ├── 05_memfd_execution/
│   └── 07_manual_elf/
└── src/
    ├── 01_memory_mapping/
    ├── 02_signal_context/
    ├── 03_threads_clone/
    ├── 04_dynamic_linker/
    ├── 05_memfd_execution/
    ├── 06_fault_driven/
    ├── 07_manual_elf/
    └── 08_process_memory/
```

Build outputs are written to `build/`.

## Category overview

| Category | Purpose |
|---|---|
| `01_memory_mapping` | Basic executable memory techniques: anonymous mappings, page permissions, executable stack, and file-backed executable mappings. |
| `02_signal_context` | Control-flow transfer through Linux signal delivery and user-level contexts. |
| `03_threads_clone` | Running shellcode as a thread or child created by pthread/clone mechanisms. |
| `04_dynamic_linker` | Loading code through the ELF dynamic linker: `dlopen`, `LD_PRELOAD`, `LD_AUDIT`, `DT_NEEDED`, and memfd-backed `.so` loading. |
| `05_memfd_execution` | Executing an ELF image from an anonymous memfd or POSIX shared-memory fd. |
| `06_fault_driven` | Making code appear during page-fault handling. |
| `07_manual_elf` | Manually mapping ELF `PT_LOAD` segments and jumping to the ELF entry point. |
| `08_process_memory` | Self/controlled-child process-memory writing, tracing, and debug-register demos. |

## Implemented loaders

### 01 - Memory mapping loaders

These are the most direct shellcode execution techniques. They focus on where the bytes live and how the memory becomes executable.

| Binary | Source | Principle |
|---|---|---|
| `mmap_rwx_loader` | `src/01_memory_mapping/mmap_rwx_loader.c` | Allocates anonymous memory with `PROT_READ | PROT_WRITE | PROT_EXEC`, copies shellcode into it, then calls the buffer as a function pointer. |
| `mmap_mprotect_loader` | `src/01_memory_mapping/mmap_mprotect_loader.c` | Allocates memory as RW, copies shellcode, then changes the mapping to RX with `mprotect` before execution. This demonstrates a W^X-style flow. |
| `global_array_mprotect_loader` | `src/01_memory_mapping/global_array_mprotect_loader.c` | Stores shellcode in a page-aligned global array, changes the page permission to RX with `mprotect`, then calls the array. |
| `stack_exec_loader` | `src/01_memory_mapping/stack_exec_loader.c` | Places shellcode on the stack and builds with `-z execstack`, allowing the stack to be executable. This demonstrates the effect of NX/executable-stack policy. |
| `file_backed_mmap_loader` | `src/01_memory_mapping/file_backed_mmap_loader.c` | Writes shellcode bytes into a temporary local file, maps the file with `mmap(PROT_EXEC)`, then executes the mapped bytes. |

### 02 - Signal and context loaders

These examples do not simply call shellcode in a normal direct path. They use signal or context mechanics to redirect execution.

| Binary | Source | Principle |
|---|---|---|
| `sigaction_direct_loader` | `src/02_signal_context/sigaction_direct_loader.c` | Registers the RX shellcode address as a `SIGUSR1` handler with `sigaction`, then triggers it with `raise(SIGUSR1)`. Linux signal delivery transfers control to the handler address. |
| `sigaction_ucontext_rip_loader` | `src/02_signal_context/sigaction_ucontext_rip_loader.c` | Uses a `SA_SIGINFO` signal handler, edits the saved `ucontext_t` instruction pointer, and returns. `rt_sigreturn` resumes execution at the shellcode address. |
| `sigaltstack_loader` | `src/02_signal_context/sigaltstack_loader.c` | Installs an alternate signal stack with `sigaltstack`, then runs the shellcode handler through signal delivery on that alternate stack. |
| `ucontext_loader` | `src/02_signal_context/ucontext_loader.c` | Creates a user-level execution context with its own stack using `getcontext`/`makecontext`/`swapcontext`; the context trampoline invokes the shellcode. |

### 03 - Thread and clone loaders

These examples execute shellcode through a new execution context rather than the original direct call path.

| Binary | Source | Principle |
|---|---|---|
| `pthread_create_loader` | `src/03_threads_clone/pthread_create_loader.c` | Copies shellcode into RX memory and passes it as the thread start routine to `pthread_create`. |
| `clone_raw_syscall_loader` | `src/03_threads_clone/clone_raw_syscall_loader.c` | Uses `_start` and raw x86_64 Linux syscalls directly. It performs `mmap`, `mprotect`, `clone`, `wait4`, and `exit` without libc wrappers. The child created by `clone` executes the shellcode. |

### 04 - Dynamic linker loaders

These are ELF/shared-object loading demonstrations. They are not always raw byte-buffer shellcode loaders, but they are important for understanding Linux runtime code loading.

| Binary / Mode | Source / Fixture | Principle |
|---|---|---|
| `dlopen_loader` | `src/04_dynamic_linker/dlopen_loader.c`, `fixtures/04_dynamic_linker/plugin_payload.c` | Loads a local `.so` with `dlopen`, resolves an exported function with `dlsym`, then calls it. |
| `memfd_dlopen_loader` | `src/04_dynamic_linker/memfd_dlopen_loader.c`, `fixtures/04_dynamic_linker/plugin_payload.c` | Copies a `.so` into a `memfd_create` anonymous file, references it through `/proc/self/fd/<fd>`, and loads it with `dlopen`. |
| `LD_PRELOAD` demo | `src/04_dynamic_linker/preload_target.c`, `fixtures/04_dynamic_linker/preload_hook.c` | Runs a target with `LD_PRELOAD` pointing to a local shared object. The shared object constructor prints the demo message when the dynamic linker loads it. |
| `LD_AUDIT` demo | `src/04_dynamic_linker/audit_target.c`, `fixtures/04_dynamic_linker/audit_module.c` | Uses glibc runtime linker auditing. The audit module is loaded through `LD_AUDIT` and prints from an audit callback such as `la_version`. |
| `DT_NEEDED` demo | `src/04_dynamic_linker/dt_needed_target.c`, `fixtures/04_dynamic_linker/dt_needed_payload.c` | Links a local target with an extra `DT_NEEDED` shared-object dependency. At process startup, `ld.so` resolves that dependency and runs the payload library constructor before `main`. This safely demonstrates the mechanism without patching system binaries. |

### 05 - fd-backed execution loaders

This category demonstrates fd-backed execution rather than same-process function-pointer execution.

| Binary | Source / Fixture | Principle |
|---|---|---|
| `memfd_fexecve_loader` | `src/05_memfd_execution/memfd_fexecve_loader.c`, `fixtures/05_memfd_execution/memfd_payload.c` | Copies a local ELF executable into an anonymous memfd, then executes it with `fexecve`. This starts a new program image from an in-memory file descriptor. |
| `shm_open_fexecve_loader` | `src/05_memfd_execution/shm_open_fexecve_loader.c`, `fixtures/05_memfd_execution/shm_payload.c` | Copies a local ELF executable into a POSIX shared-memory object created by `shm_open`, reopens it read-only, unlinks the visible `/dev/shm` name, then executes the fd with `fexecve`. |

### 06 - Fault-driven loaders

These demonstrate lazy execution/loading behavior around page faults.

| Binary | Source | Principle |
|---|---|---|
| `sigsegv_lazy_loader` | `src/06_fault_driven/sigsegv_lazy_loader.c` | Maps a page as inaccessible, jumps to it, catches `SIGSEGV`, fills the page with shellcode, changes it to RX, and returns so the faulting instruction fetch is retried. |
| `userfaultfd_loader` | `src/06_fault_driven/userfaultfd_loader.c` | Registers a missing page with `userfaultfd`. When execution faults on that page, a handler thread supplies a page containing shellcode with `UFFDIO_COPY`, then execution resumes. May be blocked by kernel policy. |

### 07 - Manual ELF loader

This demonstrates what the kernel/dynamic loader normally does for an ELF image, in a simplified educational form.

| Binary | Source / Fixture | Principle |
|---|---|---|
| `manual_elf_loader` | `src/07_manual_elf/manual_elf_loader.c`, `fixtures/07_manual_elf/manual_payload.S` | Parses an ELF64 executable, maps each `PT_LOAD` segment at its requested virtual address, applies final page permissions, then jumps to `e_entry`. The fixture is a tiny static assembly payload with raw syscalls. |

### 08 - Process-memory loaders

These examples demonstrate memory writing and execution redirection through process-memory or debugger interfaces. They only operate on the current process or a child process created by the demo.

| Binary | Source | Principle |
|---|---|---|
| `ptrace_child_loader` | `src/08_process_memory/ptrace_child_loader.c` | Forks a child, uses `ptrace` on that controlled child to write shellcode and redirect execution. This mirrors debugger-style control. |
| `ptrace_hw_breakpoint_loader` | `src/08_process_memory/ptrace_hw_breakpoint_loader.c` | Forks a traced child, sets a hardware execution breakpoint by writing debug registers (`DR0`/`DR7`) with `PTRACE_POKEUSER`, catches the resulting `SIGTRAP`, then changes the child's RIP to an RX shellcode buffer. |
| `process_vm_writev_loader` | `src/08_process_memory/process_vm_writev_loader.c` | Forks a child, writes shellcode into the child's known mapping with `process_vm_writev`, then coordinates execution in the child. |
| `proc_self_mem_loader` | `src/08_process_memory/proc_self_mem_loader.c` | Opens `/proc/self/mem`, writes shellcode bytes into the process's own mapped memory, changes it to RX, and executes it. |

## Expected output

A successful `make test` prints one message per loader. Example excerpt:

```text
== mmap_rwx_loader ==
helloworld from mmap RWX shellcode!
== sigaction_direct_loader ==
helloworld from sigaction direct shellcode!
== dt_needed_target with DT_NEEDED ==
helloworld from DT_NEEDED shellcode-style dependency!
== shm_open_fexecve_loader ==
helloworld from shm_open fexecve shellcode-style ELF!
== ptrace_hw_breakpoint_loader ==
helloworld from ptrace hardware breakpoint shellcode!
== manual_elf_loader ==
helloworld from manual ELF loader shellcode-style ELF!
```

If `userfaultfd` is blocked, the end of the test may show:

```text
== userfaultfd_loader (optional: may be blocked by kernel/sysctl) ==
userfaultfd_loader skipped/blocked in this environment
```

## Useful commands

```bash
make list      # list binaries and fixtures
make clean     # remove build outputs
make test      # build and run all demos
```

## Learning notes

All raw shellcode-style payloads are intentionally minimal. They perform a Linux x86_64 `write(1, message, length)` syscall and then return or exit, depending on the loader style. The goal is to compare execution mechanisms, not payload behavior.
