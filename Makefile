CC ?= gcc
AS ?= as
LD ?= ld
CFLAGS ?= -Wall -Wextra -O2

SRC_DIR := src
FIXTURE_DIR := fixtures
BUILD_DIR := build
FIXTURE_BUILD_DIR := $(BUILD_DIR)/fixtures

DIRECT_LOADERS := \
	$(BUILD_DIR)/mmap_rwx_loader \
	$(BUILD_DIR)/mmap_mprotect_loader \
	$(BUILD_DIR)/global_array_mprotect_loader \
	$(BUILD_DIR)/stack_exec_loader \
	$(BUILD_DIR)/file_backed_mmap_loader \
	$(BUILD_DIR)/sigaction_direct_loader \
	$(BUILD_DIR)/sigaction_ucontext_rip_loader \
	$(BUILD_DIR)/sigaltstack_loader \
	$(BUILD_DIR)/ucontext_loader \
	$(BUILD_DIR)/pthread_create_loader \
	$(BUILD_DIR)/clone_raw_syscall_loader \
	$(BUILD_DIR)/sigsegv_lazy_loader \
	$(BUILD_DIR)/ptrace_child_loader \
	$(BUILD_DIR)/ptrace_hw_breakpoint_loader \
	$(BUILD_DIR)/process_vm_writev_loader \
	$(BUILD_DIR)/proc_self_mem_loader

OPTIONAL_LOADERS := \
	$(BUILD_DIR)/userfaultfd_loader

ARG_LOADERS := \
	$(BUILD_DIR)/dlopen_loader \
	$(BUILD_DIR)/memfd_dlopen_loader \
	$(BUILD_DIR)/preload_target \
	$(BUILD_DIR)/audit_target \
	$(BUILD_DIR)/dt_needed_target \
	$(BUILD_DIR)/memfd_fexecve_loader \
	$(BUILD_DIR)/shm_open_fexecve_loader \
	$(BUILD_DIR)/manual_elf_loader

FIXTURES := \
	$(FIXTURE_BUILD_DIR)/plugin_payload.so \
	$(FIXTURE_BUILD_DIR)/preload_hook.so \
	$(FIXTURE_BUILD_DIR)/audit_module.so \
	$(FIXTURE_BUILD_DIR)/dt_needed_payload.so \
	$(FIXTURE_BUILD_DIR)/memfd_payload \
	$(FIXTURE_BUILD_DIR)/shm_payload \
	$(FIXTURE_BUILD_DIR)/manual_payload

BINARIES := $(DIRECT_LOADERS) $(OPTIONAL_LOADERS) $(ARG_LOADERS)

.PHONY: all test clean list

all: $(BINARIES) $(FIXTURES)

$(BUILD_DIR) $(FIXTURE_BUILD_DIR):
	mkdir -p $@

# 01_memory_mapping: page permissions and executable mappings
$(BUILD_DIR)/mmap_rwx_loader: $(SRC_DIR)/01_memory_mapping/mmap_rwx_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/mmap_mprotect_loader: $(SRC_DIR)/01_memory_mapping/mmap_mprotect_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/global_array_mprotect_loader: $(SRC_DIR)/01_memory_mapping/global_array_mprotect_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/stack_exec_loader: $(SRC_DIR)/01_memory_mapping/stack_exec_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -z execstack $< -o $@

$(BUILD_DIR)/file_backed_mmap_loader: $(SRC_DIR)/01_memory_mapping/file_backed_mmap_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

# 02_signal_context: signal delivery and user contexts
$(BUILD_DIR)/sigaction_direct_loader: $(SRC_DIR)/02_signal_context/sigaction_direct_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/sigaction_ucontext_rip_loader: $(SRC_DIR)/02_signal_context/sigaction_ucontext_rip_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/sigaltstack_loader: $(SRC_DIR)/02_signal_context/sigaltstack_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/ucontext_loader: $(SRC_DIR)/02_signal_context/ucontext_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

# 03_threads_clone: thread and clone entrypoints
$(BUILD_DIR)/pthread_create_loader: $(SRC_DIR)/03_threads_clone/pthread_create_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -pthread

$(BUILD_DIR)/clone_raw_syscall_loader: $(SRC_DIR)/03_threads_clone/clone_raw_syscall_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -fno-builtin -fno-stack-protector -fno-pie -no-pie -nostdlib $< -o $@

# 04_dynamic_linker: ELF shared object loading and runtime linker features
$(BUILD_DIR)/dlopen_loader: $(SRC_DIR)/04_dynamic_linker/dlopen_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -ldl

$(BUILD_DIR)/memfd_dlopen_loader: $(SRC_DIR)/04_dynamic_linker/memfd_dlopen_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -ldl

$(BUILD_DIR)/preload_target: $(SRC_DIR)/04_dynamic_linker/preload_target.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/audit_target: $(SRC_DIR)/04_dynamic_linker/audit_target.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/dt_needed_target: $(SRC_DIR)/04_dynamic_linker/dt_needed_target.c $(FIXTURE_BUILD_DIR)/dt_needed_payload.so | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -L$(FIXTURE_BUILD_DIR) -Wl,--no-as-needed -l:dt_needed_payload.so -Wl,-rpath,'$$ORIGIN/fixtures'

$(FIXTURE_BUILD_DIR)/plugin_payload.so: $(FIXTURE_DIR)/04_dynamic_linker/plugin_payload.c | $(FIXTURE_BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@

$(FIXTURE_BUILD_DIR)/preload_hook.so: $(FIXTURE_DIR)/04_dynamic_linker/preload_hook.c | $(FIXTURE_BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@

$(FIXTURE_BUILD_DIR)/audit_module.so: $(FIXTURE_DIR)/04_dynamic_linker/audit_module.c | $(FIXTURE_BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@

$(FIXTURE_BUILD_DIR)/dt_needed_payload.so: $(FIXTURE_DIR)/04_dynamic_linker/dt_needed_payload.c | $(FIXTURE_BUILD_DIR)
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@

# 05_memfd_execution: anonymous or tmpfs fd-backed execution
$(BUILD_DIR)/memfd_fexecve_loader: $(SRC_DIR)/05_memfd_execution/memfd_fexecve_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/shm_open_fexecve_loader: $(SRC_DIR)/05_memfd_execution/shm_open_fexecve_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -lrt

$(FIXTURE_BUILD_DIR)/memfd_payload: $(FIXTURE_DIR)/05_memfd_execution/memfd_payload.c | $(FIXTURE_BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(FIXTURE_BUILD_DIR)/shm_payload: $(FIXTURE_DIR)/05_memfd_execution/shm_payload.c | $(FIXTURE_BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

# 06_fault_driven: execution after page-fault handling
$(BUILD_DIR)/sigsegv_lazy_loader: $(SRC_DIR)/06_fault_driven/sigsegv_lazy_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/userfaultfd_loader: $(SRC_DIR)/06_fault_driven/userfaultfd_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -pthread

# 07_manual_elf: educational manual ELF segment mapping
$(BUILD_DIR)/manual_elf_loader: $(SRC_DIR)/07_manual_elf/manual_elf_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(FIXTURE_BUILD_DIR)/manual_payload.o: $(FIXTURE_DIR)/07_manual_elf/manual_payload.S | $(FIXTURE_BUILD_DIR)
	$(AS) --64 -o $@ $<

$(FIXTURE_BUILD_DIR)/manual_payload: $(FIXTURE_BUILD_DIR)/manual_payload.o | $(FIXTURE_BUILD_DIR)
	$(LD) -nostdlib -static -z max-page-size=0x1000 -Ttext-segment=0x700000000000 -o $@ $<

# 08_process_memory: self/controlled-child process-memory demos
$(BUILD_DIR)/ptrace_child_loader: $(SRC_DIR)/08_process_memory/ptrace_child_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/ptrace_hw_breakpoint_loader: $(SRC_DIR)/08_process_memory/ptrace_hw_breakpoint_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/process_vm_writev_loader: $(SRC_DIR)/08_process_memory/process_vm_writev_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/proc_self_mem_loader: $(SRC_DIR)/08_process_memory/proc_self_mem_loader.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

test: all
	@set -e; \
	for bin in $(DIRECT_LOADERS); do \
		echo "== $$(basename $$bin) =="; \
		./$$bin; \
	done; \
	echo "== dlopen_loader =="; \
	./$(BUILD_DIR)/dlopen_loader ./$(FIXTURE_BUILD_DIR)/plugin_payload.so; \
	echo "== memfd_dlopen_loader =="; \
	./$(BUILD_DIR)/memfd_dlopen_loader ./$(FIXTURE_BUILD_DIR)/plugin_payload.so; \
	echo "== preload_target with LD_PRELOAD =="; \
	LD_PRELOAD=$(abspath $(FIXTURE_BUILD_DIR)/preload_hook.so) ./$(BUILD_DIR)/preload_target; \
	echo "== audit_target with LD_AUDIT =="; \
	LD_AUDIT=$(abspath $(FIXTURE_BUILD_DIR)/audit_module.so) ./$(BUILD_DIR)/audit_target; \
	echo "== dt_needed_target with DT_NEEDED =="; \
	./$(BUILD_DIR)/dt_needed_target; \
	echo "== memfd_fexecve_loader =="; \
	./$(BUILD_DIR)/memfd_fexecve_loader ./$(FIXTURE_BUILD_DIR)/memfd_payload; \
	echo "== shm_open_fexecve_loader =="; \
	./$(BUILD_DIR)/shm_open_fexecve_loader ./$(FIXTURE_BUILD_DIR)/shm_payload; \
	echo "== manual_elf_loader =="; \
	./$(BUILD_DIR)/manual_elf_loader ./$(FIXTURE_BUILD_DIR)/manual_payload; \
	echo "== userfaultfd_loader (optional: may be blocked by kernel/sysctl) =="; \
	if ! ./$(BUILD_DIR)/userfaultfd_loader; then \
		echo "userfaultfd_loader skipped/blocked in this environment"; \
	fi

list:
	@printf '%s\n' $(BINARIES) $(FIXTURES)

clean:
	rm -rf $(BUILD_DIR)
