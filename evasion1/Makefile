# Optional MinGW build. Visual Studio users should use build.ps1.
CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
LDLIBS ?=

TARGETS = p01_syscall_visibility p02_parent_context p03_apc_execution           p04_timer_callback p05_memory_transition p06_dll_context           p07_etw_degradation p08_ipv6_telemetry p09_local_ipc           p10_kernel_sensor_integrity

all: $(TARGETS)

p01_syscall_visibility: p01_syscall_visibility.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

p02_parent_context: p02_parent_context.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

p03_apc_execution: p03_apc_execution.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

p04_timer_callback: p04_timer_callback.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

p05_memory_transition: p05_memory_transition.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

p06_dll_context: p06_dll_context.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

p07_etw_degradation: p07_etw_degradation.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS) -ladvapi32

p08_ipv6_telemetry: p08_ipv6_telemetry.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS) -lws2_32

p09_local_ipc: p09_local_ipc.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

p10_kernel_sensor_integrity: p10_kernel_sensor_integrity.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS)

clean:
	-del /Q *.exe 2>NUL


p11_amsi_validation: p11_amsi_validation.c poc_common.h
	$(CC) $(CFLAGS) -o $@.exe $< $(LDLIBS) -lamsi
