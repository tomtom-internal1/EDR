CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2

TARGETS = poc_r01_wmi poc_r02_winrm poc_r03_smb poc_r04_rdp poc_r05_service poc_r06_task poc_r07_powershell poc_r08_cmd poc_r09_transfer poc_r10_web

all: $(TARGETS)

%: %.c poc_common.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS) $(addsuffix .exe,$(TARGETS))
