# Building the KDASA sensor

## Prerequisites

- Windows 10/11 test VM
- Visual Studio with Desktop C++ tools
- Windows Driver Kit
- Administrator privileges
- A kernel-debugging/test-signing lab configuration

## Integrity requirement

PsSetCreateProcessNotifyRoutineEx requires the driver image to meet the documented integrity condition. In a Visual Studio driver project, enable the linker integrity-check option /INTEGRITYCHECK for the configuration used by the lab.

## Project setup

Create a Kernel Mode Driver, Empty project and add KdasaTelemetry.c.

Configure the project for x64 and build the test configuration.

## Debugging

Use a kernel debugger or documented debug-print tooling in the VM. Capture messages beginning with KDASA|.
