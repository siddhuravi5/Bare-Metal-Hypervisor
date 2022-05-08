# Bare-Metal-Hypervisor
hardware virtualization

The host OS was fully virtualized, and all the targeted instructions causes
VM exit, and the instructions were handled by the hypervisor. Any targeted
data could be monitored or modified.

A rootkit bare metal hypervisor was possible because of the support provided by intel VT-x for hardware virtualization. Important design elements
were extended page table, virtual machine control structure , execute-only
pages and intel VT-x instruction set.

The malware features included hooking functions, injecting nmi interrupts, e-mailing the monitored data to the targeted user(hacker) etc.
