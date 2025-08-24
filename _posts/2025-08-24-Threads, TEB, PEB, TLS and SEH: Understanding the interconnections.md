---
title: "Threads, TEB, PEB, TLS and SEH: Understanding the interconnections"
date: 2025-08-24 23:00:00 IST
categories:
  - REVERSE_ENGINEERING
tags:
  - threads
  - teb
  - tib
  - tls
  - peb
  - seh
  - infosec
  - x86
  - windows
toc: true
comments: false
image: https://i.ibb.co/m5NFtzcX/Thread-TEB-PEB-TLS-SEH-struct.jpg
--- 


## Threads, TEB, PEB, TLS and SEH: Understanding the interconnections


### What is a thread?

When you write and execute a simple "hello world" program, a process is created by the OS by allocating a virtual address space. The executable is then loaded into this allocated memory, and finally, a main thread is created. This main thread executes your program's logic to print "Hello World" on your screen.

A program can have one or more threads running concurrently. In the simplest terms, threads give the power of concurrency to your application. Your application can do multiple tasks at a single point in time. You can relate this to a web browser handling multiple tabs and several other sub-tasks.

Threads are best handled by a multi-core processor, but the number of threads a program can execute is not limited by the number of cores. Using techniques like hyper-threading or switching very quickly between multiple threads (also known as Context Switching), a processor can handle the modern requirement of running multiple applications and multiple threads within an application. The metadata of every thread is stored in the TEB.

---

### What is a TEB?

TEB or TIB are sometimes used interchangeably. TEB stands for Thread Environment Block, whereas TIB is Thread Information Block. The TEB stores essential information about a thread, such as stack limits, exception handlers, and Thread Local Storage (TLS). The FS segment register is used to point to and access data stored in a TEB.

---

### Where is this TEB data stored?

TEB data is stored in user-space, and hence it can be controlled and modified by a user or program for malicious purposes. This includes achieving SEH overflows, injecting fake TLS, and anti-evasion by setting the `BeingDebugged` flag to 0 (`BeingDebugged` is stored in the PEB).

---

### What data does the TEB store ?

The most important details stored in the TEB are:

- SEH linked list: Stores data about how to handle an exception in a program.
- Stack memory limits: The stack memory range is defined using these limits.
- Pointer to TLS data.
- Pointer to PEB data: The PEB is the Process Environment Block, which stores process-wide information.
- Other information like `ThreadID`, `ProcessID`, `LastErrorValue`, etc.

---

### Let's talk about the above items one by one.

#### What is PEB in TEB?

Every thread has its own TEB, but all threads in a process share the same PEB. The PEB stores process-wide data. The TEB holds a pointer to the PEB, not the actual PEB data. PEB data is stored somewhere in the user-space process address space.

- `PEB_LDR_DATA`: A linked list of all the modules loaded in the process.
- `RTL_USER_PROCESS_PARAMETERS`: Command-line arguments, environment variables, etc.
- `BeingDebugged` flag.

#### What is TLS in TEB?

TLS (Thread Local Storage) is used to store and access variables private to a thread. In this way, every thread can run its own counters and manage error values. As this is a standard way of storing thread-isolated variables, it is definitely faster than the conventional method of allocating and storing a variable in memory.

You might have heard about popular `.tls` callbacks, used popularly by threat actors. The `.tls` callbacks are an array of function pointers defined in the `.tls` section of a PE file. Each of these functions is executed before the main function of a thread, at the time of thread initialization.

Lets understand the correlation between TLS in the TEB and the `.tls` section of PE files. The `.tls` section in a PE file (which is optional) is used as a template to initialize the TLS section in a thread. Basically, the `.tls` section defined in a PE file acts as a template to create a TLS memory block for a thread.

This raises a question: if a user can write to the TEB or PEB  memory of a program, can they inject a new TLS callback function pointer? If this is possible, then a static analysis of the PE file won't show any `.tls` callbacks, but at runtime, this program will have `.tls` callbacks which will be executed whenever a new thread is initialized, just before the main function. This is a  evasion technique.

#### What is SEH?

SEH is a linked list of function pointers; these function pointers handle exceptions raised by a program. A programmer can create custom exceptions and custom exception handlers, and both the custom handlers and default ones are stored in the SEH table. The famous buffer overflow vulnerability has a special category known as SEH overflow. When an overflow is able to overwrite the TEB section of the thread, specifically the SEH linked list, then during an exception, an attacker-controlled function can be executed by taking control of the EIP.

SafeSEH is a popular security mitigation set in a PE file during compile time. A PE file with the `SafeSEH` flag checks the integrity of the SEH table before executing any of the functions from the SEH table.

