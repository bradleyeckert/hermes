# BCI

The BCI is a binary command interpreter that executes functions on a virtual machine (VM) that emulates a CPU.
The interface to the BCI is:

```C
void BCIhandler(vm_ctx ctx, const uint8_t *src, uint8_t *ret, uint16_t maxret);
```

It processes a binary command `*src` and returns a binary response `*ret`.
If necessary, it waits until the VM is ready. Its parameters are:

- ctx, the VM context
- src, a u16-counted command string
- ret, a u16-counted response string
- maxret, maximum length of response string

The BCI is like a binary version of QUIT that returns throw codes. It interprets commands for memory access and execution, building on the [3-instruction Forth](https://pages.cs.wisc.edu/~bolo/shipyard/3ins4th.html) proposed by Frank Sergeant in 1991\. Since that time, computers have grown fast enough to simulate typical CPUs used in embedded systems. Rather than have different execution environments on host and target systems, Hermes duplicates them for binary compatibility. The dictionary is kept in the host for use by QUIT, but words can be executed on either side because the code images are kept in sync. Data space on the host side may similarly be synced to the target side, making it a clone of the target VM suitable for testing.

BCI data is 32-bit regardless of the cell size of the VM.

The VM hands off control to the BCI when the data stack is empty. 

## Functions

| *Fn* | *Description* | *Parameters to BCI* | *Parameters from BCI* |
| :---- | :---- | :---- | :---- |
| 0 | Boilerplate | *m(1)* | *n(1), data(n), ack(1)* |
| 1 | Execute word (xt) | *stack(16\*4), base(1), state(1), xt(4)* | *Stack(16\*4), base(1), state(1), ack(1)* |
| 2 | Read from memory | *n(1), addr(4)* | *n(1), data(n\*4), ack(1)* |
| 3 | Get CRC of memory | *n(2), addr(4)* | *CRC32(4), ack(1)* |
| 4 | Store to memory | *n(1), addr(4), data(n\*4)* | *ack(1)* |
| 5 | Read register | *id(4)* | *data(4), ack(1)* |
| 6 | Write register | *id(4), data(4)* | *ack(1)* |

If a function fails, it will send a *nack* and the host will ignore the remaining data in the buffer.

**Fn 0: Read Boilerplate**

Read m bytes of static boilerplate, clipped if m > length.  
f(1): format \= 0  
timescale(4): timer ticks per second  
vendor(2): 0 \= generic  
model(2): Target model ID  
hw\_rev(2): Hardware revision  
sw\_rev(2): Software revision
timer(8): Real-time up-counter

**Fn 1: Execute**

* Saves the application’s data and return stacks to RAM  
* Loads the data and return stacks with the contents of the virtual stacks  
* Executes the xt  
* Saves the data and return stacks to the virtual stacks  
* Loads the application’s data and return stacks from RAM

When a word is executed, if the tx is positive, it is a code address. Execution (or simulation) starts there and continues until the return stack is empty. If the xt is negative, the lower five bits are a single five-bit instruction to execute.

**Fn 2: Read from data space**

Read a run of data from memory. The address range splits the memory into different types such as RAM, internal Flash, external Flash, peripherals, etc.

**Fn 3: Get CRC32 of data**

Similar to Fn 2 but returns the CRC32.

**Fn 4: Store to memory**

Store a run of data to memory using the same addressing as Fn 6 and Fn 7\. When writing to Flash (internal or external), writing to the first 256-byte page of a sector will pre-erase the sector. The number of bytes to be written may be less than 256, but the run must not cross page boundaries

**Fn 5: Read register**

Read from a VM register if possible.

**Fn 6: Write register**

Write to a VM register if possible. If the VM supports it, special registers are:

253: pause execution  
254: resume execution  
255: single-step

## BCI artifacts {#bci-artifacts}

| *Byte* | *Meaning* | *Parameters from BCI* |
| :---- | :---- | :---- |
| FFh | Reset occurred (-1 throw) |  |
| FEh | Ack |  |
| FDh | Nack |  |
| FCh | Command underflow |  |
| FBh | Throw | *data(4)* |
| FAh | Write data to log file | *length (1), data (length)* |

Anything that isn’t an artifact is sent to stdout. Artifacts are numbered F8 to FFh, which are not used by UTF-8.

In a single-threaded system, artifacts would appear after Execute, so there is no need to handle them asynchronously with a separate task. Throw codes are looked up on the host side and output as text messages to stderr. The terminal can treat stderr differently than stdout, such as with a split pane.
