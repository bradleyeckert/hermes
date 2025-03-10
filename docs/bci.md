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

## BCI-VM handoff

`BCIhandler` steps the VM (CPU simulator) function until it returns nonzero. The ISA includes `vmret` to send that trigger if the VM is executing instructions. The VM hands off control to the BCI when the data stack is empty. The ways the VM can return nonzero are:

- An error occurred
- `vmret` returned a value
- The CPU is stopped

## Functions

| *Fn* | *Description* | *Parameters to BCI* | *Parameters from BCI* |
| :--- | :------------ | :------------------ | :-------------------- |
| 0 | Boilerplate      | *m(1)* | *n(1), data(n), ack(1)* |
| 1 | Execute word (xt) | *base(1), state(1), n(1), stack(n\*4), xt(4)* | *mark(1), base(1), state(1), m(1), stack(m\*4), ack(1)* |
| 2 | Read from memory | *n(1), addr(4)* | *n(1), data(n\*4), ack(1)* |
| 3 | Get CRC of memory | *n(2), addr(4)* | *CRC32(4), ack(1)* |
| 4 | Store to memory  | *n(1), addr(4), data(n\*4)* | *ack(1)* |
| 5 | Read register    | *id(4)* | *data(4), ack(1)* |
| 6 | Write register   | *id(4), data(4)* | *ack(1)* |

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

Execution starts with an empty stack and ends with an empty stack. The BCI:
  
* Pushes the data stack from the incoming data
* Executes the xt  
* Pops the data stack to the return message  

When a word is executed, if the xt is positive, it is a code address. Execution (or simulation) starts there and continues until the return stack is empty. If the xt is negative, the lower five bits are a single five-bit instruction to execute.

If the VM does not have a stack pointer, the BCI first fills the stack with "empty" tokens such as 0x55555555. After execution, the "empty" token indicates that the stack is empty.

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

## BCI artifacts

| *Byte* | *Meaning* | *Parameters from BCI* |
| :----- | :-------- | :-------------------- |
| FFh | POR |  |
| FEh | Ack |  |
| FDh | Nack |  |
| FCh | Command underflow |  |
| FBh | Throw | *data(4)* |
| FAh | Write data to log file | *length (1), data (length)* |

Anything that isn’t an artifact is sent to stdout. Artifacts are numbered F8 to FFh, which are not used by UTF-8.

In a single-threaded system, artifacts would appear after Execute, so there is no need to handle them asynchronously with a separate task. Throw codes are looked up on the host side and output as text messages to stderr. The terminal can treat stderr differently than stdout, such as with a split pane.

## Tethered Forth

Classically, tethered Forths share a UART with a terminal. The BCI cannot do this the same way due to its buffered interface. Words like `emit` and `type`, when directed to the console, can't just plop bytes into a UART. `emit` appends a byte to a buffer instead. `emit` is an API function that uses static copies of `*ret` and `maxret` in the C function:

```C
void BCIhandler(vm_ctx ctx, const uint8_t *src, uint8_t *ret, uint16_t maxret);
```

Data inserted into the return buffer, by the function called by Fn1 "Execute word", appears before whatever is returned by Fn1. So, this user output is delineated by *ack* (FEh).
