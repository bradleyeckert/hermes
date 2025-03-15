#ifndef __BCIHW_H__
#define __BCIHW_H__

#include <stdint.h>

/*
bciHW.c contains the execution table and the `int BCIAPIcall(vm_ctx ctx, int xt)` function.
`ctx` exposes the VM internals to the C API.
The execution table must contain only trusted C functions.
`xt` is the index into the execution table.

Memory access functions are defined in `BCIHW.c` to access memories:

```C

*/


int BCIVMdataRead (vm_ctx ctx, uint32_t *x);
int BCIVMdataWrite(vm_ctx ctx, uint32_t x);
int BCIVMcodeRead (vm_ctx ctx, uint16_t *x);

#endif /* __BCIHW_H__ */
