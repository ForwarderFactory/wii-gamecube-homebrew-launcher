#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <ogcsys.h>
#include <gccore.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <network.h>
#include <sys/errno.h>
#include <ogcsys.h>
#include <fat.h>

#include "dol.h"
#include "asm.h"
#include "processor.h"

//u8 *data = (u8 *)0x91780000;
u8 *data = (u8 *)0x80800000;

int load_dol(void)
{
	void (*ep)();
	unsigned long level = 0;


	ep = (void(*)())load_dol_image(data, 1);

#if defined(__wii__)
	__IOS_ShutdownSubsystems();
#endif
	_CPU_ISR_Disable(level);
	__exception_closeall();
	printf("Jump to 0x%08x\n", (u32) ep);
	ep();
	return 3;
}
