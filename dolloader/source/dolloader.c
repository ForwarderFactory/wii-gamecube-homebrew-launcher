#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <ogcsys.h>
#include <gccore.h>

#include "loader.h"

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

void call_mios(void)
{
	unsigned long *entry = 0x800037fc;

	/* Restore patched entry point. */
	*entry = 0x81300200;
	DCFlushRange(entry, 32);

	/* Simulate boot. */
	__asm__(
		"bl DCDisable\n"
		"bl ICDisable\n"
		"li %r3, 0\n"
		"mtsrr1 %r3\n"
		"li %r4, 0x3400\n"
		"mtsrr0 %r4\n"
		"rfi\n"
	);
}

int main(int argc, char **argv) {
	unsigned char *magic = (unsigned char *) 0x807FFFE0;

	if (strncmp(magic, "gchomebrew dol", 32) != 0) {
		/* No homebrew means normal startup. */
		call_mios();
	}

	/* Overwrite magic value, so GC disc will work after reset. */
	*magic = 0;
	DCFlushRange(magic, 32);

	VIDEO_Init();
	PAD_Init();
	
	switch(VIDEO_GetCurrentTvMode()) {
		case VI_NTSC:
			rmode = &TVNtsc480IntDf;
			break;
		case VI_PAL:
			rmode = &TVPal528IntDf;
			break;
		case VI_MPAL:
			rmode = &TVMpal480IntDf;
			break;
		default:
			rmode = &TVNtsc480IntDf;
			break;
	}

	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	console_init(xfb,20,20,rmode->fbWidth,rmode->xfbHeight,rmode->fbWidth*VI_DISPLAY_PIX_SZ);
	
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();

	printf("Wii Gamecube Homebrew Launcher by Mega Man.\n");
	printf("Loading DOL from memory...\n");
	load_dol();
	printf("Loading failed\n");

	VIDEO_WaitVSync();
	while(1);
	return 0;
}
