/*
	GCBooter Homebrew v1.0 by Mega Man
	Version 1.2 by Hell Hibou
*/

#include <gccore.h>	
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <fat.h>
#include "whl_arg.h"

GXRModeObj *vmode;
u32 *xfb = NULL;
u8 *data = (u8 *)0x80800000;

static tikview view ATTRIBUTE_ALIGN(32);

int load_file (const char *filename)
{
	char * Drivename, * Path;
	FILE *fin = NULL;
	u32 size;
	PARTITION_INTERFACE FsId = PI_DEFAULT;

	if (!fatInitDefault()) 
	{
		printf("Failed to initialize FAT.\n");
		return -1;
	}
	
	SplitDrivePath (filename, &Drivename, &Path);
	
	if (stricmp (Drivename, "fat3:") == 0) 
	{ 
		fatMountNormalInterface (PI_INTERNAL_SD, 4);
		fatSetDefaultInterface (PI_INTERNAL_SD);
		fatEnableReadAhead (PI_INTERNAL_SD, 32, 64);
		FsId = PI_INTERNAL_SD;
	}
	else if (stricmp (Drivename, "fat1:") == 0)
	{
		fatMountNormalInterface (PI_SDGECKO_A, 4);
		fatSetDefaultInterface (PI_SDGECKO_A);
		fatEnableReadAhead (PI_SDGECKO_A, 32, 64);
		FsId = PI_SDGECKO_A;
	}
	else if (stricmp (Drivename, "fat2:") == 0)
	{
		fatMountNormalInterface (PI_SDGECKO_B, 4);
		fatSetDefaultInterface (PI_SDGECKO_B);
		fatEnableReadAhead (PI_SDGECKO_B, 32, 64);
		FsId = PI_SDGECKO_B;
	}
	else if (stricmp (Drivename, "fat4:") == 0)
	{
		fatMountNormalInterface (PI_USBSTORAGE, 4);
		fatSetDefaultInterface (PI_USBSTORAGE);
		fatEnableReadAhead (PI_USBSTORAGE, 32, 64);
		FsId = PI_USBSTORAGE;
	}
	else { return -3; }
	
	fin = fopen(filename, "rb");
	
	if (fin == NULL) 
	{
		printf("Failed to open \"%s\".\n", filename);
		fatUnmount(FsId);
		return -2;
	}
	
	fseek(fin, 0, SEEK_END);
	size = ftell(fin);
	fseek(fin, 0, SEEK_SET);
	
	if (size > 0x00800000)
	{
		fclose(fin);
		fatUnmount(FsId);
		printf("File is to large.\n");	
		return -4;
	}
	
	if (fread(data, size, 1, fin) != 1) 
	{
		fclose(fin);
		fatUnmount(FsId);
		printf("Failed to read \"%s\" on SD card.\n", filename);
		return -3;
	}

	fclose(fin);
	fatUnmount(FsId);
	DCFlushRange (data, size);
	return 0;
}

void SetLED (u32 LedMode, u32 LedIntensite)
{
	static u32 Data[0x20] __attribute__((aligned(32)));
	int f_led = -1;
	int RetVal;

	f_led = IOS_Open("/dev/stm/immediate",0);

	Data[0] = LedMode;
	RetVal = IOS_Ioctl(f_led, 0x6002, Data, 4, NULL, 0);

	Data[0] = LedIntensite;
	RetVal = IOS_Ioctl(f_led, 0x6001, Data, 4, NULL, 0);

	IOS_Close(f_led);
}

/****************************************************************************
* Main
****************************************************************************/
#define BC 		0x0000000100000100ULL
#define MIOS 	0x0000000100000101ULL

int main (int argc, char **argv)
{
	int rv;
	unsigned char *magic = (unsigned char *) 0x807FFFE0;

	VIDEO_Init ();
	vmode = VIDEO_GetPreferredMode(NULL);
	VIDEO_Configure (vmode);
 
	xfb = (u32 *) MEM_K0_TO_K1 (SYS_AllocateFramebuffer (vmode));
	console_init (xfb, 50, 180, vmode->fbWidth,480, vmode->fbWidth * 2);
	VIDEO_ClearFrameBuffer (vmode, xfb, COLOR_BLACK);
 	VIDEO_SetNextFramebuffer (xfb);
	VIDEO_SetPostRetraceCallback (NULL);
	VIDEO_SetBlack (0);
	VIDEO_Flush ();

	VIDEO_WaitVSync ();       
	if (vmode->viTVMode & VI_NON_INTERLACE) VIDEO_WaitVSync ();
	
	printf("\n\nGCBooter v1.1\n\n");
	
	SetLED (2,1);
	if (argc < 2)
	{
		printf ("Loading start.dol from Front-SD...\n");
		rv = load_file("fat:/start.dol");
	}
	else
	{
		if (stricmp (argv[1]+strlen(argv[1])-4, ".DOL") != 0)
		{
			printf ("Can't load %s, not DOL file.\n", argv[1]);
			SetLED (0,0);
			sleep(5);
			return 0;
		}
		
		printf ("Loading %s...\n", argv[1]);
		rv = load_file(argv[1]);
	}
	SetLED (0,0);
	
	if (rv != 0) 
	{
		printf("Failed to load DOL file.\n");
		sleep(5);
		return 0;
	}
	
	printf("Launching Homebrew in GameCube mode...\n");

	/* Set magic value, to inform gc side about homebrew. */
	strcpy (magic, "gchomebrew dol");
	DCFlushRange(magic, 32);
	*(volatile unsigned int *)0xCC003024 |= 7;
	
	int retval = ES_GetTicketViews(BC, &view, 1);

	if (retval != 0) printf("ES_GetTicketViews fail %d\n",retval);
	retval = ES_LaunchTitle(BC, &view);
	printf("ES_LaunchTitle fail %d\n",retval);	
	return 0;
}

