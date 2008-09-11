#include <stdio.h>
#include <gccore.h>		/*** Wrapper to include common libogc headers ***/
#include <ogcsys.h>		/*** Needed for console support ***/
#include <ogc/dvd.h>	
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <malloc.h>
#include <ogcsys.h>
#include <fat.h>

/*** 2D Video Globals ***/
GXRModeObj *vmode;		/*** Graphics Mode Object ***/
u32 *xfb[2] = { NULL, NULL };    /*** Framebuffers ***/
int whichfb = 0;        /*** Frame buffer toggle ***/
void ProperScanPADS(){	PAD_ScanPads(); }

// Wii stuff
#include <ogc/es.h>
#include <ogc/ipc.h>
#include <ogc/ios.h>
#define IOCTL_DI_READID				0x70
#define IOCTL_DI_READ				0x71
#define IOCTL_DI_RESET				0x8A

static int __dvd_fd 		= -1;
static int previously_initd =  0;
static char __di_fs[] ATTRIBUTE_ALIGN(32) = "/dev/di";
u8 *data = (u8 *)0x80800000;

u8 dicommand [32]   ATTRIBUTE_ALIGN(32);
u8 dibufferio[32]   ATTRIBUTE_ALIGN(32);
static tikview view ATTRIBUTE_ALIGN(32);

/* Synchronous DVD stuff.. bad! */
/* Open /dev/di */
int WiiDVD_Init() {
	if(!previously_initd) {
		int ret;
		ret = IOS_Open(__di_fs,0);
		if(ret<0) return ret;	
		__dvd_fd = ret;
		previously_initd = 1;
	}
	return 0;
}

/* Resets the drive, spins up the media */
void WiiDVD_Reset() {
	memset(dicommand, 0, 32 );
	dicommand[0] = IOCTL_DI_RESET;
	((u32*)dicommand)[1] = 1; //spinup(?)
	IOS_Ioctl(__dvd_fd,dicommand[0],&dicommand,0x20,NULL,0);
}

/* Read the Disc ID */
int WiiDVD_ReadID(void *dst) {
	int ret;
	memset(dicommand, 0, 32 );
	dicommand[0] = IOCTL_DI_READID;
	((u32*)dicommand)[1] = 0;
	((u32*)dicommand)[2] = 0;
	ret = IOS_Ioctl(__dvd_fd,dicommand[0],&dicommand,0x20,(void*)0x80000000,0x20);
	return ret;
}

/****************************************************************************
* Initialise Video
*
* Before doing anything in libogc, it's recommended to configure a video
* output.
****************************************************************************/
static void Initialise (void)
{
  VIDEO_Init ();        /*** ALWAYS CALL FIRST IN ANY LIBOGC PROJECT!
                     Not only does it initialise the video 
                     subsystem, but also sets up the ogc os
                ***/
 
  PAD_Init ();            /*** Initialise pads for input ***/
 
    /*** Try to match the current video display mode
         using the higher resolution interlaced.
    
         So NTSC/MPAL gives a display area of 640x480
         PAL display area is 640x528
    ***/
  switch (VIDEO_GetCurrentTvMode ())
    {
    case VI_NTSC:
      vmode = &TVNtsc480IntDf;
      break;
 
    case VI_PAL:
      vmode = &TVPal528IntDf;
      break;
 
    case VI_MPAL:
      vmode = &TVMpal480IntDf;
      break;
 
    default:
      vmode = &TVNtsc480IntDf;
      break;
    }
    /*** Let libogc configure the mode ***/
  VIDEO_Configure (vmode);
 
    /*** Now configure the framebuffer. 
         Really a framebuffer is just a chunk of memory
         to hold the display line by line.
    ***/
 
  xfb[0] = (u32 *) MEM_K0_TO_K1 (SYS_AllocateFramebuffer (vmode));
    /*** I prefer also to have a second buffer for double-buffering.
         This is not needed for the console demo.
    ***/
  xfb[1] = (u32 *) MEM_K0_TO_K1 (SYS_AllocateFramebuffer (vmode));
     /*** Define a console ***/
    		/*			x	y     w   h			*/
  console_init (xfb[0], 50, 180, vmode->fbWidth,480, vmode->fbWidth * 2);
    /*** Clear framebuffer to black ***/
  VIDEO_ClearFrameBuffer (vmode, xfb[0], COLOR_BLACK);
  VIDEO_ClearFrameBuffer (vmode, xfb[1], COLOR_BLACK);
 
    /*** Set the framebuffer to be displayed at next VBlank ***/
  VIDEO_SetNextFramebuffer (xfb[0]);
 
    /*** Get the PAD status updated by libogc ***/
  VIDEO_SetPostRetraceCallback (ProperScanPADS);
  VIDEO_SetBlack (0);
 
    /*** Update the video for next vblank ***/
  VIDEO_Flush ();
 
  VIDEO_WaitVSync ();        /*** Wait for VBL ***/
  if (vmode->viTVMode & VI_NON_INTERLACE)
    VIDEO_WaitVSync ();
}

void wait_press_A()
{
	printf("Press A to continue..\n");
	while((PAD_ButtonsHeld(0) & PAD_BUTTON_A));
	while(!(PAD_ButtonsHeld(0) & PAD_BUTTON_A));
}

void memDebug(void)
{
	unsigned char *buf = 0x80200000;
	int i;
	int size;
	unsigned char k;

	k = 0xFF;
	size = 0x1000;
	for (i = 0; i < size; i++) {
		buf[i] = k;
		k -= 2;
	}
	DCFlushRange(buf, size);
}

int load_file(const char *filename)
{
	FILE *fin = NULL;
	u32 size;

	if (!fatInitDefault()) {
		printf("Failed to initialize FAT.\n");
		return -1;
	}
	chdir ("fat:/");

	fin = fopen(filename, "rb");
	if (fin == NULL) {
		printf("Failed to open \"%s\" on SD card.\n", filename);
		return -2;
	}
	
	fseek(fin, 0, SEEK_END);
	size = ftell(fin);
	fseek(fin, 0, SEEK_SET);
	if (size > 0x00800000) {
		fclose(fin);
		printf("File is to large.\n");	
		return -4;
	}
	if (fread(data, size, 1, fin) != 1) {
		fclose(fin);
		printf("Failed to read \"%s\" on SD card.\n", filename);
		return -3;
	}

	fclose(fin);

	fatUnmount(PI_DEFAULT);
	DCFlushRange(data, size);
	return 0;
}

/****************************************************************************
* Main
****************************************************************************/
#define BC 		0x0000000100000100ULL
#define MIOS 	0x0000000100000101ULL
int main ()
{
	int rv;
	unsigned char *magic = (unsigned char *) 0x807FFFE0;

	Initialise();
	
	printf("\n\n\n\n\nGCBooter v1.0\n\n\n");

	printf("Opening /dev/di/ ..\n");
	WiiDVD_Init();
	
	printf("Resetting DI interface ..\n");
	WiiDVD_Reset();
	
	printf("Reading Disc ID ..\n");
	WiiDVD_ReadID((void*)0x80000000);
	//memDebug();
	rv = load_file("start.dol");
	if (rv != 0) {
		printf("Failed to load DOL file.\n");
		sleep(5);
		return 0;
	}
	
	printf("Launching Game ..\n");

	/* Set magic value, to inform gc side about homebrew. */
	strcpy(magic, "gchomebrew dol");
	DCFlushRange(magic, 32);
	*(volatile unsigned int *)0xCC003024 |= 7;
	
	int retval = ES_GetTicketViews(BC, &view, 1);

	if (retval != 0) printf("ES_GetTicketViews fail %d\n",retval);
	retval = ES_LaunchTitle(BC, &view);
	printf("ES_LaunchTitle fail %d\n",retval);	
	while(1);
	return 0;
}

                                                     