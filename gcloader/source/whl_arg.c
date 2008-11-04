///////////////////////////////////////////////////////////////////////////////
// Command line interface between Wii Homebrew Launcher and libogc >= 1.4.7  //
// by Hell Hibou (2008)                                                      //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////


#include <gccore.h>
#include <malloc.h>
#include <string.h>

///////////////////////////////////////////////////////////////////////////////

int SplitDrivePath (const char * FullPath, char * * Drive, char * * Path)
{
	int Boucle = 0;
	char * PtrTemp;
	
	if (FullPath == NULL) { return -1; }
	PtrTemp = malloc (strlen(FullPath) + 1);
	strcpy  (PtrTemp, FullPath);

	while (PtrTemp[Boucle] != 0)
	{
		if (PtrTemp[Boucle] == '/')
		{
			PtrTemp[Boucle] = 0x00;
			*Drive = PtrTemp;
			*Path  = PtrTemp + Boucle + 1;
			return 1;
		}
		
		Boucle++;
	}
	
	*Drive = PtrTemp + strlen(FullPath);
	*Path  = PtrTemp;
	
	return 0;
}

///////////////////////////////////////////////////////////////////////////////

