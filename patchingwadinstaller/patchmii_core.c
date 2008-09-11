/*  patchmii_core -- low-level functions to handle the downloading, patching
    and installation of updates on the Wii

    Copyright (C) 2008 bushing / hackmii.com
    Copyright (C) 2008 Mega Man

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

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

#include "patchmii_core.h"
#include "sha1.h"
#include "debug.h"
#include "haxx_certs.h"
#include "patchmios.h"

#define VERSION "0.1"

#define ALIGN(a,b) ((((a)+(b)-1)/(b))*(b))
#define round_up(x,n) (-(-(x) & -(n)))

int tmd_dirty = 0, tik_dirty = 0;
int installFile(const char *filename);
int do_wad(FILE *fin);
int do_install_wad(FILE *fin, u8 *header);
int do_patch = 0;

void debug_printf(const char *fmt, ...) {
  char buf[1024];
  int len;
  va_list ap;
  usb_flush(1);
  va_start(ap, fmt);
  len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (len <= 0 || len > sizeof(buf)) printf("Error: len = %d\n", len);
  else usb_sendbuffer(1, buf, len);
  puts(buf);
}

u32 be32(const u8 *p)
{
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

char ascii(char s) {
  if(s < 0x20) return '.';
  if(s > 0x7E) return '.';
  return s;
}

void hexdump(void *d, int len) {
  u8 *data;
  int i, off;
  data = (u8*)d;
  for (off=0; off<len; off += 16) {
    debug_printf("%08x  ",off);
    for(i=0; i<16; i++)
      if((i+off)>=len) debug_printf("   ");
      else debug_printf("%02x ",data[off+i]);

    debug_printf(" ");
    for(i=0; i<16; i++)
      if((i+off)>=len) debug_printf(" ");
      else debug_printf("%c",ascii(data[off+i]));
    debug_printf("\n");
  }
}

char *spinner_chars="/-\\|";
int spin = 0;

void spinner(void) {
  printf("\b%c", spinner_chars[spin++]);
  if(!spinner_chars[spin]) spin=0;
}

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

void printvers(void) {
  debug_printf("IOS Version: %08x\n", *((u32*)0xC0003140));
}

void console_setup(void) {
  VIDEO_Init();
  PAD_Init();
  
  rmode = VIDEO_GetPreferredMode(NULL);

  xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
  VIDEO_ClearFrameBuffer(rmode,xfb,COLOR_BLACK);
  VIDEO_Configure(rmode);
  VIDEO_SetNextFramebuffer(xfb);
  VIDEO_SetBlack(FALSE);
  VIDEO_Flush();
  VIDEO_WaitVSync();
  if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();
  CON_InitEx(rmode,20,30,rmode->fbWidth - 40,rmode->xfbHeight - 60);
}

void decrypt_buffer(u16 index, u8 *source, u8 *dest, u32 len) {
  static u8 iv[16];
  if (!source) {
	debug_printf("decrypt_buffer: invalid source paramater\n");
	exit(1);
  }
  if (!dest) {
	debug_printf("decrypt_buffer: invalid dest paramater\n");
	exit(1);
  }

  memset(iv, 0, 16);
  memcpy(iv, &index, 2);
  aes_decrypt(iv, source, dest, len);
}

static u8 encrypt_iv[16];
void set_encrypt_iv(u16 index) {
  memset(encrypt_iv, 0, 16);
  memcpy(encrypt_iv, &index, 2);
}
  
void encrypt_buffer(u8 *source, u8 *dest, u32 len) {
  aes_encrypt(encrypt_iv, source, dest, len);
}

int create_temp_dir(void) {
  int retval;
  retval = ISFS_CreateDir ("/tmp/patchmii", 0, 3, 1, 1);
  if (retval) debug_printf("ISFS_CreateDir(/tmp/patchmii) returned %d\n", retval);
  return retval;
}

u32 save_nus_object (u16 index, u8 *buf, u32 size) {
  char filename[256];
  static u8 bounce_buf[1024] ATTRIBUTE_ALIGN(0x20);
  u32 i;

  int retval, fd;
  snprintf(filename, sizeof(filename), "/tmp/patchmii/%08x", index);
  
  retval = ISFS_CreateFile (filename, 0, 3, 1, 1);

  if (retval != ISFS_OK) {
    debug_printf("ISFS_CreateFile(%s) returned %d\n", filename, retval);
    return retval;
  }
  
  fd = ISFS_Open (filename, ISFS_ACCESS_WRITE);

  if (fd < 0) {
    debug_printf("ISFS_OpenFile(%s) returned %d\n", filename, fd);
    return retval;
  }

  for (i=0; i<size;) {
    u32 numbytes = ((size-i) < 1024)?size-i:1024;
    memcpy(bounce_buf, buf+i, numbytes);
    retval = ISFS_Write(fd, bounce_buf, numbytes);
    if (retval < 0) {
      debug_printf("ISFS_Write(%d, %p, %d) returned %d at offset %d\n", 
		   fd, bounce_buf, numbytes, retval, i);
      ISFS_Close(fd);
      return retval;
    }
    i += retval;
  }
  ISFS_Close(fd);
  return size;
}

s32 install_nus_object (tmd *p_tmd, u16 index) {
  char filename[256];
  static u8 bounce_buf1[1024] ATTRIBUTE_ALIGN(0x20);
  static u8 bounce_buf2[1024] ATTRIBUTE_ALIGN(0x20);
  u32 i;
  const tmd_content *p_cr = TMD_CONTENTS(p_tmd);
  debug_printf("install_nus_object(%p, %lu)\n", p_tmd, index);
  
  int retval, fd, cfd, ret;
  snprintf(filename, sizeof(filename), "/tmp/patchmii/%08x", p_cr[index].cid);
  
  fd = ISFS_Open (filename, ISFS_ACCESS_READ);
  
  if (fd < 0) {
    debug_printf("ISFS_OpenFile(%s) returned %d\n", filename, fd);
    return fd;
  }
  set_encrypt_iv(index);
  debug_printf("ES_AddContentStart(%016llx, %x)\n", p_tmd->title_id, index);

  cfd = ES_AddContentStart(p_tmd->title_id, p_cr[index].cid);
  if(cfd < 0) {
    debug_printf(":\nES_AddContentStart(%016llx, %x) failed: %d\n",p_tmd->title_id, index, cfd);
    ES_AddTitleCancel();
    return -1;
  }
  debug_printf(" (cfd %d): ",cfd);
  for (i=0; i<p_cr[index].size;) {
    u32 numbytes = ((p_cr[index].size-i) < 1024)?p_cr[index].size-i:1024;
    numbytes = ALIGN(numbytes, 32);
    retval = ISFS_Read(fd, bounce_buf1, numbytes);
    if (retval < 0) {
      debug_printf("ISFS_Read(%d, %p, %d) returned %d at offset %d\n", 
		   fd, bounce_buf1, numbytes, retval, i);
      ES_AddContentFinish(cfd);
      ES_AddTitleCancel();
      ISFS_Close(fd);
      return retval;
    }
    
    encrypt_buffer(bounce_buf1, bounce_buf2, sizeof(bounce_buf1));
    ret = ES_AddContentData(cfd, bounce_buf2, retval);
    if (ret < 0) {
      debug_printf("ES_AddContentData(%d, %p, %d) returned %d\n", cfd, bounce_buf2, retval, ret);
      ES_AddContentFinish(cfd);
      ES_AddTitleCancel();
      ISFS_Close(fd);
      return ret;
    }
    i += retval;
  }

  debug_printf("  done! (0x%x bytes)\n",i);
  ret = ES_AddContentFinish(cfd);
  if(ret < 0) {
    printf("ES_AddContentFinish failed: %d\n",ret);
    ES_AddTitleCancel();
    ISFS_Close(fd);
    return -1;
  }
  
  ISFS_Close(fd);
  
  return 0;
}

int get_title_key(signed_blob *s_tik, u8 *key) {
  static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
  static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
  static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);
  int retval;

  const tik *p_tik;
  p_tik = (tik*)SIGNATURE_PAYLOAD(s_tik);
  u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
  memcpy(keyin, enc_key, sizeof keyin);
  memset(keyout, 0, sizeof keyout);
  memset(iv, 0, sizeof iv);
  memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);
  
  retval = ES_Decrypt(ES_KEY_COMMON, iv, keyin, sizeof keyin, keyout);
  if (retval) debug_printf("ES_Decrypt returned %d\n", retval);
  memcpy(key, keyout, sizeof keyout);
  return retval;
}

uint64_t get_ticket_title_id(signed_blob *s_tik) {
	tik *p_tik;
	p_tik = (tik*)SIGNATURE_PAYLOAD(s_tik);

	return p_tik->titleid;
}

int change_ticket_title_id(signed_blob *s_tik, u32 titleid1, u32 titleid2) {
	static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);
	int retval;

	tik *p_tik;
	p_tik = (tik*)SIGNATURE_PAYLOAD(s_tik);
	u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
	memcpy(keyin, enc_key, sizeof keyin);
	memset(keyout, 0, sizeof keyout);
	memset(iv, 0, sizeof iv);
	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);

	retval = ES_Decrypt(ES_KEY_COMMON, iv, keyin, sizeof keyin, keyout);
	p_tik->titleid = (u64)titleid1 << 32 | (u64)titleid2;
	memset(iv, 0, sizeof iv);
	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);
	
	retval = ES_Encrypt(ES_KEY_COMMON, iv, keyout, sizeof keyout, keyin);
    if (retval) debug_printf("ES_Decrypt returned %d\n", retval);
	memcpy(enc_key, keyin, sizeof keyin);
	tik_dirty = 1;

    return retval;
}

void change_tmd_title_id(signed_blob *s_tmd, u32 titleid1, u32 titleid2) {
	tmd *p_tmd;
	u64 title_id = titleid1;
	title_id <<= 32;
	title_id |= titleid2;
	p_tmd = (tmd*)SIGNATURE_PAYLOAD(s_tmd);
	p_tmd->title_id = title_id;
	tmd_dirty = 1;
}

void display_tag(u8 *buf) {
  debug_printf("Firmware version: %s      Builder: %s\n",
	       buf, buf+0x30);
}

void display_ios_tags(u8 *buf, u32 size) {
  u32 i;
  char *ios_version_tag = "$IOSVersion:";

  if (size == 64) {
    display_tag(buf);
    return;
  }

  for (i=0; i<(size-64); i++) {
    if (!strncmp((char *)buf+i, ios_version_tag, 10)) {
      char version_buf[128], *date;
      while (buf[i+strlen(ios_version_tag)] == ' ') i++; // skip spaces
      strlcpy(version_buf, (char *)buf + i + strlen(ios_version_tag), sizeof version_buf);
      date = version_buf;
      strsep(&date, "$");
      date = version_buf;
      strsep(&date, ":");
      debug_printf("%s (%s)\n", version_buf, date);
      i += 64;
    }
  }
}

int patch_hash_check(u8 *buf, u32 size) {
  u32 i;
  u32 match_count = 0;
  u8 new_hash_check[] = {0x20,0x07,0x4B,0x0B};
  u8 old_hash_check[] = {0x20,0x07,0x23,0xA2};
  
  for (i=0; i<size-4; i++) {
    if (!memcmp(buf + i, new_hash_check, sizeof new_hash_check)) {
      debug_printf("Found new-school ES hash check @ 0x%x, patching.\n", i);
      buf[i+1] = 0;
      i += 4;
      match_count++;
      continue;
    }

    if (!memcmp(buf + i, old_hash_check, sizeof old_hash_check)) {
      debug_printf("Found old-school ES hash check @ 0x%x, patching.\n", i);
      buf[i+1] = 0;
      i += 4;
      match_count++;
      continue;
    }
  }
  return match_count;
}

int patch_new_dvdlowunencrypted(u8 *buf, u32 size)
{
  u32 i;
  u32 match_count = 0;
  u8 old_table[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x7E, 0xD4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08};
  u8 new_table[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x46, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x7E, 0xD4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08};
  
  for (i=0; i<size-sizeof old_table; i++) {
    if (!memcmp(buf + i, old_table, sizeof old_table)) {
      debug_printf("Found new-school DVD_LowUnencryptedRead whitelist @ 0x%x, patching.\n", i);
      memcpy(buf + i, new_table, sizeof new_table);
      i += sizeof new_table;
      match_count++;
      continue;
    }
  }
  return match_count;
}

void print_tmd_summary(const tmd *p_tmd) {
  const tmd_content *p_cr;
  p_cr = TMD_CONTENTS(p_tmd);

  u32 size=0;

  u16 i=0;
  for(i=0;i<p_tmd->num_contents;i++) {
    size += p_cr[i].size;
  }

  debug_printf("Title ID: %016llx\n",p_tmd->title_id);
  debug_printf("Number of parts: %d.  Total size: %uK\n", p_tmd->num_contents, (u32) (size / 1024));
}

void zero_sig(signed_blob *sig) {
  u8 *sig_ptr = (u8 *)sig;
  memset(sig_ptr + 4, 0, SIGNATURE_SIZE(sig)-4);
}

void brute_tmd(tmd *p_tmd) {
  u16 fill;
  for(fill=0; fill<65535; fill++) {
    p_tmd->fill3=fill;
    sha1 hash;
    //    debug_printf("SHA1(%p, %x, %p)\n", p_tmd, TMD_SIZE(p_tmd), hash);
    SHA1((u8 *)p_tmd, TMD_SIZE(p_tmd), hash);;
  
    if (hash[0]==0) {
      //      debug_printf("setting fill3 to %04hx\n", fill);
      return;
    }
  }
  printf("Unable to fix tmd :(\n");
  exit(4);
}

void brute_tik(tik *p_tik) {
  u16 fill;
  for(fill=0; fill<65535; fill++) {
    p_tik->padding=fill;
    sha1 hash;
    //    debug_printf("SHA1(%p, %x, %p)\n", p_tmd, TMD_SIZE(p_tmd), hash);
    SHA1((u8 *)p_tik, sizeof(tik), hash);
  
    if (hash[0]==0) return;
  }
  printf("Unable to fix tik :(\n");
  exit(5);
}
    
void forge_tmd(signed_blob *s_tmd) {
  debug_printf("forging tmd sig\n");
  zero_sig(s_tmd);
  brute_tmd(SIGNATURE_PAYLOAD(s_tmd));
}

void forge_tik(signed_blob *s_tik) {
  debug_printf("forging tik sig\n");
  zero_sig(s_tik);
  brute_tik(SIGNATURE_PAYLOAD(s_tik));
}

#define BLOCK 0x1000

s32 install_ticket(const signed_blob *s_tik, const signed_blob *s_certs, u32 certs_len) {
  u32 ret;

  debug_printf("Installing ticket...\n");
  ret = ES_AddTicket(s_tik,STD_SIGNED_TIK_SIZE,s_certs,certs_len, NULL, 0);
  if (ret < 0) {
      debug_printf("ES_AddTicket failed: %d\n",ret);
      return ret;
  }
  return 0;
}

s32 install(const signed_blob *s_tmd, const signed_blob *s_certs, u32 certs_len) {
  u32 ret, i;
  tmd *p_tmd = SIGNATURE_PAYLOAD(s_tmd);
  debug_printf("Adding title...\n");

  ret = ES_AddTitleStart(s_tmd, SIGNED_TMD_SIZE(s_tmd), s_certs, certs_len, NULL, 0);

  if(ret < 0) {
    debug_printf("ES_AddTitleStart failed: %d\n",ret);
    ES_AddTitleCancel();
    return ret;
  }

  for(i=0; i<p_tmd->num_contents; i++) {
    debug_printf("Adding content ID %08x", i);
    ret = install_nus_object((tmd *)SIGNATURE_PAYLOAD(s_tmd), i);
    if (ret) return ret;
  }

  ret = ES_AddTitleFinish();
  if(ret < 0) {
    printf("ES_AddTitleFinish failed: %d\n",ret);
    ES_AddTitleCancel();
    return ret;
  }

  printf("Installation complete!\n");
  return 0;

}

int main(int argc, char **argv) {
	int rv;
	u16 btn;

	console_setup();
	printf("MIOS patching WADInstaller Core v" VERSION ", by Mega Man\n");

	PAD_ScanPads();
	while((PAD_ButtonsHeld(0) & (PAD_BUTTON_A | PAD_BUTTON_B))) {
		PAD_ScanPads();
	}
	printf("\n");
	printf("Press A to install patch (Caution: If Gamecube discs are still working, is not tested).\n");
	printf("Press B to remove patch (GC games should work again).\n");
	printf("\n");
	printf("Switch off your console, if you don't know why you have started this program!\n");
	PAD_ScanPads();
	while(1) {
		btn = PAD_ButtonsHeld(0);
		if (btn &PAD_BUTTON_B) {
			do_patch = 0;
			break;
		}
		if (btn &PAD_BUTTON_A) {
			do_patch = -1;
			break;
		}
		PAD_ScanPads();
	}

	if (!fatInitDefault()) {
		printf("Failed to initialize FAT.\n");
		return 0;
	}
	chdir ("fat:/");
	printvers();
  
	if (ISFS_Initialize() || create_temp_dir()) {
		perror("Failed to create temp dir: ");
		return(1);
	}

	rv = installFile("RVL-mios-v5.wad.out.wad");
	fatUnmount(PI_DEFAULT);
	sleep(5);
	return rv;
}

int installFile(const char *filename)
{
	int rv = 1;
	FILE *fin = NULL;

	fin = fopen(filename, "rb");
	if (fin == NULL) {
		printf("Failed to read \"%s\" on SD card.\n", filename);
		return 1;
	}

	while (!feof(fin)) {
		rv = do_wad(fin);
		if (rv != 0) {
			fprintf(stderr, "do_wad() failed with rv = %d\n", rv);
			break;
		} else {
			break;
		}
	}
	fclose(fin);
	return rv;
}

int do_wad(FILE *fin)
{
	u8 header[0x80];
	u32 header_len;
	u32 header_type;
	int rv;

	if (fread(header, 0x40, 1, fin) != 1) {
		if (!feof(fin)) {
			fprintf(stderr, "Error: Reading wad header\n");
			return -5;
		} else {
			return 0;
		}
	}
	header_len = be32(header);
	if (header_len >= 0x80) {
		fprintf(stderr, "wad header too big\n");
		return -1;
	}
	if (header_len >= 0x40) {
		if (fread(header + 0x40, 0x40, 1, fin) != 1) {
			fprintf(stderr, "Error: Reading wad header (2)\n");
			return -2;
		}
	}

	header_type = be32(header + 4);
	switch (header_type) {
	case 0x49730000:
		rv = do_install_wad(fin, header);
		break;
	case 0x69620000:
		rv = do_install_wad(fin, header);
		break;
	default:
		fprintf(stderr, "unknown header type %08x\n", header_type);
		return -6;
	}
	return rv;
}

static u8 *get_wad(FILE *fin, u32 len)
{
	u32 rounded_len;
	u8 *p;

	rounded_len = round_up(len, 0x40);
	p = malloc(rounded_len);
	if (p == 0) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	if (len) {
		if (fread(p, rounded_len, 1, fin) != 1) {
			fprintf(stderr, "get_wad read, len = %x\n", len);
			free(p);
			return NULL;
		}
	}

	return p;
}

int do_install_wad(FILE *fin, u8 *header)
{
  	signed_blob *s_tmd = NULL, *s_tik = NULL, *s_certs = NULL;
	int retval;
  	u8 *temp_tmdbuf = NULL, *temp_tikbuf = NULL;

  	static u8 tmdbuf[MAX_SIGNED_TMD_SIZE] ATTRIBUTE_ALIGN(0x20);
  	static u8 tikbuf[STD_SIGNED_TIK_SIZE] ATTRIBUTE_ALIGN(0x20);
  
  	u32 tmdsize;
	int update_tmd;
	u32 header_len;
	u32 cert_len;
	u32 ticketsize;
	u32 app_len;
	u32 trailer_len;
	u8 *cert;
	u8 *app;
	u8 *trailer;

	header_len = be32(header);
	if (header_len != 0x20) {
		fprintf(stderr, "Error: Bad install header length (%x)", header_len);
		return -7;
	}

	cert_len = be32(header + 8);
	// 0 = be32(header + 0x0c);
	ticketsize = be32(header + 0x10);
	tmdsize = be32(header + 0x14);
	app_len = be32(header + 0x18);
	trailer_len = be32(header + 0x1c);

	cert = get_wad(fin, cert_len);
	if (cert == NULL) {
		fprintf(stderr, "Error: Reading cert.\n");
		return -8;
	}
	temp_tikbuf = get_wad(fin, ticketsize);
	if (temp_tikbuf == NULL) {
		fprintf(stderr, "Error: Reading ticket.\n");
		return -9;
	}
	memcpy(tikbuf, temp_tikbuf, MIN(ticketsize, sizeof(tikbuf)));
	s_tik = (signed_blob *)tikbuf;
	if(!IS_VALID_SIGNATURE(s_tik)) {
    	debug_printf("Bad tik signature!\n");
		return(1);
  	}
  	free(temp_tikbuf);

	temp_tmdbuf = get_wad(fin, tmdsize);
	if (temp_tmdbuf == NULL) {
		debug_printf("Failed to allocate temp buffer for encrypted content, size was %u\n", tmdsize);
		return(1);
	}
  	memcpy(tmdbuf, temp_tmdbuf, MIN(tmdsize, sizeof(tmdbuf)));
	free(temp_tmdbuf);

	s_tmd = (signed_blob *)tmdbuf;
	if(!IS_VALID_SIGNATURE(s_tmd)) {
    	debug_printf("Bad TMD signature!\n");
		return(1);
  	}

  	debug_printf("\b ..tmd..");
	app = get_wad(fin, app_len);
	if (app == NULL) {
		fprintf(stderr, "Error: Reading app.\n");
		return -10;
	}
	trailer = get_wad(fin, trailer_len);

	s_certs = (signed_blob *)haxx_certs;
	if(!IS_VALID_SIGNATURE(s_certs)) {
    	debug_printf("Bad cert signature!\n");
		return(1);
  	}

	debug_printf("\b ..ticket..");

	u8 key[16];
	get_title_key(s_tik, key);
	aes_set_key(key);

	const tmd *p_tmd;
	tmd_content *p_cr;
	p_tmd = (tmd*)SIGNATURE_PAYLOAD(s_tmd);
	p_cr = TMD_CONTENTS(p_tmd);
        
	print_tmd_summary(p_tmd);
	uint64_t id = get_ticket_title_id(s_tik);

	if (id != 0x0000000100000101) {
		printf("WAD file must be MIOS!\n");
		printf("Please copy correct file on SD card.\n");
		return -46;
	}

	debug_printf("Extracting contents: \n");
	static char cidstr[32];
	u16 i;
	u8 *contentPointer = app;
	for (i=0;i<p_tmd->num_contents;i++) {
	   debug_printf("Downloading part %d/%d (%uK): ", i+1, 
					p_tmd->num_contents, p_cr[i].size / 1024);
	   sprintf(cidstr, "%08x", p_cr[i].cid);
   
	   u8 *content_buf, *decrypted_buf;
	   u32 content_size;

		content_size = round_up(p_cr[i].size, 0x40);
		content_buf = contentPointer;

		if (content_buf == NULL) {
			debug_printf("error allocating content buffer, size was %u\n", content_size);
			return(1);
		}

		if (content_size % 16) {
			debug_printf("ERROR: downloaded content[%hu] size %u is not a multiple of 16\n",
					i, content_size);
			free(app);
			return(1);
		}

		decrypted_buf = malloc(content_size);
		if (!decrypted_buf) {
			debug_printf("ERROR: failed to allocate decrypted_buf (%u bytes)\n", content_size);
			free(app);
			return(1);
		}

		decrypt_buffer(i, content_buf, decrypted_buf, content_size);

		sha1 hash;
		SHA1(decrypted_buf, p_cr[i].size, hash);

		if (!memcmp(p_cr[i].hash, hash, sizeof hash)) {
			debug_printf("\b hash OK. ");
			display_ios_tags(decrypted_buf, content_size);

			update_tmd = 0;

			if (do_patch) {
				if (p_cr[i].index == 1) {
					int rv;

					rv = patchMIOS(&decrypted_buf);
					if (rv <= 0) {
						fprintf(stderr, "Error: Patching of MIOS failed.\n");
						return rv;
					}
					update_tmd = 1;
					p_cr[i].size = rv;
					content_size = round_up(p_cr[i].size, 0x40);
				}
			}
			if(update_tmd == 1) {
				debug_printf("Updating TMD.\n");
				SHA1(decrypted_buf, p_cr[i].size, hash);
				memcpy(p_cr[i].hash, hash, sizeof hash);
				tmd_dirty=1;
			}

			retval = (int) save_nus_object(p_cr[i].cid, decrypted_buf, content_size);
			if (retval < 0) {
				debug_printf("save_nus_object(%x) returned error %d\n", p_cr[i].cid, retval);
				return(1);
			}
		} else {
			debug_printf("hash BAD\n");
			return(1);
		}
     
		free(decrypted_buf);
		contentPointer += content_size;
	}
	free(app);
    
	id = get_ticket_title_id(s_tik);
	printf("Titleid 0x%08x%08x\n", (uint32_t) (id >> 32), (uint32_t) id);
	/* CAUTION: Don't remove this security check. */
	if (id != 0x0000000100000101) {
		printf("This is not a MIOS installation, something failed!\n");
		return -47;
	}

	if (tmd_dirty) {
    	forge_tmd(s_tmd);
    	tmd_dirty = 0;
  	}

  	if (tik_dirty) {
    	forge_tik(s_tik);
    	tik_dirty = 0;
  	}
  	debug_printf("Installing:\n");

#if 1
  	retval = install_ticket(s_tik, s_certs, haxx_certs_size);
  	if (retval) {
    	debug_printf("install_ticket returned %d\n", retval);
		return(1);
  	}

  	retval = install(s_tmd, s_certs, haxx_certs_size);
		   
  	if (retval) {
    	debug_printf("install returned %d\n", retval);
    	return(1);
  	}
#endif

  	debug_printf("Done!\n");

	return(0);
}
