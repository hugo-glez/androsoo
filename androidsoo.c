/*
 * dexstrings  - Extract information from .dex files
 *
 * compile:
 *     gcc -g -o androsoo androsoo.c -lm
 *     two warnings will be showed, you can ignore that.
 * check the order of the string pointer
 * usually the repackaged apps with apktool before 2.0
 * and other productos create .dex files with the strings
 * pointer not in order.
 *
 * All the theory is explained in the paper:
 * Exploring reverse engineering symptoms in Android apps
 * EuroSec '15 Proceedings of the Eighth European Workshop on System Security
 *
 * http://dx.doi.org/10.1145/2751323.2751330
 *
 */

#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/stat.h>

#define VERSION "1.0"

typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;

typedef struct {
	char dex[3];
	char newline[1];
	char ver[3];
	char zero[1];
} dex_magic;

typedef struct {
	dex_magic magic;
	u4 checksum[1];
	unsigned char signature[20];
	u4 file_size[1];
	u4 header_size[1];
	u4 endian_tag[1];
	u4 link_size[1];
	u4 link_off[1];
	u4 map_off[1];
	u4 string_ids_size[1];
	u4 string_ids_off[1];
	u4 type_ids_size[1];
	u4 type_ids_off[1];
	u4 proto_ids_size[1];
	u4 proto_ids_off[1];
	u4 field_ids_size[1];
	u4 field_ids_off[1];
	u4 method_ids_size[1];
	u4 method_ids_off[1];
	u4 class_defs_size[1];
	u4 class_defs_off[1];
	u4 data_size[1];
	u4 data_off[1];
} dex_header;


typedef struct {
	u4 string_data_off[1];
} string_id_struct;


void help_show_message(char name[])
{
	printf ("\n=== androsoo %s - (c) 2014 Hugo Gonzalez @hugo_glez\n", VERSION);
    printf( "Paper: Exploring reverse engineering symptoms in Android apps\n");
    printf ("EuroSec '15 Proceedings of the Eighth European Workshop on System Security\n");
    printf ("http://dx.doi.org/10.1145/2751323.2751330\n===\n");
	printf( "Usage: %s  <file.dex> [options]\n",name);
    printf( "\t-s\tsilence, no headers\n");
}
int main(int argc, char *argv[])
{
	char *dexfile;
	FILE *input;
    u1 *fileinmemory;
	int i;
    int SILENCE=2;
    char c;

	dex_header* header;

	string_id_struct* string_id_list;

	if (argc < 2) {
		help_show_message(argv[0]);
		return 1;
	}

	dexfile=argv[1];
	input = fopen(dexfile, "rb");
	if (input == NULL) {
		fprintf(stderr, "ERROR: Can't open dex file!\n");
		perror(dexfile);
		exit(1);
	}
    while ((c = getopt(argc, argv, "s")) != -1) {
                switch(c) {
            case 's':
                SILENCE =-2 ;
                break;
            default:
                     help_show_message(argv[0]);
                     return 1;
                }
        }
    if (SILENCE>0)
    {
	printf ("\n=== androsoo %s - (c) 2014 Hugo Gonzalez @hugo_glez\n", VERSION);
    printf( "Paper: Exploring reverse engineering symptoms in Android apps\n");
    printf ("EuroSec '15 Proceedings of the Eighth European Workshop on System Security\n");
    printf ("http://dx.doi.org/10.1145/2751323.2751330\n===\n");
    }


    // Obtain the size of the file
    int fd = fileno(input);
    struct stat buffs;
    fstat(fd,&buffs);
    int filesize = buffs.st_size;

    // allocate memory, load all the file in memory
    fileinmemory = malloc(filesize*sizeof(u1));
    if (fileinmemory == NULL) {
        fprintf(stderr, "ERROR: Can't allocate memory!\n");
    }
	fread(fileinmemory,1,filesize,input); // file in memory contains the binary
    fclose(input);


	/* print dex header information */

    header = (struct dex_header *)fileinmemory;

	 if ((strncmp(header->magic.dex,"dex",3) != 0) || 
	     (strncmp(header->magic.newline,"\n",1) != 0) || 
	     (strncmp(header->magic.zero,"\0",1) != 0 ) ) {
		fprintf (stderr, "ERROR: not a dex file\n");
		fclose(input);
		exit(1);
	    }

	if (strncmp(header->magic.ver,"035",3) != 0) {
		if (SILENCE) fprintf (stderr,"Warning: Dex file version != 035\n");
	}

	if (*header->header_size != 0x70) {
		if (SILENCE) fprintf (stderr,"Warning: Header size != 0x70\n");
	}

	if (*header->endian_tag != 0x12345678) {
		if (SILENCE) fprintf (stderr,"Warning: Endian tag != 0x12345678\n");
	}

    u2 strptr = sizeof(string_id_struct);
    
    u4 oldvalue = 0;
	for (i= 0; i < *header->string_ids_size; i++) {
        string_id_list = (struct string_id_struct *) (fileinmemory + *header->string_ids_off + strptr * i); 
		//printf("%d : ", *string_id_list->string_data_off); 
        if (oldvalue > *string_id_list->string_data_off)
        {
            printf("String offset not in order: %s\n", dexfile);
	        free(fileinmemory);
            return 0;
        }
        oldvalue = *string_id_list->string_data_off;
	}
    if (SILENCE>0) printf ("String offset IN order: %s\n",dexfile);

	free(fileinmemory);
	return 0;
}
