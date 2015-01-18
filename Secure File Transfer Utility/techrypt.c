#include <gcrypt.h>     /* for Encyption and Authentication routines */
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), bind(), and connect() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close(), access() */

#define ALGO GCRY_CIPHER_AES128 
#define MODE GCRY_CIPHER_MODE_CBC
#define HASH GCRY_MD_SHA512
#define KDF GCRY_KDF_PBKDF2 /* Key Derivation Function */
#define HMACFLAG GCRY_MD_FLAG_HMAC /* FLAG to use SHA512 as HMAC */


char * getPlainText(char *, int *);   /* Function to fetch the plain text from the input file */
int writeCipher(char *, char *, size_t); /* Function to write cipher in output file(if used in local mode) */
char * generateKey(size_t); /* Function to generate key using key derivation function */
char * computeMAC(char *, char *, size_t, size_t, size_t); /* Function to compute the MAC on cipher text */
char* prepend(char *, char *, size_t, size_t); /*Function to prepend one string to another */
char* append(char *, char *, size_t, size_t); /*Function to append one string to another */
char intToHex[] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe, 0xf}; /* Conversion useful for Padding related work */

/******************************************************************************
			MAIN FUNCTION 
*/
int main(int argc, char* argv[])
{
	if (!gcry_check_version(GCRYPT_VERSION)) /* Library Initialization */
         {
           printf("libgcrypt Version Mismatch");
           exit(1);
         }
   	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN); /* Suspending secure memory related warning messages */
   	gcry_control(GCRYCTL_INIT_SECMEM, 1,0); /* Initializing secure memory of default bytes (16384 bytes)*/
   	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);  /* Resuming secure memory related warning messages */
   	gcry_control(GCRYCTL_INITIALIZATION_FINISHED,0); /* initialization finished */
	int isLocal = 0;
	if(argc < 3)
	{
		printf("Usage: %s < input file > [-d < IP-addr:port >][-l] \n", argv[0]);
		return 0;
	}
	if(strcmp(argv[2],"-l") == 0)
		isLocal = 1;
	else if(strcmp(argv[2],"-d") != 0 || (!argv[3]))
	{
		printf("Usage: %s < input file > [-d < IP-addr:port >][-l] \n", argv[0]);
		return 0;
	}
	gcry_cipher_hd_t gcryHd;
        gcry_error_t gcryErr;
	size_t keySize = gcry_cipher_get_algo_keylen(ALGO); /* Get the algo key size */
        size_t blkSize = gcry_cipher_get_algo_blklen(ALGO); /* Get the algo block size */
	size_t i,totalBufferSize, txtLength=0;
	size_t macSize = 64;
	int execResult, writeStatus, iniVtr = 5844;
	char * txtBuffer = getPlainText(argv[1], &txtLength); /* Get the plain text in buffer */
	if(!txtBuffer)
	{
		printf("getPlainText(): FAILED\n");
		exit(1);
	}
        char * encBuffer = malloc(txtLength*sizeof(char)); /* allocate memory for cipher text */
	char *keyBuffer = generateKey(keySize); /* Get the key based on the password */
	char *macBuffer = NULL; /* Apointer to point to the HMAC buffer later */
	if(!keyBuffer) 
	{	
		printf("generateKey() : FAILED\n");
		exit(1);
	}
	gcryErr = gcry_cipher_open(&gcryHd,ALGO, MODE, 0); /* Creating Context */
	if (gcryErr)
    	{
               printf("gcry_cipher_open(): FAILED\n");
      	       exit(1);
        }
	gcryErr = gcry_cipher_setkey(gcryHd, keyBuffer, keySize); /* Setting key for the context */
        if (gcryErr)
        {
             printf("gcry_cipher_setkey() : FAILED\n");
	     exit(1);
        }

	/* Setting IV for the context
           Length is the sizeof(int) as this parameter takes the length of the IV passed. 
	   It throws a warning but works fine. On setting it to blocksize, the encryption/decryption fails.		
	*/	
	gcryErr = gcry_cipher_setiv(gcryHd, (void *)&iniVtr, sizeof(int)); 
        if (gcryErr)
        {
               printf("gcry_cipher_setiv() : FAILED\n");
               exit(1);
        }
	gcryErr = gcry_cipher_encrypt(gcryHd, encBuffer,txtLength, txtBuffer,txtLength); /* Encrypt the plain text */
    	if (gcryErr)
        {
               printf("gcry_cipher_encrypt() : FAILED\n");
	       printf("gcry_cipher_encrypt failed:  %s \t %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
               exit(1);
        }
	macBuffer = computeMAC(encBuffer, keyBuffer, keySize, txtLength, macSize); /* Compute HMAC on the cipher text */	
	if(!macBuffer)
	{	
		printf("Problem while generating MAC\n");
    		exit(1);
	}
	encBuffer = append(encBuffer, macBuffer, txtLength, macSize); /* Appends the MAC to the cipher text */
	totalBufferSize = txtLength+macSize;
	/*
	If it is used locally, writes to the output file. It exits with error code 33 in case the output file already exits.
	with option '-d', tranfers the file using the function transferFile.
	*/
	if(isLocal)
	{	writeStatus = writeCipher(argv[1], encBuffer, totalBufferSize);
		if (writeStatus == -1)
		{
			printf("Cipher Write Operation : Failed. Destination file exists already\n");
			exit(33);
		}
		else if (writeStatus == 1)
			printf("Encrypted File Written Successfully.\n");
		else 
			printf("Problem while writing the file.\n");
	}
	else
	{
		if(transferFile(argv[3], encBuffer, totalBufferSize) == 1)
			printf("File Transferred Successfully.\n");
		else
			printf("File transfer failed\n");
	}
	/* clean up */
	gcry_cipher_close (gcryHd);
	free(encBuffer);
	free(keyBuffer);
	free(macBuffer);
	exit(0);
}

/************************************************************************************
	Function to transfer file to the remote machine
*/
int transferFile(char *address, char *message, size_t totalBufferSize)
{
	char *remoteIP = strtok(address, ":");/* Remote Machine's IP address*/
	unsigned short remotePort = atoi(strtok(NULL, ":")); /* Remote Machine's Port */
	int sockfd;                      /* Socket Descriptor */
        struct sockaddr_in remoteAddr; /* Remote Machine's Address */              
	int positive = 1;
	printf("Transferring file to remote IP : %s and remote port: %d\n", remoteIP, remotePort);
	size_t bytesWritten = 0;
	/* PF_INET - IP Protocol Family(socket.h) | SOCK_STREAM - Reliable, Sequenced and connection oriented Byte Stream(socket.h)
	IPPROTO_TCP - Protocol in the Protocol Family
	*/
	if ((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	{
		printf("socket(): FAILED\n");
		return -1;
	}
	/* Allow Reusing a given address for binding - deals with sockets closed improperly */	
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &positive, sizeof(int)) == -1)
	{
		printf("setsockopt(): FAILED\n");
		return -1;
	}
	/* Constructing the address structure for the Remote Machine
	   Socket Address Structure Defined in netinet/in.h
	*/
    	memset(&remoteAddr, 0, sizeof(remoteAddr));
    	remoteAddr.sin_family      = AF_INET;             /* Address Family Corresponding to IP Protocol Family*/
    	remoteAddr.sin_addr.s_addr = inet_addr(remoteIP);   /* Remote Machine's IP address */
    	remoteAddr.sin_port        = htons(remotePort); /* Remote Machine's Port - htons for host to network byte order conversion*/
	/* Establish Connection to Remote Machine */
    	if (connect(sockfd, (struct sockaddr *) &remoteAddr, sizeof(struct sockaddr)) == -1)
        {
		printf("connect(): FAILED\n");
		return -1;
	}
	/* Write to the Socket */
	bytesWritten = write(sockfd, message, totalBufferSize);
	printf("%d bytes have been written.\n", bytesWritten);
	close(sockfd);
	return 1;

}

/**********************************************************************************************/
char* prepend(char *prependTo, char *prependIt, size_t sizeofPrependTo, size_t sizeofPrependIt)
{
	prependTo = realloc( prependTo, sizeofPrependTo + sizeofPrependIt);
   	memmove( prependTo + sizeofPrependIt, prependTo, sizeofPrependTo);
   	memmove( prependTo, prependIt,sizeofPrependIt);
	return prependTo;
}

/************************************************************************************************/
char* append(char *appendTo, char *appendIt, size_t txtLength, size_t macSize)
{
	appendTo = realloc( appendTo, txtLength + macSize);
   	memmove( appendTo + txtLength, appendIt, macSize);
	return appendTo;
}


/************************************************************************************************
	FUNCTION to compute HMAC on the cipher
*/
char * computeMAC(char *cipherText, char *keyBuffer, size_t keySize, size_t cipherSize, size_t macSize)
{
	int i;
	char * macBuffer = malloc(sizeof(char)*macSize); /* Allocating Buffer to hold MAC */
	gcry_error_t gcryErr;
	gcry_md_hd_t gcryMacHd;
	gcryErr = gcry_md_open(&gcryMacHd, HASH, HMACFLAG); /* Creating context HMAC flag */
	if(gcryErr)
	{
		printf("gcry_md_open() : FAILED\n");
		return NULL;
	}
	gcryErr = gcry_md_setkey(gcryMacHd, keyBuffer, keySize); /* Setting key for the context */
	if(gcryErr)
	{
		printf("gcry_md_setkey() : FAILED\n");
		return NULL;
	}
	gcry_md_write(gcryMacHd, cipherText, cipherSize); /* Generating MAC in secure memory */
	memcpy(macBuffer, gcry_md_read (gcryMacHd, 0), 64); /* Copying the MAC to macBuffer */
	if(!macBuffer)
	{
		printf("macBuffer is NULL");
		return NULL;
	}
	gcry_md_close(gcryMacHd);
	return macBuffer;
}

/**********************************************************************************************
	FUNCTION to generate the key based on the password
*/
char * generateKey(size_t keySize)
{
	gcry_error_t gcryErr;
	char *kdfSalt = "NaCl"; 
	char passPhrase[50];
        char *keyBuffer = malloc((sizeof(char))*keySize); /* Allcation for key */
 	int iterations = 4096; 
	size_t i;

	printf("Enter the Password:\n");
	if ( fgets(passPhrase, sizeof(passPhrase), stdin) != NULL )
   	{
      		char *newline = strchr(passPhrase, '\n'); /* search for newline character */
      		if (newline != NULL)
      		{
         		*newline = '\0'; /* overwrite trailing newline */
      		}
   	}
	else
	{
		printf("Problem in reading password. Try again\n");
		return NULL;
	}
	gcryErr = gcry_kdf_derive (passPhrase, strlen(passPhrase), KDF, HASH, kdfSalt, strlen(kdfSalt), iterations, keySize, keyBuffer);
	if (gcryErr)
	{
		printf("gcry_kdf_derive(): FAILED");
		return NULL;
	}
        printf("Key = ");
    	for (i = 0; i<keySize; i++)
        	printf("%02X ", (unsigned char)keyBuffer[i]);
    	printf("\n");
	return keyBuffer;
}

/************************************************************************************************
getPlainText checks the size of the file, finds te number of bytes to be padded,
Allocates the buffer with file size + padsize,
Reads the file content in memory.
Pads it with the repeated HEX value of number of bytes in the pad.
The array intToHex is used for simple conversion.
Array has value till 15 only because we are check for block size of 16. So maximum pad can be of 15 bytes.
*/
char * getPlainText(char *filename, int *bufferSize)
{
	char *contents;
	int remainder=0, bytes=0, count =0;
	size_t i, fileSize = 0, readSize = 0;
	FILE *stream = fopen(filename, "rb");
	if(!stream)
	{
		return NULL;
	}
	fseek(stream, 0L, SEEK_END);
	fileSize = ftell(stream);
	remainder = fileSize % 16;
	if(remainder != 0)
		bytes = 16 - remainder;
	*bufferSize = fileSize+bytes;
	fseek(stream, 0L, SEEK_SET);
	contents = (char *)malloc((*bufferSize)*sizeof(char));
	readSize = fread(contents,1,fileSize,stream);
	fclose(stream);	
	while(readSize<(*bufferSize))
	{
		count++;
		contents[readSize++] = intToHex[bytes];
	}
	return contents;
}

/*******************************************************************************************************
Function to write cipher text to the file <filename>.gt in case it is used in local mode.
Throws error in case the output file is already present.
*/
int writeCipher(char *filename, char *cipher, size_t cipherLength)
{	
	char *newFile = (char *)malloc(strlen(filename)+4);
	FILE *stream;
	strcpy(newFile, filename);
	strcat(newFile, ".gt");
	if( access(newFile, F_OK) != -1 )
		return -1; 
	printf("output file: %s\n", newFile);
	stream = fopen(newFile, "wb");
	if(stream)
	{
		fwrite(cipher, cipherLength, 1, stream);
		fclose(stream);
		return 1;
	}
	else
		return 0;
}
