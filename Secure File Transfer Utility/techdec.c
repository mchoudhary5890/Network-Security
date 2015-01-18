#include <fcntl.h>
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), bind(), and connect() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() and access()*/
#include <gcrypt.h>

#define ALGO GCRY_CIPHER_AES128 
#define MODE GCRY_CIPHER_MODE_CBC
#define HASH GCRY_MD_SHA512
#define KDF GCRY_KDF_PBKDF2
#define HMACFLAG GCRY_MD_FLAG_HMAC

char * generateKey(size_t); /* Function for Key Generation */
char* append(char *, char *, size_t *, size_t); /* Appends one string to another */
char * getCipherText(char *, size_t*); /* to read cipher text from file in case of local mode */
char* verifyMAC(char *, char *, size_t, size_t, size_t); /* Generates and verifies the MAC with the MAC appended in Cipher */
char intToHex[] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf}; /* For padding related coversion */

int main(int argc, char* argv[]) 
{
	if (!gcry_check_version(GCRYPT_VERSION))
         {
           printf("libgcrypt Version Mismatch");
           exit(1);
         }
   	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
   	gcry_control(GCRYCTL_INIT_SECMEM, 1,0);
   	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
   	gcry_control(GCRYCTL_INITIALIZATION_FINISHED,0);
	int isLocal = 0;
	if(argc < 3)
	{
		printf("Usage: %s < input file > [-d <port>][-l] \n", argv[0]);
		exit(0);
	}
	if(strcmp(argv[2],"-l") == 0)
		isLocal = 1;
	else if(strcmp(argv[2],"-d") != 0 || (!argv[3]))
	{
		printf("Usage: %s < input file > [-d <port>][-l] \n", argv[0]);
		exit(0);
	}
	gcry_cipher_hd_t gcryHd;
        gcry_error_t gcryErr;
	size_t keySize = gcry_cipher_get_algo_keylen(ALGO); /* ALGO Key Length */
        size_t blkSize = gcry_cipher_get_algo_blklen(ALGO); /* AlGO block length */
	size_t i, encTxtLength = 0, cipherLength = 0;
	int padMismatch = 0, searchIndex = 0, execResult;
	char * encBuffer = NULL; /* Holds cipher */
        char * outBuffer = NULL; /* Holds generated plain text */
        int iniVtr = 5844; /* IV for the CBC mode */
	size_t macSize = 64; /* MAC size is 64 bytes for SHA512 */
	char *filename = argv[1]; /* Pointer to filename passed as command line input */
	char *keyBuffer = generateKey(keySize);	 /* Get the key */
	if(!keyBuffer)
	{
		printf("Key generation failed.\n");
		exit(1);
	}
	gcryErr = gcry_cipher_open(&gcryHd,ALGO, MODE, 0); /* Creates Context */
	if (gcryErr)
    	{
               printf("gcry_cipher_open(): FAILED\n");
      	       exit(1);
        }	
	gcryErr = gcry_cipher_setkey(gcryHd, keyBuffer, keySize); /* Sets key for the context */
        if (gcryErr)
        {
             printf("gcry_cipher_setkey() : FAILED\n");
	     exit(1);
        }
	gcryErr = gcry_cipher_setiv(gcryHd, (void *)&iniVtr, sizeof(int)); /* Sets IV for the context. Length passed is sizeof(int) */
        if (gcryErr)
        {
               printf("gcry_cipher_setiv() : FAILED\n");
               exit(1);
        }
	/*
	If local, reads the content from the INPUT file and modifies the filename to get OUTPUT file name.
	*/
	if(isLocal)
	{
		encBuffer = getCipherText(argv[1], &cipherLength);
		if(!encBuffer)	
		{
			printf("Source File doesn't exist\n");
			exit(33);
		}
		filename[strlen(filename)-3] = '\0';
	}
	/* Check if output file is already present */
	if( access(filename, F_OK) != -1 )
	{
		printf("The output file already exists.\n");
		free(keyBuffer);
		free(encBuffer);		
		exit(33);
	} 
	/* Open the output file. 
	If successful, output file would contain plain text.
	Else it would have some error messages.
	*/
	FILE* ostream = fopen(filename, "wb");
	if(!ostream)
	{
		printf("Error while Creating Output file\n");
		free(keyBuffer);
		free(encBuffer);		
		exit(33);
	}	
	if(!isLocal)
	{
		/*
		If not local, network Daemon has to be created to run in as a background process. 
		*/
		pid_t processID, sessionID; /* Process ID and Session ID */
		processID = fork(); /* Fork off the parent process */
		if (processID < 0) /* Fork Failed */
			exit(1); /* Exit with error */
		if (processID > 0)
			exit(0); /* Exit the parent process */
		umask(0); /* Change the file mode mask */
		FILE *stream = fopen("log.txt", "wb"); /* A log file to enter activity log */
		fprintf(stream, "Log File Start\n");
		sessionID = setsid(); /* New SID for the child process */
		if (sessionID < 0) 
		{
			fprintf(stream, "setsid() : FAILED\n");
			exit(1);
		}
		fprintf(stream, "setsid() : PASSED\n");	
		if ((chdir("/")) < 0) /* Change the current working directory */
		{
			fprintf(stream, "chdir() : FAILED\n");
			exit(1);
		}
		fprintf(stream, "chdir() : PASSED\n");	
		/* Close the standard file descriptors */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		fprintf(stream, "Starting Server Initialization\n");
		int localSockfd; /* Local Sock Identifier*/
		int remoteSockfd;  /* Remote Sock Identifier*/
		int remoteSinSize = sizeof(struct sockaddr_in);
		struct sockaddr_in remoteAddr;
		struct sockaddr_in localAddr; /* Built-in structure to hold local Address */
		int backLog = 5, positive = 1; /* Backlog queue can hold 5 requests */
		size_t readBufferSize = 16; /* Size of buffer read at once using socket */
		char* receivedBuffer = malloc(sizeof(char)*readBufferSize);/* Buffer to hold content of one read operation */
		size_t receivedLength = 0; /* total length of the content received */
		unsigned short localPort = atoi(argv[3]); /* Local port value passed by user */
		fprintf(stream, "local Port: %d\n", localPort);
		/* PF_INET - IP Protocol Family(socket.h) | SOCK_STREAM - Reliable, Sequenced and connection oriented Byte Stream(socket.h)
		IPPROTO_TCP - Protocol in the Protocol Family
		*/
		localSockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); /* Create socket */
		if (localSockfd == -1)
		{
			fprintf(stream, "local socket(): FAILED\n");
			return 1;
		}
		else fprintf(stream, "local socket(): PASSED\n");
		/* Allow Reusing a given address for binding - deals with sockets closed improperly */	
		if (setsockopt(localSockfd, SOL_SOCKET, SO_REUSEADDR, &positive, sizeof(int)) == -1)
			fprintf(stream, "setsockopt(): FAILED\n");
		else	
			fprintf(stream, "setsockopt() : PASSED\n");   
		/* Constructing the address structure for the local Machine
		   Socket Address Structure Defined in netinet/in.h
		*/
    		localAddr.sin_family = AF_INET;                
    		localAddr.sin_addr.s_addr = 0; 
    		localAddr.sin_port = htons(localPort); 
		memset(&(localAddr.sin_zero), '\0', 8); /* Zero the rest of the struct */
		/* bind the address to the socket identified by localSockfd */
		if (bind(localSockfd, (struct sockaddr *) &localAddr, sizeof(localAddr)) == -1)
        	{
			fprintf(stream, "bind(): FAILED\n");
			fprintf(stream, "Exiting\n");
			return 1;
		}
		fprintf(stream,"bind() : PASSED\n");
		/* Listen on the socket */		
		if (listen(localSockfd, backLog) == -1)
		{
			fprintf(stream, "listen(): FAILED\n");
			return 1;
		}
		fprintf(stream, "listen() : PASSED\n");
		fflush(stream);
		/* Accepts the incoming Request */
		remoteSockfd = accept(localSockfd, (struct sockaddr *) &remoteAddr, &remoteSinSize);
		if (remoteSockfd == -1)
           	{
			fprintf(stream, "accept(): FAILED\n");	
			fflush(stream);		
			return 1;
		}
		fprintf(stream, "accept() : PASSED\n");
	 	fprintf(stream, "Accepted the Connection from %s:%d\n", inet_ntoa(remoteAddr.sin_addr), ntohs(remoteAddr.sin_port));
		fflush(stream);
		/* Read whole content from the socket in chucks of 16 bytes 
		   Append the chuck to the encBuffer
		*/
		do
		{		
			receivedLength = read(remoteSockfd, receivedBuffer, readBufferSize);
			if(receivedLength == 0)
				fprintf(stream, "Read from socket completed\n");
			else if(receivedLength < 0)
				fprintf(stream, "Error while Reading from socket. Terminating..\n");
			else
			{
				fprintf(stream, "Received %d bytes\n", receivedLength);
				encBuffer = append(encBuffer, receivedBuffer, &cipherLength, receivedLength);
			}			
			fflush(stream);
		}while(receivedLength > 0);
		fprintf(stream, "Cipher Received= ");
		for (i = 0; i<cipherLength; i++)
			fprintf(stream, "%02X", (unsigned char)encBuffer[i]);
    		fprintf(stream, "\n");		
		/* Socket related clean up*/		
		close(remoteSockfd);
		close(localSockfd);
		free(receivedBuffer);
		fclose(stream);
	}
	/* Common Code: For both '-l' and '-d' */
	encTxtLength = cipherLength-macSize;
	/* Verify the MAC and throws exits with error code 62 in case the verification fails */
	if(encBuffer = verifyMAC(encBuffer, keyBuffer, keySize, cipherLength, macSize))
	{
		outBuffer = (char *)malloc(sizeof(char)*encTxtLength);
	}
	else
	{
		fprintf(ostream, "Sorry, Content not available. HMAC FAILED\n"); 	
		exit(62);
	}
	gcryErr = gcry_cipher_decrypt(gcryHd, outBuffer, encTxtLength, encBuffer, encTxtLength); /* Decrypts if verification passes */
	if (gcryErr)
        {
		fprintf(ostream, "gcry_cipher_decrypt() : FAILED");
		fprintf(ostream, "gcry_cipher_decrypt failed:  %s/%s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
		return 1;
        }
	gcry_cipher_close (gcryHd);
	/* Below: Padding related work
	Get the last byte.check if the the 'byte' number of bytes(at the end) are equal to the last byte. If equal, remove the pad and write 		in the file.
	*/
	char lastByte = outBuffer[encTxtLength-1];	
	for(i=0;i<16;i++)
	{
		if(intToHex[i]==lastByte)
			break;
	}
	if(i<16)
	{	
		searchIndex = encTxtLength-i;
		while(searchIndex < encTxtLength)
		{
			if(outBuffer[searchIndex++] != lastByte)
			{
				padMismatch = 1;
				break;
			}
		}
		if(padMismatch)
			fwrite(outBuffer, encTxtLength, 1, ostream);
		else
			fwrite(outBuffer, encTxtLength-i, 1, ostream);
	}
	else
		fwrite(outBuffer, encTxtLength, 1, ostream);
	/* Clean Up */
	fclose(ostream);
	free(encBuffer);
	free(keyBuffer);
	free(outBuffer);
	exit(0);
}

/*******************************************************************************************************
Extracts the MAC from the cipher.
Generated MAC on the cipher text(after removing MAC).
Verifies that the generated MAC is equal to the extracted one.
*/
char* verifyMAC(char *totalBuffer, char *keyBuffer, size_t keySize, size_t totalBufferSize, size_t macSize)
{
	size_t cipherSize = totalBufferSize - macSize;
	char *cipherText = (char *)malloc(cipherSize*sizeof(char));
	char *expectedMAC = (char *)malloc(macSize*sizeof(char));
	memmove( cipherText, totalBuffer, cipherSize);
	memmove(expectedMAC, totalBuffer+cipherSize, macSize);
	free(totalBuffer);
	int i;
	char * macBuffer = malloc(sizeof(char)*macSize);
	gcry_error_t gcryErr;
	gcry_md_hd_t gcryMacHd;
	gcryErr = gcry_md_open(&gcryMacHd, HASH,HMACFLAG);
	if(gcryErr)
		return NULL;
	gcryErr = gcry_md_setkey(gcryMacHd, keyBuffer, keySize);
	if(gcryErr)
		return NULL;
	gcry_md_write(gcryMacHd, cipherText, cipherSize);
	memcpy(macBuffer, gcry_md_read (gcryMacHd, 0), macSize);
	if(!macBuffer)
		return NULL;
	gcry_md_close(gcryMacHd);
	if(memcmp(macBuffer,expectedMAC,macSize) == 0)
		return cipherText;
	else return NULL;
}

/***************************************************************************************/

char* append(char *appendTo, char *appendIt, size_t *appendToSize, size_t appendItSize)
{
	appendTo = realloc( appendTo, (*appendToSize) + appendItSize);
   	memmove( appendTo + (*appendToSize), appendIt, appendItSize);
	*appendToSize = (*appendToSize) + appendItSize;	
	return appendTo;
}


/***************************************************************************************
Function to generate key using the ley derivation fucntion.
Salt: NaCl
Iterations: 4096
*/
char * generateKey(size_t keySize)
{
	gcry_error_t gcryErr;
	char *kdfSalt = "NaCl"; 
	char passPhrase[50];
        char *keyBuffer = malloc((sizeof(char))*keySize);
 	int iterations = 4096;
	size_t i;

	printf("Enter the password:\n");
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
		printf("Problem with password. Try again!!\n");
		return NULL;
	}
	gcryErr = gcry_kdf_derive (passPhrase, strlen(passPhrase), KDF, HASH, kdfSalt, strlen(kdfSalt), iterations, keySize, keyBuffer);
	if (gcryErr)
		return NULL;
        printf("Key = ");
    	for (i = 0; i<keySize; i++)
        	printf("%02X ", (unsigned char)keyBuffer[i]);
    	printf("\n");
	return keyBuffer;
}

/**************************************************************************************************
function to read the cipher text from the file in case of local mode.
*/
char * getCipherText(char *filename, size_t* cipherLength)
{
	char *contents;
	FILE *stream = fopen(filename, "rb");
	if(!stream)
		return NULL;
	fseek(stream, 0L, SEEK_END);
	*cipherLength = ftell(stream);
	fseek(stream, 0L, SEEK_SET);
	contents = (char *)malloc((*cipherLength)*sizeof(char));
	fread(contents,*cipherLength,1,stream);
	fclose(stream);	
	return contents;
}
