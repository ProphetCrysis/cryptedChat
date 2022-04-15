/*	
	Copyright 2022 Alexey Khroponyuk (ProhetCrysis)

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	http ://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissionsand
	limitations under the License. 
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#ifdef _WINDOWS
#include <WinSock2.h>
#include <processthreadsapi.h>
#define THREAD_RET DWORD WINAPI
#define pthread_cancel CloseHandle
#define poll WSAPoll
#else
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#define closesocket close
#define SOCKET int
#define SD_BOTH SHUT_RDWR
#define THREAD_RET void*
#endif

#define CRYPTO_ALG EVP_aes_256_cbc()
#define NICKNAME_LENGTH 30
#define MESSAGE_LENGTH 64
#define DEFAULT_PORT 8888

uint8_t is_server = 0;
char address[22] = "";
uint8_t nickname[NICKNAME_LENGTH] = "";
SOCKET sock = 0;
SOCKET client = 0;
uint8_t* sessionKey = NULL;
size_t sessionKeyLength = 0;
uint8_t* IV = NULL;
uint32_t IVsize = 0;
EVP_CIPHER_CTX* decrypt = NULL;
EVP_CIPHER_CTX* encrypt = NULL;
uint8_t running = 1;
uint8_t receiving = 0;
FILE* file = NULL;

THREAD_RET threadInput(void* args) {
	uint8_t msg[MESSAGE_LENGTH];
	while (running) {
		int s = scanf("%s", msg);
		uint8_t buff[MESSAGE_LENGTH + NICKNAME_LENGTH + 2];
		sprintf(buff, "%s: %s", nickname, msg);
		printf("%s\n", buff);
		uint8_t crypted[sizeof(buff)];
		int len = 0;
		EVP_EncryptInit(encrypt, CRYPTO_ALG, sessionKey, IV);
		if (msg[0] != '/') {
			EVP_EncryptUpdate(encrypt, crypted, &len, buff, sizeof(buff));
			send((is_server) ? client : sock, crypted, len, 0);
		}
		else {
			if (strstr(msg, "/stop")) running = 0;
			if (strstr(msg, "/recv")) {
				sprintf(buff, "%s ready accept file", nickname);
				EVP_EncryptUpdate(encrypt, crypted, &len, buff, sizeof(buff));
				send((is_server) ? client : sock, crypted, len, 0);
				receiving = 1;
				file = fopen(strchr(msg, '_') + 1, "wb");
			}
			if (strstr(msg, "/send")) {
				if ((file = fopen(strchr(msg, '_') + 1, "rb")) == NULL) printf("File doesn't exists!");
				else {
					fseek(file, 0, SEEK_END);
					long endFile = ftell(file);
					fseek(file, 0, SEEK_SET);
					long pos = 0;
					uint8_t readLen = 0;
					while (!feof(file)) {
						memset(buff, 0, sizeof(buff));
						readLen = fread(buff + 1, 1, sizeof(buff) - 1, file);
						buff[0] = readLen;
						pos += readLen;
						EVP_EncryptUpdate(encrypt, crypted, &len, buff, sizeof(buff));
						send((is_server) ? client : sock, crypted, len, 0);
						printf("%li / %li. %f\n", pos, endFile, (float)pos * 100.0f / (float)endFile);
						EVP_CIPHER_CTX_reset(encrypt);
						EVP_EncryptInit(encrypt, CRYPTO_ALG, sessionKey, IV);
					}
					fclose(file);
					sprintf(buff, "/end");
					EVP_EncryptUpdate(encrypt, crypted, &len, buff, sizeof(buff));
					send((is_server) ? client : sock, crypted, len, 0);
				}
			}
		}
		EVP_CIPHER_CTX_reset(encrypt);
	}
	return 0;
}

uint8_t CheckArgs(int argc, char* args[]) {
	if (argc < 2) {
		printf("Please, run program with argument -h(--help) to get information of using\n");
		return 1;
	}
	for (int i = 1; i < argc; i++) {
		if (!strcmp(args[i], "-h") || !strcmp(args[i], "--help")) {
			printf("Usage:\n\
CryptedChat <mode> <ip address>\n\
-c, --client - start program at client mode \n\
-s, --server - start program at server mode \n\
Example:\nCryptedChat --server 127.0.0.1:8888\n");
			return 1;
		}
		if (!strcmp(args[i], "-c") || !strcmp(args[i], "--client") || !strcmp(args[i], "-s") || !strcmp(args[i], "--server")) {
			if (i + 1 >= argc) {
				printf("Please, run program with argument -h(--help) to get information of using\n");
				return 1;
			}
			is_server = (!strcmp(args[i], "-s") || !strcmp(args[i], "--server"));
			memcpy(address, args[++i], sizeof(address));
		}
	}
	return 0;
}

int main(int argc, char* args[]) {
	if (CheckArgs(argc, args)) return 0;
	printf("Enter your nickname: ");
	while(!scanf("%s", nickname));
#ifdef _WINDOWS
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
		printf("Error code: %i\n", WSAGetLastError());
		return -1;
	}
#endif
	printf("Hello %s!\n", nickname);
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		printf("Error! Can't create socket\nError code: ");
#ifdef _WINDOWS
		printf("%i\n", WSAGetLastError());
#else
		printf("%i. %s\n", errno, strerror(errno));
#endif
		return -1;
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	char* colonPos = NULL;
	addr.sin_addr.s_addr = 0;
	if (colonPos = strchr(address, ':')) {
		addr.sin_port = htons((uint16_t)atoi(colonPos + 1));
		*colonPos = '\0';
}
	else addr.sin_port = htons(DEFAULT_PORT);
	addr.sin_addr.s_addr = inet_addr(address);
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
	EVP_PKEY* key = NULL;
	EVP_PKEY_keygen_init(ctx);
	EVP_PKEY_keygen(ctx, &key);
	EVP_PKEY_CTX_free(ctx);
	ctx = EVP_PKEY_CTX_new(key, NULL);
	if (is_server) {
		if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
			EVP_PKEY_free(key);
			EVP_PKEY_CTX_free(ctx);
			printf("Error! Can't bind socket\nError code: ");
#ifdef _WINDOWS
			printf("%i\n", WSAGetLastError());
#else
			printf("%i. %s\n", errno, strerror(errno));
#endif
			return -1;
		}
		if (listen(sock, 1) == -1) {
			EVP_PKEY_free(key);
			EVP_PKEY_CTX_free(ctx);
			printf("Error! Can't listen sock\nError code: ");
#ifdef _WINDOWS
			printf("%i\n", WSAGetLastError());
#else
			printf("%i. %s\n", errno, strerror(errno));
#endif
			return -1;
		}
		if ((client = accept(sock, NULL, NULL)) == -1) {
			EVP_PKEY_free(key);
			EVP_PKEY_CTX_free(ctx);
			printf("Error! Can't accept client\nError code: ");
#ifdef _WINDOWS
			printf("%i\n", WSAGetLastError());
#else
			printf("%i. %s\n", errno, strerror(errno));
#endif
			return -1;
		}
		size_t pubKeyLength = 0;
		EVP_PKEY_get_raw_public_key(key, NULL, &pubKeyLength);
		uint8_t* pubKey = malloc(pubKeyLength);
		if (pubKey) {
			pubKeyLength = recv(client, pubKey, pubKeyLength, 0);
			EVP_PKEY* secondKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pubKey, pubKeyLength);
			EVP_PKEY_derive_init(ctx);
			EVP_PKEY_derive_set_peer(ctx, secondKey);
			EVP_PKEY_derive(ctx, NULL, &sessionKeyLength);
			sessionKey = malloc(sessionKeyLength);
			EVP_PKEY_derive(ctx, sessionKey, &sessionKeyLength);
			EVP_PKEY_free(secondKey);
			EVP_PKEY_get_raw_public_key(key, pubKey, &pubKeyLength);
			send(client, pubKey, pubKeyLength, 0);
			free(pubKey);
		}
	}
	else {
		if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
			EVP_PKEY_free(key);
			EVP_PKEY_CTX_free(ctx);
			printf("Error! Can't connect\nError code: ");
#ifdef _WINDOWS
			printf("%i\n", WSAGetLastError());
#else
			printf("%i. %s\n", errno, strerror(errno));
#endif
			return -1;
		}
		size_t pubKeyLength = 0;
		EVP_PKEY_get_raw_public_key(key, NULL, &pubKeyLength);
		uint8_t* pubKey = malloc(pubKeyLength);
		if (pubKey) {
			EVP_PKEY_get_raw_public_key(key, pubKey, &pubKeyLength);
			send(sock, pubKey, pubKeyLength, 0);
			pubKeyLength = recv(sock, pubKey, pubKeyLength, 0);
			EVP_PKEY* secondKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pubKey, pubKeyLength);
			free(pubKey);
			EVP_PKEY_derive_init(ctx);
			EVP_PKEY_derive_set_peer(ctx, secondKey);
			EVP_PKEY_derive(ctx, NULL, &sessionKeyLength);
			sessionKey = malloc(sessionKeyLength);
			EVP_PKEY_derive(ctx, sessionKey, &sessionKeyLength);
			EVP_PKEY_free(secondKey);
		}
	}
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	encrypt = EVP_CIPHER_CTX_new();
	decrypt = EVP_CIPHER_CTX_new();
	IVsize = EVP_CIPHER_iv_length(CRYPTO_ALG);
	IV = calloc(IVsize, sizeof(uint8_t));
	EVP_EncryptInit(encrypt, CRYPTO_ALG, sessionKey, IV);
	EVP_DecryptInit(decrypt, CRYPTO_ALG, sessionKey, IV);
	if (IV) {
#ifdef _WINDOWS
		HANDLE thread = CreateThread(NULL, 0, threadInput, NULL, 0, 0);
#else
		pthread_t thread;
		pthread_create(&thread, NULL, threadInput, NULL);
#endif
		struct pollfd pfd;
		pfd.fd = (is_server) ? client : sock;
		pfd.events = POLLRDNORM;
		uint8_t msg[NICKNAME_LENGTH + MESSAGE_LENGTH + 2];
		uint8_t recvBuff[sizeof(msg)];
		int decodeMsgLen;
		int code = 0;
		while (running) {
			if ((code = poll(&pfd, 1, 100)) > 0) {
				int len = recv((is_server) ? client : sock, recvBuff, sizeof(recvBuff), 0);
				if (len <= 0) break;
				else {
					EVP_DecryptInit(decrypt, CRYPTO_ALG, sessionKey, IV);
					EVP_DecryptUpdate(decrypt, msg, &decodeMsgLen, recvBuff, len);
					if (!receiving) printf("%s\n", msg);
					else {
						if (strstr(msg, "/end")) {
							fclose(file);
							receiving = 0;
						}
						else {
							fwrite(msg + 1, 1, *msg, file);
						}
						char chr = 'n';
						send((is_server) ? client : sock, &chr, 1, 0);
					}
					EVP_CIPHER_CTX_reset(decrypt);
				}
			}
			else if (code < 0) break;
		}
		if (thread)
		pthread_cancel(thread);
		free(IV);
	}
	EVP_CIPHER_CTX_free(encrypt);
	EVP_CIPHER_CTX_free(decrypt);
	free(sessionKey);
	if (client != 0) {
		shutdown(client, SD_BOTH);
		closesocket(client);
	}
	shutdown(sock, SD_BOTH);
	closesocket(sock);
	return 0;
}