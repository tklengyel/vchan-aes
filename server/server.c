/**
 * Xen AES server implementation using inter-domain communication channels.
 *
 * Tamas K Lengyel (tamas.k.lengyel@tum.de) 2014
 * TU Munich
 *
 * Based on AES encryption/decryption demo program using OpenSSL EVP apis
 * by Saju Pillai (saju.pillai@gmail.com) (code in public domain)
 * http://saju.net.in/code/misc/openssl_aes.c.txt
 **/

#include <config.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

#include <libxenvchan.h>
#include <xenstore.h>

#define ENCRYPT_MODE 0
#define DECRYPT_MODE 1

static const char* mode_strings[] = { [ENCRYPT_MODE] = "Encrypt", [DECRYPT_MODE
		] = "Decrypt" };

/* 8 bytes to salt the key_data during key generation. This is an example of
 compiled in salt. We just read the bit pattern created by these two 4 byte
 integers on the stack as 64 bits of contigous salt material -
 of course this only works if sizeof(int) >= 4 */
static unsigned int salt[] = { 12345, 54321 };

/* "opaque" encryption, decryption ctx structures that libcrypto uses to record
 status of enc/dec operations */
static EVP_CIPHER_CTX en, de;

/* Xen vchan structures used for inter-domain communication **/
static struct libxenvchan *vchan_en_in, *vchan_en_out, *vchan_de_in,
		*vchan_de_out;

/* Xenstore handle */
static struct xs_handle *xs;

/* Threads for encryption/decryption */
static pthread_t thread_en, thread_de;

/* The domain ID we are running in */
static int my_domid;

/* Interrupt handler */
static int interrupted;
static void close_handler(int sig) {
	interrupted = sig;
}

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
		EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data,
			key_data_len, nrounds, key, iv);
	if (i != 32) {
		printf("Key size is %d bits - should be 256 bits\n", i);
		return 0;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return 1;
}

void aes_finish() {
	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext,
		int *len) {
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	 *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext,
		int *len) {
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}

/* Initialize channels for encryption and decryption */
int vchan_init(int peer_domid) {

	int ret = 1;

	char *xenstore_encrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/encrypt/%i/in") + 1);
	sprintf(xenstore_encrypt_path, "/vtpm/aes/encrypt/%i/in", peer_domid);
	vchan_en_in = libxenvchan_server_init(NULL, peer_domid,
			xenstore_encrypt_path, 0, 0);
	free(xenstore_encrypt_path);

	if (!vchan_en_in) {
		printf("Failed to init encryption channel!\n");
		ret = 0;
		goto done;
	}

	xenstore_encrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/encrypt/%i/out") + 1);
	sprintf(xenstore_encrypt_path, "/vtpm/aes/encrypt/%i/out", peer_domid);
	vchan_en_out = libxenvchan_server_init(NULL, peer_domid,
			xenstore_encrypt_path, 0, 0);
	free(xenstore_encrypt_path);

	if (!vchan_en_out) {
		printf("Failed to init encryption channel!\n");
		ret = 0;
		goto done;
	}

	// Set channel to blocking
	vchan_en_in->blocking = 1;
	vchan_en_in->server_persist = 1;
	vchan_en_out->blocking = 1;
	vchan_en_out->server_persist = 1;

	//printf("Encryption channel opened for peer domain %i\n", peer_domid);
	//printf("\tEvent port: %u\n", vchan_en->event_port);

	char *xenstore_decrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/decrypt/%i/in") + 1);
	sprintf(xenstore_decrypt_path, "/vtpm/aes/decrypt/%i/in", peer_domid);
	vchan_de_in = libxenvchan_server_init(NULL, peer_domid,
			xenstore_decrypt_path, 0, 0);
	free(xenstore_decrypt_path);

	if (!vchan_de_in) {
		printf("Failed to init decryption channel!\n");
		ret = 0;
		goto done;
	}

	xenstore_decrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/decrypt/%i/out") + 1);
	sprintf(xenstore_decrypt_path, "/vtpm/aes/decrypt/%i/out", peer_domid);
	vchan_de_out = libxenvchan_server_init(NULL, peer_domid,
			xenstore_decrypt_path, 0, 0);
	free(xenstore_decrypt_path);

	if (!vchan_de_out) {
		printf("Failed to init decryption channel!\n");
		ret = 0;
		goto done;
	}

	// Set channel to blocking
	vchan_de_in->blocking = 1;
	vchan_de_in->server_persist = 1;
	vchan_de_out->blocking = 1;
	vchan_de_out->server_persist = 1;

	//printf("Decryption channel opened for peer domain %i\n", peer_domid);
	//printf("\tEvent port: %u\n", vchan_de->event_port);

	// Save the server's domid into Xenstore
	xs_transaction_t th;
	char *domid_str = malloc(snprintf(NULL, 0, "%i", my_domid) + 1);
	sprintf(domid_str, "%i", my_domid);
	if (!xs_write(xs, th, "/vtpm/aes/server_domid", domid_str,
			strlen(domid_str))) {
		printf("Failed to save server domid into Xenstore\n");
		ret = 0;
	}
	free(domid_str);

	done: return ret;
}

void vchan_finish() {
	if (vchan_en_in) {
		libxenvchan_close(vchan_en_in);
	}
	if (vchan_en_out) {
		libxenvchan_close(vchan_en_out);
	}
	if (vchan_de_in) {
		libxenvchan_close(vchan_de_in);
	}
	if (vchan_de_out) {
		libxenvchan_close(vchan_de_out);
	}
}

void *server_thread(void *input) {

	int mode = *(int *) input;
	struct libxenvchan *vchan_in, *vchan_out;

	if (mode == ENCRYPT_MODE) {
		vchan_in = vchan_en_in;
		vchan_out = vchan_en_out;
	} else if (mode == DECRYPT_MODE) {
		vchan_in = vchan_de_in;
		vchan_out = vchan_de_out;
	}

	printf("Starting AES %s Server\n", mode_strings[mode]);

	while (!interrupted) {
		unsigned char buffer[4096];
		memset(buffer, 0, 4096);
		int size = 0, sent = 0;

		size = libxenvchan_read(vchan_in, buffer, 4096);
		if (size > 0) {

			unsigned char *newtext = NULL;

			if (ENCRYPT_MODE == mode) {
				printf("Received '%s' for encryption\n", buffer);
				newtext = aes_encrypt(&en, buffer, &size);
			} else {
				printf("Received '%s' for decryption\n", buffer);
				newtext = aes_decrypt(&de, buffer, &size);
			}

			while (sent < size && !interrupted) {
				printf("Sending result: '%s'.\n", newtext);
				int rc = libxenvchan_write(vchan_out, newtext + sent,
						size - sent);
				if (rc > 0) {
					sent += rc;
				} else {
					printf("Error\n");
					break;
				}
			}
		}

	}

	printf("Stopping AES %s Server\n", mode_strings[mode]);

	pthread_exit(NULL);
	return NULL;
}

void init_my_domid() {
	xs_transaction_t th;

	int size = 0;
	char* id = xs_read(xs, th, "domid", &size);
	if (size <= 0 || !id) {
		printf("Failed to access xenstore\n");
		return;
	}

	my_domid = atoi(id);
	free(id);

	printf("My domain ID is %i\n", my_domid);
}

int xenstore_init() {
	xs = xs_open(0);
	if (!xs) {
		return 0;
	}

	return 1;
}

void xenstore_close() {
	if (xs) {
		xs_close(xs);
		xs = NULL;
	}
}

void usage(char **argv) {
	printf("%s <encryption_key> <peer domain ID>\n", argv[0]);
}

int main(int argc, char **argv) {

	int ret = 0;
	interrupted = 0;

	if (argc < 3) {
		usage(argv);
		goto done;
	}

	if (!aes_init(argv[1], strlen(argv[1]), (unsigned char *) &salt, &en,
			&de)) {
		printf("Couldn't initialize AES cipher\n");
		ret = -1;
		goto done;
	}

	if (!xenstore_init()) {
		printf("Failed to open Xenstore!\n");
		ret = -1;
		goto done;
	}

	init_my_domid();

	// TODO: pass peer domain id through xenstore
	if (!vchan_init(atoi(argv[2]))) {
		printf(
				"Couldn't initialize Xen inter-domain communication channel (vchan)\n");
		ret = -1;
		goto done;
	}

	/* for a clean exit */
	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	int encrypt_mode = ENCRYPT_MODE;
	int decrypt_mode = DECRYPT_MODE;

	pthread_create(&thread_en, NULL, server_thread, &encrypt_mode);
	pthread_create(&thread_de, NULL, server_thread, &decrypt_mode);
	pthread_join(thread_en, NULL);
	pthread_join(thread_de, NULL);

	vchan_finish();
	xenstore_close();
	aes_finish();

	done: return ret;
}
