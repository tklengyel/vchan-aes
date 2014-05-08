/**
 * Xen AES client implementation using inter-domain communication channels.
 *
 * Tamas K Lengyel (tamas.k.lengyel@tum.de) 2014
 * TU Munich
 */

#include <config.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <libxenvchan.h>
#include <xenstore.h>

static struct xs_handle *xs;
static int my_domid;
static int server_domid;
static struct libxenvchan *vchan_en_in, *vchan_en_out, *vchan_de_in,
		*vchan_de_out;

/* Interrupt handler */
static int interrupted;
static void close_handler(int sig) {
	interrupted = sig;
}

int init_my_domid() {
	xs_transaction_t th;

	int size = 0;
	char* id = xs_read(xs, th, "domid", &size);
	if (size <= 0 || !id) {
		printf("Failed to access xenstore\n");
		return 0;
	}

	my_domid = atoi(id);
	free(id);

	printf("My domain ID is %i\n", my_domid);

	return 1;
}

int init_server_domid() {
	xs_transaction_t th;

	int size = 0;
	char* id = xs_read(xs, th, "/vtpm/aes/server_domid", &size);
	if (size <= 0 || !id) {
		printf(
				"Could not find vTPM AES server ID in Xenstore. Is the server running?\n");
		return 0;
	}

	server_domid = atoi(id);
	free(id);

	printf("vTPM AES server domID is: %i\n", server_domid);

	return 1;
}

int init_vchan() {
	int rc = 0, size = 0;

	char *xs_encrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/encrypt/%i/in", my_domid) + 1);
	sprintf(xs_encrypt_path, "/vtpm/aes/encrypt/%i/in", my_domid);
	vchan_en_in = libxenvchan_client_init(NULL, server_domid, xs_encrypt_path);
	free(xs_encrypt_path);

	if (!vchan_en_in) {
		printf("Failed to init encryption channel!\n");
		goto done;
	}

	xs_encrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/encrypt/%i/out", my_domid) + 1);
	sprintf(xs_encrypt_path, "/vtpm/aes/encrypt/%i/out", my_domid);
	vchan_en_out = libxenvchan_client_init(NULL, server_domid, xs_encrypt_path);
	free(xs_encrypt_path);

	if (!vchan_en_out) {
		printf("Failed to init encryption channel!\n");
		goto done;
	}

	vchan_en_in->blocking = 1;
	vchan_en_out->blocking = 1;

	char *xs_decrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/decrypt/%i/in", my_domid) + 1);
	sprintf(xs_encrypt_path, "/vtpm/aes/decrypt/%i/in", my_domid);
	vchan_de_in = libxenvchan_client_init(NULL, server_domid, xs_decrypt_path);
	free(xs_decrypt_path);

	if (!vchan_de_in) {
		printf("Failed to init decryption channel!\n");
		goto done;
	}

	xs_decrypt_path = malloc(
			snprintf(NULL, 0, "/vtpm/aes/decrypt/%i/out", my_domid) + 1);
	sprintf(xs_encrypt_path, "/vtpm/aes/decrypt/%i/out", my_domid);
	vchan_de_out = libxenvchan_client_init(NULL, server_domid, xs_decrypt_path);
	free(xs_decrypt_path);

	if (!vchan_de_out) {
		printf("Failed to init decryption channel!\n");
		goto done;
	}

	vchan_de_in->blocking=1;
	vchan_de_out->blocking=1;

	rc = 1;

	done: return rc;
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

int main(int argc, char **argv) {

	unsigned int rc = 0;
	/* for a clean exit */
	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	xs = xs_open(XS_OPEN_READONLY);
	if (!xs) {
		printf("Failed to open Xenstore!\n");
		goto done;
	}

	if (!init_my_domid()) {
		goto done;
	}

	if (!init_server_domid()) {
		goto done;
	}

	if (!init_vchan()) {
		goto done;
	}

	while (!interrupted) {
		char string[1024];

		printf("Enter string for encryption:\n");

		fgets(string, 1024, stdin);
		if (interrupted)
			break;

		char encrypted[4096], decrypted[4096];
		unsigned char *newtext = NULL;
		size_t size = strlen(string);
		string[size - 1] = '\0';
		size_t sent = 0;

		printf("Sending '%s' for encryption\n", string);
		while (sent < size) {
			int rc = libxenvchan_write(vchan_en_in, string + sent, size - sent);
			if (rc > 0) {
				sent += rc;
			} else {
				printf("Error\n");
				break;
			}
		}

		size_t size_read = libxenvchan_read(vchan_en_out, encrypted, 4096);
		if (size_read > 0) {
			printf("\tEncrypted string: '%s'\n", encrypted);
		} else {
			printf("Failed to receive encrypted string\n");
			continue;
		}

		printf("Sending '%s' for decryption\n", encrypted);

		sent = 0;
		while (sent < size_read) {
			int rc = libxenvchan_send(vchan_de_in, encrypted + sent,
					size_read - sent);
			if (rc > 0) {
				sent += rc;
			} else {
				printf("Error\n");
				break;
			}
		}

		size_read = libxenvchan_read(vchan_de_out, decrypted, 4096);
		if (size_read > 0) {
			printf("\tDecrypted string: '%s'\n", decrypted);
		} else {
			printf("Failed to receive decrypted string\n");
			continue;
		}

	}

	done: vchan_finish();
	xs_close(xs);

	return 0;
}
