#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <stdio.h>
#include <string.h>
#include <libp11.h>
#include <ctype.h>
#include "sha2.h"

/* {{{ defines */
#ifndef FALSE
# define FALSE 0
#endif 

#ifndef TRUE
# define TRUE 1
#endif 

#define RANDOM_SOURCE 		"/dev/urandom"
#define TARGET_KEY_SIZE 	32	/* 256 bits */
#define MAX_PIN_SIZE		8
#define MIN_PIN_SIZE		4
#define MAX_SIG_SIZE		256
#define OPENSC_PKCS11_LIB	"/usr/lib/opensc-pkcs11.so"
/* }}} */

/* {{{ pkcs11_ctl */
struct pkcs11_ctl {
	PKCS11_CTX *ctx;
	PKCS11_SLOT *slots;
	PKCS11_KEY *pkey;
	char pin[MAX_PIN_SIZE + 1];
	int user_pin;
	int nslots;
	int pkcs11_loaded;

};
typedef struct pkcs11_ctl pkcs11_ctl;
/* }}} */

/* {{{ static data */
static char rand_key[] = 
{ 0xe8, 0x8d, 0xa4, 0xfb, 0x23, 0x69, 0x6f, 0xb7, 0xdd, 0xfb, 0x95, 0x21,
  0x08, 0x50, 0xfa, 0x5f, 0x24, 0x42, 0xf7, 0xd9, 0xad, 0x2c, 0x9f, 0xd8,
  0xf3, 0xa7, 0x1e, 0x99, 0xf4, 0xda, 0xb1, 0xcb 
};

static int debug = FALSE;
/* }}} */

/* {{{ prototypes */
static int pkcs11_initialize(pkcs11_ctl *ctl);
static int pkcs11_find_certificate_key(pkcs11_ctl *ctl);
static int pkcs11_find_private_key(pkcs11_ctl *ctl);
static void pkcs11_cleanup(pkcs11_ctl *ctl);
static int pkcs11_token_login(pkcs11_ctl *ctl, PKCS11_SLOT *slot);
static void print_null_key(FILE *out, int keysize);
static int pkcs11_create_key(char *in, size_t len_in, char *out, int hexdisplay, PKCS11_KEY *authkey);
static int get_user_pin(char *pin, char *label);
static void display_help(void);
static int handle_pin(char *optarg, char *pin);
/* }}} */

/* {{{ int main(int argc, char **argv) */
int main(int argc, char *argv[])
{
	pkcs11_ctl ctl;	
	char data[128] = { 0 } ;
	int c;
	int hexdisplay = FALSE;
	FILE *out = stderr;

	/* Zero ctl struct */
	ctl.ctx = NULL;
	ctl.slots = NULL;
	ctl.pkey = NULL;
	memset(ctl.pin, 0, sizeof(ctl.pin));
	ctl.user_pin = FALSE;
	ctl.nslots = 0;
	ctl.pkcs11_loaded = FALSE;


	/* parse options */
	while (1) {
		c = getopt(argc, argv, "dhop:r");

		if (c == -1)
			break;

		switch (c) {
			case 'd':
				debug = TRUE;
				break;
			case 'h':
				display_help();
				return 1;
				break;
			case 'o':
				out = stdout;
				break;
			case 'p':
				ctl.user_pin = handle_pin(optarg, ctl.pin);
				break;
			case 'r':
				hexdisplay = TRUE;
				break;
			default:
				break;
		}
	}

	ERR_load_PKCS11_strings();


	if (pkcs11_initialize(&ctl) == FALSE)
		goto errout;

	if (pkcs11_find_certificate_key(&ctl) == FALSE &&
	  pkcs11_find_private_key(&ctl) == FALSE)
		goto errout;

	/* Encrypt rand_key with private key */
	if (pkcs11_create_key((char *)rand_key, sizeof(rand_key), data, hexdisplay, ctl.pkey) == FALSE)
		goto errout;

	fprintf(out, "%.128s", data);

	pkcs11_cleanup(&ctl);

	return 0;

errout:
	pkcs11_cleanup(&ctl);

	print_null_key(out, TARGET_KEY_SIZE);	
	
	return 1;
}
/* }}} */

/* {{{ static int pkcs11_initialize(pkcs11_ctl *ctl) */
static int pkcs11_initialize(pkcs11_ctl *ctl)
{
	int rc;

	ctl->ctx = PKCS11_CTX_new();
	if (ctl->ctx == NULL) {
		if (debug)
			fprintf(stderr, "Can't create PKCS11_CTX\n");
		return FALSE;
	}

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(ctl->ctx, OPENSC_PKCS11_LIB);
	if (rc) {
		if (debug)
			fprintf(stderr, "Can't load PKCS11 extension\n");
		return FALSE;
	}
	ctl->pkcs11_loaded = TRUE;

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctl->ctx, &ctl->slots, &ctl->nslots);
	if (rc < 0)  {
		if (debug)
			fprintf(stderr, "No slots found\n");
		return FALSE;
	}

	return TRUE;
}
/* }}} */

/* {{{ static int pkcs11_find_certificate_key(pkcs11_ctl *ctl) */
static int pkcs11_find_certificate_key(pkcs11_ctl *ctl)
{
	PKCS11_CERT *certs = NULL, *cert;
	unsigned int ncerts;
	PKCS11_SLOT *slot;
	int rc;
	
	/* get first slot with a token */
	slot = PKCS11_find_token(ctl->ctx, ctl->slots, ctl->nslots);
	if (!slot || !slot->token) {
		if (debug)
			fprintf(stderr, "No token found\n");
		goto errout;
	}

	/* get all certs */
	rc = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	if (rc || ncerts <= 0) {
		if (debug)
			fprintf(stderr, "No slots found\n");
		goto errout;
	}

	/* use the first cert */
	cert = &certs[0];

	if (pkcs11_token_login(ctl, slot) == FALSE)
		goto errout;

	ctl->pkey = PKCS11_find_key(cert);

	if (ctl->pkey == NULL) {
		if (debug)
			fprintf(stderr, "Private key not found\n");
		goto errout;
	}

	return TRUE;

errout:
	return FALSE;
}
/* }}} */

/* {{{ static int pkcs11_find_private_key(pkcs11_ctl *ctl) */
static int pkcs11_find_private_key(pkcs11_ctl *ctl)
{
	PKCS11_KEY *keys = NULL;
	unsigned int nkeys;
	PKCS11_SLOT *slot;
	int rc;
	
	/* get first slot with a token */
	slot = PKCS11_find_token(ctl->ctx, ctl->slots, ctl->nslots);
	if (!slot || !slot->token) {
		if (debug)
			fprintf(stderr, "No token found\n");
		goto errout;
	}

	/* get all certs */
	rc = PKCS11_enumerate_keys(slot->token, &keys, &nkeys);
	if (rc || nkeys <= 0) {
		if (debug)
			fprintf(stderr, "No keys found\n");
		goto errout;
	}

	ctl->pkey = &keys[0];

	if (ctl->pkey == NULL) {
		if (debug)
			fprintf(stderr, "Private key not found\n");
		goto errout;
	}

	return TRUE;

errout:
	return FALSE;
}
/* }}} */

/* {{{ static void pkcs11_cleanup(pkcs11_ctl *ctl) */
static void pkcs11_cleanup(pkcs11_ctl *ctl)
{
	if (ctl->slots && ctl->nslots) {
		PKCS11_release_all_slots(ctl->ctx, ctl->slots, ctl->nslots);
		ctl->slots = NULL;
		ctl->nslots = 0;
	}
	if (ctl->ctx) {
		if (ctl->pkcs11_loaded == TRUE)
			PKCS11_CTX_unload(ctl->ctx);
		PKCS11_CTX_free(ctl->ctx);
		ctl->ctx = NULL;
	}
}
/* }}} */

/* {{{ static int pkcs11_token_login(pkcs11_ctl *ctl, PKCS11_SLOT *slot) */
static int pkcs11_token_login(pkcs11_ctl *ctl, PKCS11_SLOT *slot)
{
	if (slot->token->loginRequired) {
		if (ctl->user_pin == FALSE) {
			if (get_user_pin(ctl->pin, slot->token->label) == FALSE)
				return FALSE;
		}
		if (PKCS11_login(slot, 0, ctl->pin) != 0)
			return FALSE;
	}

	return TRUE;
}
/* }}} */

/* {{{ static void print_null_key(FILE *out, int keysize) */
static void print_null_key(FILE *out, int keysize)
{
	int i;

	for (i = 0; i < keysize; i++) {
		fprintf(out, "00");
	}
}
/* }}} */

/* {{{ static int pkcs11_create_key(unsigned char *in, size_t len_in, unsigned char **out, int hexdisplay, PKCS11_KEY *authkey) */
static int pkcs11_create_key(char *in, size_t len_in, char *out, int hexdisplay, PKCS11_KEY *authkey)
{
	char *sig = NULL;
	int siglen, rc;
	SHA256_CTX ctx;

	if (!authkey)
		goto errout;

	sig = malloc(sizeof(char) * MAX_SIG_SIZE);
	if (sig == NULL)
		goto errout;

	siglen = MAX_SIG_SIZE;
	rc = PKCS11_sign(NID_sha1, in, len_in, sig, &siglen, authkey);
	if (rc != 1)
		goto errout;

	/* Make a SHA256 hash of the signature */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, sig, siglen);
	if (!hexdisplay) {
		SHA256_BinEnd(&ctx, out);
		out[32] = '\0';
	}
	else
		SHA256_End(&ctx, out);

	free(sig);

	return TRUE;

errout:
	if (sig)
		free(sig);

	return FALSE;
}
/* }}} */

/* {{{ static int get_user_pin(char *pin, char *label) */
static int get_user_pin(char *pin, char *label)
{
	struct termios old, new;
	char tmp[32];
	int rc;

	/* Turn echoing off and fail if we can't. */
	if (tcgetattr(0, &old) != 0)
		return FALSE;

	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(0, TCSAFLUSH, &new) != 0)
		return FALSE;

	/* Read the password. */
	printf("Password for token %.32s: ", label);
	fgets(tmp, sizeof(tmp), stdin);

	/* Restore terminal. */
	(void)tcsetattr(0, TCSAFLUSH, &old);

	/* strip tailing \n from password */
	rc = strlen(tmp);
	if (rc < MIN_PIN_SIZE || rc > MAX_PIN_SIZE)
		return FALSE;
	tmp[rc-1] = 0;
	strcpy(pin, tmp);

	return TRUE;
}
/* }}} */

/* {{{ static void display_help(void) */
static void display_help(void)
{
	printf("Usage: etoken_key [OPTION...]\n");
	printf("-d 		Enable debug\n");
	printf("-h 		Show this help message\n");
	printf("-o 		Output to stdout\n");
	printf("-p		E-token PIN\n");
	printf("-r 		Output in hex\n");
}
/* }}} */

/* {{{ static int handle_pin(char *optarg, char *pin) */
static int handle_pin(char *optarg, char *pin)
{
	int i;

	if (strlen(optarg) < MIN_PIN_SIZE)
		return FALSE;
	if (strlen(optarg) > MAX_PIN_SIZE)
		return FALSE;

	for (i = 0; i < strlen(optarg); i++) {
		if (!isdigit(optarg[i]))
			return FALSE;
	}

	/* Ok. Valid pin : copy */
	strncpy(pin, optarg, strlen(optarg));

	return TRUE;
}
/* }}} */
