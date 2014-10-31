// Copyright (c) 2014 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include <secp256k1.h>

#include "stolen.h"

#define ERROREXIT(str...) do {fprintf(stderr, str); exit(1);} while(0)
#define USAGEEXIT(str...) do {fprintf(stderr, str); usage(); exit(1);} while (0)

void usage() {
	printf("USAGE: Generate address: -g -r <redeem script> (-d <Contract P2SH/regular address>)|(-a <ASCII Contract text>)  [-n <16-byte random nonce>]\n");
	printf("When generating the address, a random nonce is used unless one is specified\n");
	printf("If you do not care about privacy, anything may be used, otherwise some random value should be used\n");
	printf("Note that if the nonce is lost, your ability to redeem funds sent to the resulting address is also lost\n");
	printf("USAGE: Generate privkey: -c -p <base58 private key> (-d <Contract P2SH/regular address>)|(-a <ASCII Contract text>) -n <nonce>\n");
}

int get_pubkeys_from_redeemscript(unsigned char *redeem_script, unsigned int redeem_script_len, unsigned char* pubkeys[]) {
	unsigned char *readpos = redeem_script, * const endpos = redeem_script + redeem_script_len;
	unsigned char *maybe_keys[redeem_script_len/33];
	unsigned int maybe_keys_count = 0, pubkeys_count = 0;;
	bool require_next_checkmultisig = false;

	while (readpos < endpos) {
		int pushlen = -1;
		unsigned char* push_start = NULL;

		if (*readpos > 0 && *readpos < 76) {
			pushlen = *readpos;
			push_start = readpos + 1;
		} else if (*readpos == 76) {
			if (readpos + 1 >= endpos)
				ERROREXIT("Invalid push in script\n");
			pushlen = *(readpos + 1);
			push_start = readpos + 2;
		} else if (*readpos == 77) {
			if (readpos + 2 >= endpos)
				ERROREXIT("Invalid push in script\n");
			pushlen = *(readpos + 1) | (*(readpos + 2) << 8);
			push_start = readpos + 3;
		} else if (*readpos == 78) {
			if (readpos + 4 >= endpos)
				ERROREXIT("Invalid push in script\n");
			pushlen = *(readpos + 1) | (*(readpos + 2) << 8) | (*(readpos + 3) << 16) | (*(readpos + 4) << 24);
			push_start = readpos + 5;
		}

		if (pushlen > -1) {
			if (push_start + pushlen >= endpos)
				ERROREXIT("Invalid push in script\n");

			if (pushlen == 65 && *push_start == 4)
				ERROREXIT("ERROR: Possible uncompressed pubkey found in redeem script, not converting it\n");
			else if (pushlen == 33 && (*push_start == 2 || *push_start == 3))
				maybe_keys[maybe_keys_count++] = push_start;
			else if (maybe_keys_count > 0)
				ERROREXIT("ERROR: Found possible public keys but are not using them as they are not followed immediately by [OP_N] OP_CHECK[MULTI]SIG[VERIFY]\n");
		} else {
			if (require_next_checkmultisig) {
				if (*readpos == 174 || *readpos == 175) {
					require_next_checkmultisig = false;
					for (unsigned int i = 0; i < maybe_keys_count; i++)
						pubkeys[pubkeys_count++] = maybe_keys[i];
					maybe_keys_count = 0;
				} else
					ERROREXIT("ERROR: Found possible public keys but are not using them as they are not followed immediately by [OP_N] OP_CHECK[MULTI]SIG[VERIFY]\n");
			} else if (maybe_keys_count > 0) {
				if (maybe_keys_count == 1 && (*readpos == 172 || *readpos == 173)) {
					pubkeys[pubkeys_count++] = maybe_keys[0];
					maybe_keys_count = 0;
				} else if (((unsigned int)*readpos) - 80 == maybe_keys_count)
					require_next_checkmultisig = true;
				else
					ERROREXIT("ERROR: Found possible public keys but are not using them as they are not followed immediately by [OP_N] OP_CHECK[MULTI]SIG[VERIFY]\n");
			} else if (*readpos >= 172 && *readpos <= 175)
				ERROREXIT("ERROR: Found OP_CHECK[MULTI]SIG[VERIFY] without pubkey(s) immediately preceeding it\n");
		}

		if (pushlen != -1)
			readpos = push_start + pushlen;
		else
			readpos++;
	}

	return pubkeys_count;
}

int main(int argc, char* argv[]) {
	char mode = 0; // 0x1 == address, 0x2 == privkey
	char *redeem_script_hex = NULL, *p2sh_address = NULL, *ascii_contract = NULL, *priv_key_str = NULL, *nonce_hex = NULL;

	// ARGPARSE
	int i;
	while ((i = getopt(argc, argv, "gcr:d:p:a:n:h?")) != -1)
		switch(i) {
		case 'g':
		case 'c':
			if (mode != 0)
				USAGEEXIT("May only specify one of -g, -c\n");
			mode = i == 'g' ? 0x1 : 0x2;
			break;
		case 'r':
			if (mode != 0x1 || redeem_script_hex)
				USAGEEXIT("-r only allowed once and in -g mode\n");
			redeem_script_hex = optarg;
			break;
		case 'p':
			if (mode != 0x2 || priv_key_str)
				USAGEEXIT("-p only allowed once and in -c mode\n");
			priv_key_str = optarg;
			break;
		case 'd':
			if (p2sh_address || ascii_contract)
				USAGEEXIT("Only one contract allowed\n");
			p2sh_address = optarg;
			break;
		case 'a':
			if (ascii_contract)
				USAGEEXIT("Only one contract allowed\n");
			ascii_contract = optarg;
			break;
		case 'n':
			if (nonce_hex)
				USAGEEXIT("Only one nonce allowed\n");
			nonce_hex = optarg;
			break;
		case 'h':
		case '?':
			usage();
			exit(0);
		default:
			ERROREXIT("getopt malfunction?\n");
		}

	// ARGCHECK
	if (!p2sh_address && !ascii_contract)
		USAGEEXIT("No contract provided\n");
	if (mode == 0x1 && !redeem_script_hex)
		USAGEEXIT("No redeem script specified\n");
	if (mode == 0x2 && !nonce_hex)
		USAGEEXIT("No nonce specified\n");
	if (mode == 0x2 && !priv_key_str)
		USAGEEXIT("No private key specified\n");

	secp256k1_start((unsigned int) -1);

	// GLOBALCONV
	unsigned char p2sh_bytes[20];
	const char* address_type = "TEXT";
	if (p2sh_address) {
		address_type = contract_str_to_bytes(p2sh_address, p2sh_bytes);
		if (!address_type)
			ERROREXIT("Contract Address (%s) is invalid\n", p2sh_address);
	}

	unsigned char nonce[16];
	if (nonce_hex && !hex_to_bytes(nonce_hex, nonce, 16))
		ERROREXIT("Nonce is not a valid 16-byte hex string\n");

	// DOIT
	if (mode == 0x1) {
		unsigned int redeem_script_len = strlen(redeem_script_hex)/2;
		unsigned char redeem_script[redeem_script_len];
		if (!hex_to_bytes(redeem_script_hex, redeem_script, redeem_script_len))
			ERROREXIT("Invalid redeem script\n");

		unsigned char* keys[redeem_script_len / 33];
		int key_count = get_pubkeys_from_redeemscript(redeem_script, redeem_script_len, keys);
		if (key_count < 1)
			ERROREXIT("Redeem script invalid or no pubkeys found\n");

		FILE* rand;
		if (!nonce_hex) {
			rand = fopen("/dev/urandom", "rb");
			assert(rand);
		}

		unsigned char keys_work[key_count][33];
		while (true) {
			for (i = 0; i < key_count; i++)
				memcpy(keys_work[i], keys[i], 33);

			if (!nonce_hex)
				assert(fread((char*)nonce, 1, 16, rand) == 16);

			unsigned char data[4 + 16 + (ascii_contract ? strlen(ascii_contract) : 20)];
			memset(data,                         0,              4);
			memcpy(data,                         address_type,   strlen(address_type));
			memcpy(data + 4,                     nonce,          sizeof(nonce));
			if (ascii_contract)
			    memcpy(data + 4 + sizeof(nonce), ascii_contract, strlen(ascii_contract));
			else
			    memcpy(data + 4 + sizeof(nonce), p2sh_bytes,     sizeof(p2sh_bytes));

			for (i = 0; i < key_count; i++) {
				unsigned char res[32];
				hmac_sha256(res, keys_work[i], data, 4 + 16 + (ascii_contract ? strlen(ascii_contract) : 20));
				
				if (secp256k1_ec_pubkey_tweak_add(keys_work[i], 33, res) == 0) {
					if (nonce_hex)
						ERROREXIT("YOU BROKE SHA256, PLEASE SEND THE EXACT DATA USED IN A BUG REPORT\n");
					break; // if tweak > order
				}
			}
			if (i == key_count)
				break;
		}
		for (i = 0; i < key_count; i++)
			memcpy(keys[i], keys_work[i], 33);

		if (!nonce_hex)
			fclose(rand);

		char p2sh_res[35];
		p2sh_res[34] = 0;
		redeemscript_to_p2sh(p2sh_res, redeem_script, redeem_script_len);

		printf("Nonce: ");
		for (int i = 0; i < 16; i++)
			printf("%02x", nonce[i]);
		printf("\nModified redeem script: ");
		for (unsigned int i = 0; i < redeem_script_len; i++)
			printf("%02x", redeem_script[i]);
		printf("\nModified redeem script as P2SH address: %s\n", p2sh_res);
	} else if (mode == 0x2) {
		unsigned char priv[33], pub[33];
		if (!privkey_str_to_bytes(priv_key_str, priv))
			ERROREXIT("Private key is invalid (or not used as compressed)\n");

		unsigned char data[4 + 16 + (ascii_contract ? strlen(ascii_contract) : 20)];
		memset(data,                         0,              4);
		memcpy(data,                         address_type,   strlen(address_type));
		memcpy(data + 4,                     nonce,          sizeof(nonce));
		if (ascii_contract)
		    memcpy(data + 4 + sizeof(nonce), ascii_contract, strlen(ascii_contract));
		else
		    memcpy(data + 4 + sizeof(nonce), p2sh_bytes,     sizeof(p2sh_bytes));

		int len = 0;
		if (secp256k1_ec_pubkey_create(pub, &len, priv, 1) != 1 || len != 33)
			ERROREXIT("Private key was invalid\n");

		unsigned char tweak[32];
		hmac_sha256(tweak, pub, data, 4 + 16 + (ascii_contract ? strlen(ascii_contract) : 20));

		if (secp256k1_ec_privkey_tweak_add(priv, tweak) != 1)
			ERROREXIT("Tweak is invalid\n");

		priv[32] = 1;
		char res[52];
		bytes_to_privkey_str(priv, res);
		printf("New secret key: %s\n", res);
	} else
		ERROREXIT("OH GOD WHAT DID YOU DO?\n");

	secp256k1_stop();

	return 0;
}
