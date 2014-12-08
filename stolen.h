// Copyright (c) 2014 Blockstream
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


extern "C" {
void maybe_set_testnet(int testnet);
bool hex_to_bytes(const char* c, unsigned char* res, unsigned int len);
const char* contract_str_to_bytes(const char* c, unsigned char* res);
bool privkey_str_to_bytes(const char* c, unsigned char res[33]);
void bytes_to_privkey_str(const unsigned char* c, char* res);
void hmac_sha256(unsigned char* res, unsigned char key[33], unsigned char *data, unsigned int data_len);
void redeemscript_to_p2sh(char* res, unsigned char* redeem_script, unsigned int redeem_script_len);
void hash160(unsigned char* res, char* ascii_contract);
}
