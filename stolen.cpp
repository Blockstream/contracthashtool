// Copyright (c) 2014 Blockstream
// Copyright (c) 2012-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Things stolen from Bitcoin Core......



#include <string>
#include <vector>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "stolen.h"

#include "hash.h"
#include "uint256.h"

using namespace std;

const signed char p_util_hexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

signed char HexDigit(char c)
{
    return p_util_hexdigit[(unsigned char)c];
}

bool IsHex(const string& str)
{
    for(std::string::const_iterator it(str.begin()); it != str.end(); ++it)
    {
        if (HexDigit(*it) < 0)
            return false;
    }
    return (str.size() > 0) && (str.size()%2 == 0);
}

vector<unsigned char> ParseHex(const char* psz)
{
    // convert hex dump to vector
    vector<unsigned char> vch;
    while (true)
    {
        while (isspace(*psz))
            psz++;
        signed char c = HexDigit(*psz++);
        if (c == (signed char)-1)
            break;
        unsigned char n = (c << 4);
        c = HexDigit(*psz++);
        if (c == (signed char)-1)
            break;
        n |= c;
        vch.push_back(n);
    }
    return vch;
}



/* All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    std::vector<unsigned char> b256(strlen(psz) * 733 / 1000 + 1); // log(58) / log(256), rounded up.
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        const char* ch = strchr(pszBase58, *psz);
        if (ch == NULL)
            return false;
        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin();
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    std::vector<unsigned char> b58((pend - pbegin) * 138 / 100 + 1); // log(256) / log(58), rounded up.
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); it != b58.rend(); it++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin();
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, insure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(&vch[0], &vch[vch.size()]);
}

enum Base58Type {
	PUBKEY_ADDRESS = 0,
	SCRIPT_ADDRESS = 5,
	PUBKEY_ADDRESS_TN = 111,
	SCRIPT_ADDRESS_TN = 196,
	SECRET_KEY = 128,
	SECRET_KEY_TN = 239,
};

class CBase58Data
{
public:
    // the version byte(s)
    std::vector<unsigned char> vchVersion;

    // the actually encoded data
    std::vector<unsigned char> vchData;

    bool SetString(const char* psz, unsigned int nVersionBytes = 1);
    std::string ToString() const;
    void SetData(const std::vector<unsigned char>& vchVersionIn, const void* pdata, size_t nSize);
};

void CBase58Data::SetData(const std::vector<unsigned char>& vchVersionIn, const void* pdata, size_t nSize)
{
    vchVersion = vchVersionIn;
    vchData.resize(nSize);
    if (!vchData.empty())
        memcpy(&vchData[0], pdata, nSize);
}

bool CBase58Data::SetString(const char* psz, unsigned int nVersionBytes)
{
    std::vector<unsigned char> vchTemp;
    bool rc58 = DecodeBase58Check(psz, vchTemp);
    if ((!rc58) || (vchTemp.size() < nVersionBytes)) {
        vchData.clear();
        vchVersion.clear();
        return false;
    }
    vchVersion.assign(vchTemp.begin(), vchTemp.begin() + nVersionBytes);
    vchData.resize(vchTemp.size() - nVersionBytes);
    if (!vchData.empty())
        memcpy(&vchData[0], &vchTemp[nVersionBytes], vchData.size());
    //OPENSSL_cleanse(&vchTemp[0], vchData.size());
    return true;
}

std::string CBase58Data::ToString() const
{
    std::vector<unsigned char> vch = vchVersion;
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return EncodeBase58Check(vch);
}


// WRAPPERS
static int is_testnet = -1;

void maybe_set_testnet(int testnet) {
	if (is_testnet == -1) {
		is_testnet = testnet;
		if (is_testnet == 1)
			printf("Using testnet!\n");
		else
			printf("Using mainnet!\n");

	}
}

bool hex_to_bytes(const char* c, unsigned char* res, unsigned int len) {
	vector<unsigned char> hex = ParseHex(c);
	if (hex.size() != len)
		return false;
	memcpy(res, &hex[0], len);
	return true;
}

const char* contract_str_to_bytes(const char* c, unsigned char* res) {
	CBase58Data addr;
	if (!addr.SetString(c))
		return NULL;
	if (addr.vchVersion.size() != 1 || addr.vchData.size() != 20)
		return NULL;

	if (is_testnet < 0) {
		is_testnet = (addr.vchVersion[0] == SCRIPT_ADDRESS_TN || addr.vchVersion[0] == PUBKEY_ADDRESS_TN) ? 1 : 0;
		if (is_testnet == 1)
			printf("Using testnet!\n");
		else
			printf("Using mainnet!\n");
	}

	if ((is_testnet == 0 && addr.vchVersion[0] != SCRIPT_ADDRESS && addr.vchVersion[0] != PUBKEY_ADDRESS) ||
		(is_testnet == 1 && addr.vchVersion[0] != SCRIPT_ADDRESS_TN && addr.vchVersion[0] != PUBKEY_ADDRESS_TN))
		return NULL;

	memcpy(res, &addr.vchData[0], 20);
	return (addr.vchVersion[0] == PUBKEY_ADDRESS || addr.vchVersion[0] == PUBKEY_ADDRESS_TN) ? "P2PH" : "P2SH";
}

bool privkey_str_to_bytes(const char* c, unsigned char res[33]) {
	CBase58Data priv;
	if (!priv.SetString(c))
		return false;

	if (priv.vchVersion.size() != 1 || priv.vchData.size() != 33)
		return false;

	if (is_testnet < 0) {
		is_testnet = (priv.vchVersion[0] == SECRET_KEY_TN) ? 1 : 0;
		if (is_testnet == 1)
			printf("Using testnet!\n");
		else
			printf("Using mainnet!\n");
	}

	if ((is_testnet == 0 && priv.vchVersion[0] != SECRET_KEY) || (is_testnet == 1 && priv.vchVersion[0] != SECRET_KEY_TN))
		return false;

	memcpy(res, &priv.vchData[0], 33);
	return true;
}

void bytes_to_privkey_str(const unsigned char* c, char* res) {
	assert(is_testnet >= 0);
	std::vector<unsigned char> version; version.push_back(is_testnet == 0 ? SECRET_KEY : SECRET_KEY_TN);
	CBase58Data priv;
	priv.SetData(version, c, 33);
	strcpy(res, priv.ToString().c_str());
}

void redeemscript_to_p2sh(char* res, unsigned char *redeem_script, unsigned int redeem_script_len) {
	assert(is_testnet >= 0);
	uint160 hash(Hash160(redeem_script, redeem_script + redeem_script_len));
	std::vector<unsigned char> version; version.push_back(is_testnet == 0 ? SCRIPT_ADDRESS : SCRIPT_ADDRESS_TN);
	CBase58Data addr;
	addr.SetData(version, &hash, 20);
	strcpy(res, addr.ToString().c_str());
}

void hmac_sha256(unsigned char* res, unsigned char key[33], unsigned char *data, unsigned int data_len) {
	CHMAC_SHA256(key, 33).Write(data, data_len).Finalize(res);
}

void hash160(unsigned char* res, char* ascii_contract) {
	uint160 hash(Hash160(ascii_contract, ascii_contract + strlen(ascii_contract) + 1));
	memcpy(res, &hash, 20);
}
