// GOST 34.12.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"

#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <iostream>
#include <string>
#include <vector>

/*
	DESIGNATIONS:

	p - pointer
	dw - double word (type uint32)
	qw - quad word (type uint64)
	Arr - array
	by - byte (uint8_t, unsigned char)
*/

using namespace std;

using substitution_t = uint8_t[128];

substitution_t byArrPi = {
	0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1,
	0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf,
	0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0,
	0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb,
	0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc,
	0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0,
	0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7,
	0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2
};

void magma_round(uint32_t dwRoundkey, uint32_t& dwA1, uint32_t dwA0)
{
	uint32_t g = dwA0 + dwRoundkey;

	uint32_t dwT =
		((byArrPi[0 + ((g & 0x0000000f) >> 0)]) << 0)
		| ((byArrPi[16 + ((g & 0x000000f0) >> 4)]) << 4)
		| ((byArrPi[32 + ((g & 0x00000f00) >> 8)]) << 8)
		| ((byArrPi[48 + ((g & 0x0000f000) >> 12)]) << 12)
		| ((byArrPi[64 + ((g & 0x000f0000) >> 16)]) << 16)
		| ((byArrPi[80 + ((g & 0x00f00000) >> 20)]) << 20)
		| ((byArrPi[96 + ((g & 0x0f000000) >> 24)]) << 24)
		| ((byArrPi[112 + ((g & 0xf0000000) >> 28)]) << 28);

	dwA1 ^= ((dwT << 11) | (dwT >> 21));
}

//Требуется реализовать следующие функции :
uint32_t* create_round_keys(uint8_t *pKey) {
	/* view of RoundKey in format of one byte SubKey */	
	union key_formated
	{
		uint32_t dwRoundKey;
		uint8_t byArrSubKey[4];
	};
	key_formated format_Rkey;

	uint32_t *pRoundKeys = new uint32_t[32];

	for (uint8_t i = 0; i < 8; i++) {
		for (uint8_t j = 0; j < 4; j++) { format_Rkey.byArrSubKey[j] = pKey[4*i + j]; }
		pRoundKeys[7-i] = format_Rkey.dwRoundKey;
	}

	for (uint8_t i = 8; i < 24; i++) { pRoundKeys[i] = pRoundKeys[i % 8]; }
	for (uint8_t i = 24; i < 32; i++) { pRoundKeys[i] = pRoundKeys[7 - (i % 8)]; }
	return pRoundKeys;
}

/* Зашифрование одного блока данных */
uint64_t magma_encrypt_block(uint32_t* pRoundKeys, uint64_t qwBlock) {
	uint32_t dwA0 = qwBlock & 0xffffffff;
	uint32_t dwA1 = qwBlock >> 32;


	for (uint8_t i = 0; i < 32; i++) {
		magma_round(pRoundKeys[i], dwA1, dwA0);
		swap(dwA1, dwA0);
	}

	uint64_t qwResult = dwA0;
	qwResult = qwResult << 32;
	return qwResult ^ dwA1;
}

/* Расшифрование одного блока данных */
uint64_t magma_decrypt_block(uint32_t* pRoundKeys, uint64_t qwBlock) {
	uint32_t dwA0 = qwBlock & 0xffffffff;
	uint32_t dwA1 = qwBlock >> 32;

	for (uint8_t i = 32; i > 0; i--) {
		magma_round(pRoundKeys[i-1], dwA1, dwA0);
		swap(dwA1, dwA0);
	}

	uint64_t qwResult = dwA0;
	qwResult = qwResult << 32;
	return qwResult ^ dwA1;
};

/* Тестирование корректности реализации операции зашифрования/расшифрования одного блока данных */
int test_magma_encrypt_decrypt_block() {

	union formated {
		unsigned char byArrBlock[8];
		uint64_t qwBlock;
	};
	formated convert;

	uint8_t key[32] = { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	vector<unsigned char> plain_text = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe };
	vector<unsigned char> cipher_text;
	vector<unsigned char> decrypt_text;


	/*If plain_text size mod(8) != 0 Add salt (GOST 34.13)*/
	if (plain_text.size() % 8 != 0) {
		plain_text.push_back(0x0f);													//Add 0x0f
		uint8_t num_bytes = 7 - plain_text.size() % 8;
		for (uint8_t i = 0; i < num_bytes; i++) { plain_text.push_back(0x00); }		//Add 0x00
	}

	uint32_t *round_keys = create_round_keys(key);

	cout << "Round_keys: " << endl;
	for (uint8_t i = 0; i < 32; i++) { printf("Round key %d: %x\n", i + 1, round_keys[i]); }
	cout << endl;

	cout << "Key: ";
	for (unsigned char i : key) { printf("%x", i); }
	cout << endl << endl;

	cout << "Plain_text: ";
	for (unsigned char i : plain_text) { printf("%x ", i); }
	cout << endl << endl;

	for (uint32_t i = 0; i < plain_text.size(); i++) {
		convert.byArrBlock[i % 8] = plain_text[i];
		if (i % 8 == 7) {
			convert.qwBlock = magma_encrypt_block(round_keys, convert.qwBlock);
			for (unsigned char j : convert.byArrBlock) {
				cipher_text.push_back(j);
			}
		}
	}

	cout << "Cipher_text: ";
	for (unsigned char i : cipher_text) { printf("%x ", i); }
	cout << endl << endl;

	for (uint32_t i = 0; i < cipher_text.size(); i++) {
		convert.byArrBlock[i % 8] = cipher_text[i];
		if (i % 8 == 7) {
			convert.qwBlock = magma_decrypt_block(round_keys, convert.qwBlock);
			for (unsigned char j : convert.byArrBlock) {
				decrypt_text.push_back(j);
			}
		}
	}

	cout << "Decrypt_text: ";
	for (unsigned char i : decrypt_text) { printf("%x ", i); }
	cout << endl << endl;

	//CLEAR ROUND_KEYS MEMORY
	for (uint8_t i = 0; i < 32; i++) { round_keys[i] = 0; }

	cout << "Round_keys after CLEAR: " << endl;
	for (uint8_t i = 0; i < 32; i++) { printf("Round key %d: %x\n", i + 1, round_keys[i]); }
	cout << endl;

	delete round_keys;

	return 0;
};

int main()
{
	test_magma_encrypt_decrypt_block();
	system("pause");

    return 0;
}

