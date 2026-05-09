/* cbc_decrypt.cpp
 * AES-128 CBC Decryption
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

#include "structures.h"

using namespace std;

/* =====================================================
   BASIC AES FUNCTIONS
===================================================== */

void SubRoundKey(unsigned char * state,
                 unsigned char * roundKey) {

    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

/* =====================================================
   INVERSE MIX COLUMNS
===================================================== */

void InverseMixColumns(unsigned char * state) {

    unsigned char tmp[16];

    for (int i = 0; i < 4; i++) {

        int offset = i * 4;

        tmp[offset + 0] =
            mul14[state[offset + 0]] ^
            mul11[state[offset + 1]] ^
            mul13[state[offset + 2]] ^
            mul9[state[offset + 3]];

        tmp[offset + 1] =
            mul9[state[offset + 0]] ^
            mul14[state[offset + 1]] ^
            mul11[state[offset + 2]] ^
            mul13[state[offset + 3]];

        tmp[offset + 2] =
            mul13[state[offset + 0]] ^
            mul9[state[offset + 1]] ^
            mul14[state[offset + 2]] ^
            mul11[state[offset + 3]];

        tmp[offset + 3] =
            mul11[state[offset + 0]] ^
            mul13[state[offset + 1]] ^
            mul9[state[offset + 2]] ^
            mul14[state[offset + 3]];
    }

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/* =====================================================
   SHIFT ROWS (RIGHT SHIFT)
===================================================== */

void ShiftRows(unsigned char * state) {

    unsigned char tmp[16];

    tmp[0]  = state[0];
    tmp[1]  = state[13];
    tmp[2]  = state[10];
    tmp[3]  = state[7];

    tmp[4]  = state[4];
    tmp[5]  = state[1];
    tmp[6]  = state[14];
    tmp[7]  = state[11];

    tmp[8]  = state[8];
    tmp[9]  = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

/* =====================================================
   INVERSE SUB BYTES
===================================================== */

void SubBytes(unsigned char * state) {

    for (int i = 0; i < 16; i++) {
        state[i] = inv_s[state[i]];
    }
}

/* =====================================================
   AES DECRYPTION ROUNDS
===================================================== */

void Round(unsigned char * state,
           unsigned char * key) {

    SubRoundKey(state, key);

    InverseMixColumns(state);

    ShiftRows(state);

    SubBytes(state);
}

void InitialRound(unsigned char * state,
                  unsigned char * key) {

    SubRoundKey(state, key);

    ShiftRows(state);

    SubBytes(state);
}

/* =====================================================
   KEY EXPANSION
===================================================== */

void RotWord(unsigned char * w) {

    unsigned char tmp = w[0];

    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

void SubWord(unsigned char * w) {

    for (int i = 0; i < 4; i++) {
        w[i] = s[w[i]];
    }
}

void KeyExpansion(unsigned char * key,
                  unsigned char * expandedKey) {

    unsigned char tmp[4];

    int i = 0;

    while (i < 16) {
        expandedKey[i] = key[i];
        i++;
    }

    i = 16;

    while (i < 176) {

        for (int j = 0; j < 4; j++) {
            tmp[j] = expandedKey[(i - 4) + j];
        }

        if (i % 16 == 0) {

            RotWord(tmp);

            SubWord(tmp);

            tmp[0] ^= rcon[i / 16];
        }

        for (int j = 0; j < 4; j++) {

            expandedKey[i] =
                expandedKey[i - 16] ^ tmp[j];

            i++;
        }
    }
}

/* =====================================================
   AES DECRYPT
===================================================== */

void AESDecrypt(unsigned char * encryptedMessage,
                unsigned char * expandedKey,
                unsigned char * decryptedMessage) {

    unsigned char state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = encryptedMessage[i];
    }

    InitialRound(state, expandedKey + 160);

    for (int i = 8; i >= 0; i--) {

        Round(
            state,
            expandedKey + (16 * (i + 1))
        );
    }

    SubRoundKey(state, expandedKey);

    for (int i = 0; i < 16; i++) {
        decryptedMessage[i] = state[i];
    }
}

/* =====================================================
   HELPER FUNCTIONS
===================================================== */

bool LoadKey(unsigned char * key) {

    ifstream keyfile("keyfile");

    if (!keyfile.is_open()) {

        cerr << "Error: Cannot open keyfile"
             << endl;

        return false;
    }

    string keystr;

    getline(keyfile, keystr);

    keyfile.close();

    istringstream hexStream(keystr);

    unsigned int value;

    int count = 0;

    while (hexStream >> hex >> value) {

        if (count >= 16) {
            break;
        }

        key[count++] =
            static_cast<unsigned char>(value);
    }

    if (count != 16) {

        cerr << "Error: Invalid AES key"
             << endl;

        return false;
    }

    return true;
}

void XORBlocks(unsigned char * a,
               unsigned char * b,
               unsigned char * output) {

    for (int i = 0; i < 16; i++) {
        output[i] = a[i] ^ b[i];
    }
}

void PrintHex(unsigned char * data,
              int len) {

    for (int i = 0; i < len; i++) {

        cout << hex
             << setw(2)
             << setfill('0')
             << (int)data[i]
             << " ";
    }

    cout << dec << endl;
}

/* =====================================================
   MAIN
===================================================== */

int main() {

    cout << "===================================="
         << endl;

    cout << "      AES-128 CBC Decryption"
         << endl;

    cout << "===================================="
         << endl;

    /* =================================================
       OPEN FILE
    ================================================= */

    ifstream infile(
        "message_cbc.aes",
        ios::binary | ios::ate
    );

    if (!infile.is_open()) {

        cerr << "Error: Cannot open message_cbc.aes"
             << endl;

        return 1;
    }

    streamsize fileSize = infile.tellg();

    infile.seekg(0, ios::beg);

    if (fileSize <= 16 ||
        ((fileSize - 16) % 16 != 0)) {

        cerr << "Error: Invalid CBC file format"
             << endl;

        return 1;
    }

    /* =================================================
       READ IV
    ================================================= */

    unsigned char iv[16];

    infile.read(
        reinterpret_cast<char*>(iv),
        16
    );

    cout << "\nRead IV:" << endl;

    PrintHex(iv, 16);

    /* =================================================
       READ CIPHERTEXT
    ================================================= */

    int ciphertextSize = fileSize - 16;

    vector<unsigned char> ciphertext(ciphertextSize);

    infile.read(
        reinterpret_cast<char*>(ciphertext.data()),
        ciphertextSize
    );

    infile.close();

    cout << "\n[INFO] Read "
         << ciphertextSize
         << " bytes ciphertext"
         << endl;

    /* =================================================
       LOAD KEY
    ================================================= */

    unsigned char key[16];

    if (!LoadKey(key)) {
        return 1;
    }

    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    cout << "[INFO] Key Expansion Completed"
         << endl;

    /* =================================================
       CBC DECRYPTION
    ================================================= */

    vector<unsigned char> plaintext(ciphertextSize);

    unsigned char previousBlock[16];

    memcpy(previousBlock, iv, 16);

    for (int i = 0; i < ciphertextSize; i += 16) {

        unsigned char decryptedBlock[16];

        AESDecrypt(
            ciphertext.data() + i,
            expandedKey,
            decryptedBlock
        );

        XORBlocks(
            decryptedBlock,
            previousBlock,
            plaintext.data() + i
        );

        memcpy(
            previousBlock,
            ciphertext.data() + i,
            16
        );
    }

    /* =================================================
       PRINT HEX
    ================================================= */

    cout << "\nRecovered Plaintext (HEX):"
         << endl;

    PrintHex(
        plaintext.data(),
        ciphertextSize
    );

    /* =================================================
       PRINT PLAINTEXT
    ================================================= */

    cout << "\nRecovered Plaintext:"
         << endl;

    for (int i = 0; i < ciphertextSize; i++) {

        if (plaintext[i] != 0x00) {
            cout << plaintext[i];
        }
    }

    cout << endl;

    /* =================================================
       SAVE PLAINTEXT
    ================================================= */

    ofstream outfile("cbc_decrypted.txt");

    if (outfile.is_open()) {

        for (int i = 0; i < ciphertextSize; i++) {

            if (plaintext[i] != 0x00) {
                outfile << plaintext[i];
            }
        }

        outfile.close();

        cout << "\n[INFO] Plaintext saved to cbc_decrypted.txt"
             << endl;
    }

    cout << "\nCBC Decryption Completed Successfully."
         << endl;

    return 0;
}