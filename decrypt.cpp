/* decrypt.cpp
 * Performs AES-128 decryption
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

#include "structures.h"

using namespace std;

/* =====================================================
   BASIC AES DECRYPT FUNCTIONS
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
   AES DECRYPT
===================================================== */

void AESDecrypt(unsigned char * encryptedMessage,
                unsigned char * expandedKey,
                unsigned char * decryptedMessage) {

    unsigned char state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = encryptedMessage[i];
    }

    // initial round with last round key
    InitialRound(state, expandedKey + 160);

    // 9 main rounds
    for (int i = 8; i >= 0; i--) {

        Round(state,
              expandedKey + (16 * (i + 1)));
    }

    // final round
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
        cerr << "Error: Cannot open keyfile" << endl;
        return false;
    }

    string keystr;
    getline(keyfile, keystr);

    keyfile.close();

    istringstream hex_chars_stream(keystr);

    unsigned int c;
    int i = 0;

    while (hex_chars_stream >> hex >> c) {

        if (i >= 16) {
            break;
        }

        key[i] = static_cast<unsigned char>(c);
        i++;
    }

    if (i != 16) {
        cerr << "Error: Invalid AES-128 key" << endl;
        return false;
    }

    return true;
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

    cout << "===================================" << endl;
    cout << "      AES-128 Decryption Tool      " << endl;
    cout << "===================================" << endl;

    /* =================================================
       READ ENCRYPTED FILE
    ================================================= */

    ifstream infile(
        "message.aes",
        ios::binary | ios::ate
    );

    if (!infile.is_open()) {

        cerr << "Error: Cannot open message.aes" << endl;
        return 1;
    }

    streamsize fileSize = infile.tellg();

    infile.seekg(0, ios::beg);

    if (fileSize <= 0 ||
        fileSize % 16 != 0) {

        cerr << "Error: Invalid AES ciphertext size" << endl;
        return 1;
    }

    vector<unsigned char> encryptedMessage(fileSize);

    if (!infile.read(
            reinterpret_cast<char*>(encryptedMessage.data()),
            fileSize)) {

        cerr << "Error: Failed to read ciphertext" << endl;
        return 1;
    }

    infile.close();

    cout << "[INFO] Read "
         << fileSize
         << " bytes from message.aes"
         << endl;

    /* =================================================
       LOAD KEY
    ================================================= */

    unsigned char key[16];

    if (!LoadKey(key)) {
        return 1;
    }

    cout << "[INFO] AES Key Loaded Successfully"
         << endl;

    /* =================================================
       KEY EXPANSION
    ================================================= */

    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    cout << "[INFO] Key Expansion Completed"
         << endl;

    /* =================================================
       DECRYPT BLOCKS
    ================================================= */

    vector<unsigned char> decryptedMessage(fileSize);

    for (int i = 0; i < fileSize; i += 16) {

        AESDecrypt(
            encryptedMessage.data() + i,
            expandedKey,
            decryptedMessage.data() + i
        );
    }

    /* =================================================
       PRINT HEX
    ================================================= */

    cout << "\nDecrypted message in HEX:" << endl;

    PrintHex(
        decryptedMessage.data(),
        fileSize
    );

    /* =================================================
       PRINT PLAINTEXT
    ================================================= */

    cout << "\nRecovered plaintext:" << endl;

    for (int i = 0; i < fileSize; i++) {

        // ignore zero padding
        if (decryptedMessage[i] != 0x00) {
            cout << decryptedMessage[i];
        }
    }

    cout << endl;

    /* =================================================
       SAVE PLAINTEXT
    ================================================= */

    ofstream outfile("decrypted.txt");

    if (outfile.is_open()) {

        for (int i = 0; i < fileSize; i++) {

            if (decryptedMessage[i] != 0x00) {
                outfile << decryptedMessage[i];
            }
        }

        outfile.close();

        cout << "\n[INFO] Plaintext written to decrypted.txt"
             << endl;
    }

    cout << "\nDecryption completed successfully."
         << endl;

    return 0;
}