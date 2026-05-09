/* encrypt.cpp
 * Thực hiện mã hóa AES 128-bit
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "structures.h"

using namespace std;

/* =====================================================
   CÁC HÀM AES CƠ BẢN
===================================================== */

void AddRoundKey(unsigned char * state, unsigned char * roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

void SubBytes(unsigned char * state) {
    for (int i = 0; i < 16; i++) {
        state[i] = s[state[i]];
    }
}

void ShiftRows(unsigned char * state) {
    unsigned char tmp[16];

    // Row 0
    tmp[0]  = state[0];
    tmp[4]  = state[4];
    tmp[8]  = state[8];
    tmp[12] = state[12];

    // Row 1
    tmp[1]  = state[5];
    tmp[5]  = state[9];
    tmp[9]  = state[13];
    tmp[13] = state[1];

    // Row 2
    tmp[2]  = state[10];
    tmp[6]  = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];

    // Row 3
    tmp[3]  = state[15];
    tmp[7]  = state[3];
    tmp[11] = state[7];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
}

void MixColumns(unsigned char * state) {
    unsigned char tmp[16];

    for (int i = 0; i < 4; i++) {

        int offset = i * 4;

        tmp[offset + 0] =
            mul2[state[offset + 0]] ^
            mul3[state[offset + 1]] ^
            state[offset + 2] ^
            state[offset + 3];

        tmp[offset + 1] =
            state[offset + 0] ^
            mul2[state[offset + 1]] ^
            mul3[state[offset + 2]] ^
            state[offset + 3];

        tmp[offset + 2] =
            state[offset + 0] ^
            state[offset + 1] ^
            mul2[state[offset + 2]] ^
            mul3[state[offset + 3]];

        tmp[offset + 3] =
            mul3[state[offset + 0]] ^
            state[offset + 1] ^
            state[offset + 2] ^
            mul2[state[offset + 3]];
    }

    for (int i = 0; i < 16; i++) {
        state[i] = tmp[i];
    }
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

void KeyExpansion(unsigned char * key, unsigned char * expandedKey) {

    unsigned char tmp[4];
    int i = 0;

    // copy original key
    while (i < 16) {
        expandedKey[i] = key[i];
        i++;
    }

    // generate remaining bytes
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
   AES ROUNDS
===================================================== */

void Round(unsigned char * state, unsigned char * key) {

    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key);
}

void FinalRound(unsigned char * state, unsigned char * key) {

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key);
}

void AESEncrypt(unsigned char * message,
                unsigned char * expandedKey,
                unsigned char * encryptedMessage) {

    unsigned char state[16];

    for (int i = 0; i < 16; i++) {
        state[i] = message[i];
    }

    // Initial round
    AddRoundKey(state, expandedKey);

    // 9 main rounds
    for (int i = 1; i <= 9; i++) {
        Round(state, expandedKey + (16 * i));
    }

    // Final round
    FinalRound(state, expandedKey + 160);

    for (int i = 0; i < 16; i++) {
        encryptedMessage[i] = state[i];
    }
}

/* =====================================================
   HELPER FUNCTIONS
===================================================== */

bool LoadKey(unsigned char * key) {

    ifstream infile("keyfile");

    if (!infile.is_open()) {
        cerr << "Error: Cannot open keyfile" << endl;
        return false;
    }

    string keyStr;
    getline(infile, keyStr);
    infile.close();

    istringstream hexStream(keyStr);

    unsigned int value;
    int count = 0;

    while (hexStream >> hex >> value) {

        if (count >= 16) {
            break;
        }

        key[count++] = static_cast<unsigned char>(value);
    }

    if (count != 16) {
        cerr << "Error: AES-128 key must contain 16 bytes" << endl;
        return false;
    }

    return true;
}

void PrintHex(unsigned char * data, int len) {

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
    cout << "      AES-128 Encryption Tool      " << endl;
    cout << "===================================" << endl;

    char message[1024];

    cout << "Enter plaintext: ";
    cin.getline(message, sizeof(message));

    int originalLen = strlen(message);

    // zero padding
    int paddedMessageLen =
        ((originalLen + 15) / 16) * 16;

    unsigned char * paddedMessage =
        new unsigned char[paddedMessageLen];

    for (int i = 0; i < paddedMessageLen; i++) {

        if (i < originalLen) {
            paddedMessage[i] =
                static_cast<unsigned char>(message[i]);
        } else {
            paddedMessage[i] = 0x00;
        }
    }

    unsigned char * encryptedMessage =
        new unsigned char[paddedMessageLen];

    cout << "\n[INFO] Original length : "
         << originalLen << " bytes" << endl;

    cout << "[INFO] Padded length  : "
         << paddedMessageLen << " bytes" << endl;

    /* =================================================
       LOAD KEY
    ================================================= */

    unsigned char key[16];

    if (!LoadKey(key)) {
        delete[] paddedMessage;
        delete[] encryptedMessage;
        return 1;
    }

    cout << "\n[INFO] AES Key Loaded Successfully" << endl;

    /* =================================================
       KEY EXPANSION
    ================================================= */

    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    cout << "[INFO] Key Expansion Completed" << endl;

    /* =================================================
       ENCRYPT BLOCKS
    ================================================= */

    for (int i = 0; i < paddedMessageLen; i += 16) {

        AESEncrypt(
            paddedMessage + i,
            expandedKey,
            encryptedMessage + i
        );
    }

    /* =================================================
       OUTPUT HEX
    ================================================= */

    cout << "\nEncrypted message (HEX):" << endl;

    PrintHex(encryptedMessage, paddedMessageLen);

    /* =================================================
       WRITE BINARY FILE
    ================================================= */

    ofstream outfile(
        "message.aes",
        ios::binary
    );

    if (!outfile.is_open()) {

        cerr << "Error: Cannot write message.aes" << endl;

        delete[] paddedMessage;
        delete[] encryptedMessage;

        return 1;
    }

    outfile.write(
        reinterpret_cast<char*>(encryptedMessage),
        paddedMessageLen
    );

    outfile.close();

    cout << "\n[INFO] Ciphertext written to message.aes" << endl;

    /* =================================================
       WRITE HEX LOG FILE
    ================================================= */

    ofstream hexlog("message_hex.txt");

    if (hexlog.is_open()) {

        for (int i = 0; i < paddedMessageLen; i++) {

            hexlog
                << hex
                << setw(2)
                << setfill('0')
                << (int)encryptedMessage[i]
                << " ";
        }

        hexlog.close();
    }

    cout << "[INFO] Hex dump written to message_hex.txt" << endl;

    /* =================================================
       CLEANUP
    ================================================= */

    delete[] paddedMessage;
    delete[] encryptedMessage;

    cout << "\nEncryption completed successfully." << endl;

    return 0;
}