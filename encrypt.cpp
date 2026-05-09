/* encrypt.cpp
 * AES-128 Encryption Tool
 */

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "structures.h"

using namespace std;

/* =====================================================
   AES HELPER FUNCTIONS
===================================================== */

unsigned char Multiply(unsigned char x, unsigned char y)
{
    unsigned char result = 0;

    while (y)
    {
        if (y & 1)
        {
            result ^= x;
        }

        if (x & 0x80)
        {
            x = (x << 1) ^ 0x1b;
        }
        else
        {
            x <<= 1;
        }

        y >>= 1;
    }

    return result;
}

/* =====================================================
   AES CORE FUNCTIONS
===================================================== */

void AddRoundKey(unsigned char *state,
                 unsigned char *roundKey)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}

void SubBytes(unsigned char *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = s[state[i]];
    }
}

void ShiftRows(unsigned char *state)
{
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

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
}

void MixColumns(unsigned char *state)
{
    unsigned char tmp[16];

    for (int i = 0; i < 4; i++)
    {
        int offset = i * 4;

        tmp[offset + 0] =
            Multiply(state[offset + 0], 2) ^
            Multiply(state[offset + 1], 3) ^
            state[offset + 2] ^
            state[offset + 3];

        tmp[offset + 1] =
            state[offset + 0] ^
            Multiply(state[offset + 1], 2) ^
            Multiply(state[offset + 2], 3) ^
            state[offset + 3];

        tmp[offset + 2] =
            state[offset + 0] ^
            state[offset + 1] ^
            Multiply(state[offset + 2], 2) ^
            Multiply(state[offset + 3], 3);

        tmp[offset + 3] =
            Multiply(state[offset + 0], 3) ^
            state[offset + 1] ^
            state[offset + 2] ^
            Multiply(state[offset + 3], 2);
    }

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
}

/* =====================================================
   AES ROUNDS
===================================================== */

void Round(unsigned char *state,
           unsigned char *roundKey)
{
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKey);
}

void FinalRound(unsigned char *state,
                unsigned char *roundKey)
{
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKey);
}

void AESEncrypt(unsigned char *message,
                unsigned char *expandedKey,
                unsigned char *encryptedMessage)
{
    unsigned char state[16];

    for (int i = 0; i < 16; i++)
    {
        state[i] = message[i];
    }

    // Initial Round
    AddRoundKey(state, expandedKey);

    // 9 Main Rounds
    for (int i = 1; i <= 9; i++)
    {
        Round(state, expandedKey + (16 * i));
    }

    // Final Round
    FinalRound(state, expandedKey + 160);

    for (int i = 0; i < 16; i++)
    {
        encryptedMessage[i] = state[i];
    }
}

/* =====================================================
   FILE / IO HELPERS
===================================================== */

bool LoadKey(unsigned char *key)
{
    ifstream infile("keyfile");

    if (!infile.is_open())
    {
        cerr << "Error: Cannot open keyfile" << endl;
        return false;
    }

    string keyStr;
    getline(infile, keyStr);

    infile.close();

    istringstream hexStream(keyStr);

    unsigned int value;
    int count = 0;

    while (hexStream >> hex >> value)
    {
        if (count >= 16)
        {
            break;
        }

        key[count++] =
            static_cast<unsigned char>(value);
    }

    if (count != 16)
    {
        cerr << "Error: AES-128 key must contain 16 bytes"
             << endl;

        return false;
    }

    return true;
}

void PrintHex(unsigned char *data,
              int len)
{
    for (int i = 0; i < len; i++)
    {
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

int main()
{
    cout << "===================================" << endl;
    cout << "      AES-128 Encryption Tool      " << endl;
    cout << "===================================" << endl;

    char message[1024];

    cout << "Enter plaintext: ";

    cin.getline(message, sizeof(message));

    int originalLen = strlen(message);

    // Padding to multiple of 16 bytes
    int paddedMessageLen =
        ((originalLen + 15) / 16) * 16;

    unsigned char *paddedMessage =
        new unsigned char[paddedMessageLen];

    for (int i = 0; i < paddedMessageLen; i++)
    {
        if (i < originalLen)
        {
            paddedMessage[i] =
                static_cast<unsigned char>(message[i]);
        }
        else
        {
            paddedMessage[i] = 0x00;
        }
    }

    unsigned char *encryptedMessage =
        new unsigned char[paddedMessageLen];

    cout << "\n[INFO] Original Length : "
         << originalLen
         << " bytes"
         << endl;

    cout << "[INFO] Padded Length  : "
         << paddedMessageLen
         << " bytes"
         << endl;

    /* ================================================
       LOAD AES KEY
    ================================================= */

    unsigned char key[16];

    if (!LoadKey(key))
    {
        delete[] paddedMessage;
        delete[] encryptedMessage;

        return 1;
    }

    cout << "\n[INFO] AES Key Loaded Successfully"
         << endl;

    /* ================================================
       KEY EXPANSION
    ================================================= */

    unsigned char expandedKey[176];

    KeyExpansion(key, expandedKey);

    cout << "[INFO] Key Expansion Completed"
         << endl;

    /* ================================================
       ENCRYPT BLOCKS
    ================================================= */

    for (int i = 0;
         i < paddedMessageLen;
         i += 16)
    {
        AESEncrypt(
            paddedMessage + i,
            expandedKey,
            encryptedMessage + i
        );
    }

    /* ================================================
       PRINT HEX OUTPUT
    ================================================= */

    cout << "\nEncrypted Message (HEX):"
         << endl;

    PrintHex(
        encryptedMessage,
        paddedMessageLen
    );

    /* ================================================
       WRITE BINARY FILE
    ================================================= */

    ofstream outfile(
        "message.aes",
        ios::binary
    );

    if (!outfile.is_open())
    {
        cerr << "Error: Cannot create message.aes"
             << endl;

        delete[] paddedMessage;
        delete[] encryptedMessage;

        return 1;
    }

    outfile.write(
        reinterpret_cast<char*>(encryptedMessage),
        paddedMessageLen
    );

    outfile.close();

    cout << "\n[INFO] Ciphertext written to message.aes"
         << endl;

    /* ================================================
       WRITE HEX LOG
    ================================================= */

    ofstream hexlog("message_hex.txt");

    if (hexlog.is_open())
    {
        for (int i = 0;
             i < paddedMessageLen;
             i++)
        {
            hexlog << hex
                   << setw(2)
                   << setfill('0')
                   << (int)encryptedMessage[i]
                   << " ";
        }

        hexlog.close();
    }

    cout << "[INFO] Hex dump written to message_hex.txt"
         << endl;

    /* ================================================
       CLEANUP
    ================================================= */

    delete[] paddedMessage;
    delete[] encryptedMessage;

    cout << "\nEncryption completed successfully."
         << endl;

    return 0;
}
