/* decrypt.cpp
 * AES-128 Decryption
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

#include "structures.h"

using namespace std;

/* =====================================================
   GALOIS FIELD MULTIPLICATION
===================================================== */

unsigned char gmul(unsigned char a,
                   unsigned char b)
{
    unsigned char p = 0;

    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            p ^= a;
        }

        bool hi_bit = (a & 0x80);

        a <<= 1;

        if (hi_bit)
        {
            a ^= 0x1B;
        }

        b >>= 1;
    }

    return p;
}

/* =====================================================
   ADD ROUND KEY
===================================================== */

void AddRoundKey(unsigned char *state,
                 unsigned char *roundKey)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= roundKey[i];
    }
}

/* =====================================================
   INVERSE SUB BYTES
===================================================== */

void InvSubBytes(unsigned char *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = inv_s[state[i]];
    }
}

/* =====================================================
   INVERSE SHIFT ROWS
===================================================== */

void InvShiftRows(unsigned char *state)
{
    unsigned char tmp[16];

    tmp[0]  = state[0];
    tmp[4]  = state[4];
    tmp[8]  = state[8];
    tmp[12] = state[12];

    tmp[1]  = state[13];
    tmp[5]  = state[1];
    tmp[9]  = state[5];
    tmp[13] = state[9];

    tmp[2]  = state[10];
    tmp[6]  = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];

    tmp[3]  = state[7];
    tmp[7]  = state[11];
    tmp[11] = state[15];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
}

/* =====================================================
   INVERSE MIX COLUMNS
===================================================== */

void InvMixColumns(unsigned char *state)
{
    unsigned char tmp[16];

    for (int i = 0; i < 4; i++)
    {
        int offset = i * 4;

        unsigned char s0 = state[offset + 0];
        unsigned char s1 = state[offset + 1];
        unsigned char s2 = state[offset + 2];
        unsigned char s3 = state[offset + 3];

        tmp[offset + 0] =
            gmul(s0, 14) ^
            gmul(s1, 11) ^
            gmul(s2, 13) ^
            gmul(s3, 9);

        tmp[offset + 1] =
            gmul(s0, 9) ^
            gmul(s1, 14) ^
            gmul(s2, 11) ^
            gmul(s3, 13);

        tmp[offset + 2] =
            gmul(s0, 13) ^
            gmul(s1, 9) ^
            gmul(s2, 14) ^
            gmul(s3, 11);

        tmp[offset + 3] =
            gmul(s0, 11) ^
            gmul(s1, 13) ^
            gmul(s2, 9) ^
            gmul(s3, 14);
    }

    for (int i = 0; i < 16; i++)
    {
        state[i] = tmp[i];
    }
}

/* =====================================================
   AES DECRYPT BLOCK
===================================================== */

void AESDecrypt(unsigned char *input,
                unsigned char *expandedKey,
                unsigned char *output)
{
    unsigned char state[16];

    for (int i = 0; i < 16; i++)
    {
        state[i] = input[i];
    }

    AddRoundKey(state, expandedKey + 160);

    for (int round = 9; round >= 1; round--)
    {
        InvShiftRows(state);

        InvSubBytes(state);

        AddRoundKey(
            state,
            expandedKey + (16 * round)
        );

        InvMixColumns(state);
    }

    InvShiftRows(state);

    InvSubBytes(state);

    AddRoundKey(state, expandedKey);

    for (int i = 0; i < 16; i++)
    {
        output[i] = state[i];
    }
}

/* =====================================================
   LOAD AES KEY
===================================================== */

bool LoadKey(unsigned char *key)
{
    ifstream infile("keyfile");

    if (!infile.is_open())
    {
        cerr << "Error: Cannot open keyfile"
             << endl;

        return false;
    }

    string keyStr;

    getline(infile, keyStr);

    infile.close();

    istringstream iss(keyStr);

    unsigned int value;

    int count = 0;

    while (iss >> hex >> value)
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
        cerr << "Error: AES key must contain 16 bytes"
             << endl;

        return false;
    }

    return true;
}

/* =====================================================
   PRINT HEX
===================================================== */

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

/*  MAIN
===================================================== */

int main()
{
    cout << "=================================="
         << endl;

    cout << "     AES-128 DECRYPTION TOOL"
         << endl;

    cout << "=================================="
         << endl;

    /* READ CIPHERTEXT
    ================================================= */

    ifstream infile(
        "message.aes",
        ios::binary | ios::ate
    );

    if (!infile.is_open())
    {
        cerr << "Error: Cannot open message.aes"
             << endl;

        return 1;
    }

    streamsize fileSize = infile.tellg();

    infile.seekg(0, ios::beg);

    if (fileSize <= 0 ||
        fileSize % 16 != 0)
    {
        cerr << "Error: Invalid ciphertext size"
             << endl;

        return 1;
    }

    vector<unsigned char> encrypted(
        fileSize
    );

    infile.read(
        reinterpret_cast<char*>(encrypted.data()),
        fileSize
    );

    infile.close();

    /*  LOAD KEY */

    unsigned char key[16];

    if (!LoadKey(key))
    {
        return 1;
    }

    cout << "[INFO] AES key loaded"
         << endl;

    /* KEY EXPANSION */

    unsigned char expandedKey[176];

    KeyExpansion(
        key,
        expandedKey
    );

    cout << "[INFO] Key expansion completed"
         << endl;

    /* =================================================
       DECRYPT
    ================================================= */

    vector<unsigned char> decrypted(
        fileSize
    );

    for (int i = 0; i < fileSize; i += 16)
    {
        AESDecrypt(
            encrypted.data() + i,
            expandedKey,
            decrypted.data() + i
        );
    }

    /*   OUTPUT */

    cout << "\nDecrypted HEX:"
         << endl;

    PrintHex(
        decrypted.data(),
        fileSize
    );

    cout << "\nRecovered plaintext:"
         << endl;

    for (int i = 0; i < fileSize; i++)
    {
        if (decrypted[i] != 0x00)
        {
            cout << decrypted[i];
        }
    }

    cout << endl;

    /* SAVE FILE */

    ofstream outfile("decrypted.txt");

    if (outfile.is_open())
    {
        for (int i = 0; i < fileSize; i++)
        {
            if (decrypted[i] != 0x00)
            {
                outfile << decrypted[i];
            }
        }

        outfile.close();
    }

    cout << "\n[INFO] Plaintext written to decrypted.txt"
         << endl;

    cout << "\nDecryption completed successfully."
         << endl;

    return 0;
}
