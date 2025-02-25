#include "../lib/utilityLib/utilityFile.h"
#include "../lib/utilityLib/timestampLibrary.h"
#include "../configuration.h"
#include "../lib/communicationLib/messagePackingLibrary.h"

#include "../dataStructures/models/userBBS.h"

using namespace std;

int main(int argc, char *argv[])
{
    bool global_test = true;

    // ------ AES-256 Testing---------------------------------------
    string plaintext = "Plaintext";
    string key = "0123456789abcdef0123456789abcdef"; // 32-byte (256-bit) key

    string encryptedMessage, decryptedMessage;

    encryptedMessage = vectorUnsignedCharToString(encrypt_AES(plaintext, key));
    if (decrypt_AES(encryptedMessage, key) != plaintext)
    {
        cout << "AES NON funziona" << endl;
        global_test = false;
    }

    // ------ RSA Testing---------------------------------------
    encryptedMessage = rsa_encrypt(plaintext, loadRSAKey("../serverPublicKey/rsa_pubkey.pem", true));
    decryptedMessage = rsa_decrypt(encryptedMessage, loadRSAKey("../serverPrivateKey/rsa_privkey.pem",false));

    if (decryptedMessage != plaintext)
    {
        cout << "RSA NON funziona" << endl;
        global_test = false;
    }

    // ------ HMAC Testing---------------------------------------
    const EVP_MD *md = EVP_sha256();
    string iv = "1234567890abcdef"; // 16-byte (128-bit) IV
    string HMAC_original = calculateHMAC(iv, plaintext, md);

    if (HMAC_original == calculateHMAC(iv, plaintext + " ", md))
    {
        cout << "HMAC NON funziona" << endl;
        global_test = false;
    }

    if (HMAC_original == calculateHMAC(iv, " " + plaintext, md))
    {
        cout << "HMAC NON funziona" << endl;
        global_test = false;
    }

    if (HMAC_original == calculateHMAC(iv, plaintext + "a", md))
    {
        cout << "HMAC NON funziona" << endl;
        global_test = false;
    }

    // ------ Timestamps Testing---------------------------------------
    const string ts = "2024-06-20 11:17:03.958";
    const string ta = "2024-06-20 11:17:43.958";
    int num = secondDifference(ts, ta);

    if (num != 40)
    {
        cout << "(+) secondDifference NON funziona" << endl;
        global_test = false;
    }

    num = secondDifference(ta, ts);

    if (num != -40)
    {
        cout << "(-) secondDifference NON funziona" << endl;
        global_test = false;
    }

    // ------ RSAE and Digital Signature Testing---------------------------------------
    int R = 100;
    string conc, check, Tpubkey, Tprivkey;
    RSAEMessage messageRSAE;

    generateRSAKeyPair(Tpubkey, Tprivkey);

    EVP_PKEY* privKey = loadRSAKey("../serverPrivateKey/rsa_privkey.pem" , false);

    messageRSAE.setPublicKey(Tpubkey);
    messageRSAE.computeDigitalFirm(R, privKey);
    messageRSAE.setCert(loadCertFromPEM("../serverPublicKey/cacert.pem"));
    if (!messageRSAE.verifyDigitalFirm(R))
    {
        cout << "RSAEMessage - La firma digitale NON funziona" << endl;
        global_test = false;
    }

    messageRSAE.concatenateFields(check);
    messageRSAE.deconcatenateAndAssign(check);

    messageRSAE.computeDigitalFirm(R, privKey);
    if (!messageRSAE.verifyDigitalFirm(R))
    {
        cout << "La firma digitale NON funziona" << endl;
        global_test = false;
    }

    R = 120;
    if (messageRSAE.verifyDigitalFirm(R))
    {
        cout << "La firma digitale NON funziona" << endl;
        global_test = false;
    }
    
    messageRSAE.concatenateFields(check);
    messageRSAE.deconcatenateAndAssign(check);

    R = 120;
    messageRSAE.computeDigitalFirm(R, privKey);
    if (!messageRSAE.verifyDigitalFirm(R))
    {
        cout << "La firma digitale NON funziona" << endl;
        global_test = false;
    }

    // ------ HASH Testing---------------------------------------
    userBBS user;
    user.setNickname("Pini");
    user.setEmail("pini@gmail.com");
    user.setSalt(generateRandomSalt());
    string password = "Pini";
    user.setPasswordDigest(computeHash(password, user.getSalt()));
    if (!checkSaltedPasswordDigest(password, user.getPasswordDigest(), user.getSalt()))
    {
        cout << "La prima verifica della password utente NON funziona" << endl;
        global_test = false;
    }

    password = password + "a";
    if (checkSaltedPasswordDigest(password, user.getPasswordDigest(), user.getSalt()))
    {
        cout << "La seconda verifica della password utente NON funziona" << endl;
        global_test = false;
    }

    password = " " + password;
    if (checkSaltedPasswordDigest(password, user.getPasswordDigest(), user.getSalt()))
    {
        cout << "La seconda verifica della password utente NON funziona" << endl;
        global_test = false;
    }

    password = password + "-";
    if (checkSaltedPasswordDigest(password, user.getPasswordDigest(), user.getSalt()))
    {
        cout << "La seconda verifica della password utente NON funziona" << endl;
        global_test = false;
    }

    password = "-" + password;
    if (checkSaltedPasswordDigest(password, user.getPasswordDigest(), user.getSalt()))
    {
        cout << "La seconda verifica della password utente NON funziona" << endl;
        global_test = false;
    }

    string aes_key = "Pippo";
    string msg = "Pluto";
    string c = vectorUnsignedCharToString(encrypt_AES(msg, aes_key));

    if (decrypt_AES(c, aes_key) != msg)
    {
        cout << "La prima verifica di AES NON funziona!" << endl;
        global_test = false;
    }

    if (!(decrypt_AES(c, aes_key) != (msg + " ")))
    {
        cout << "La prima verifica di AES NON funziona!" << endl;
        global_test = false;
    }

    if (global_test)
    {
        cout << "Tutto OK!" << endl;
    }
    return 0;
}