#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cstdio>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>

#include "../utilityLib/utility.h"

using namespace std;

#ifndef SECURITY_H
#define SECURITY_H

const char *PRIVATE_ENC = "keyPassword"; // AES256 key used to encrypt the rsa private key.

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

// ----------------------------- Digest e HMAC -------------------------------------------

string computeHash(string input, string salt = "")
{
    // Creazione del contesto
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr)
    {
        throw runtime_error("EVP_MD_CTX_new failed");
    }

    // Selezione dell'algoritmo di hash (SHA-256)
    const EVP_MD *md = EVP_sha256();
    if (md == nullptr)
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_sha256 failed");
    }

    // Inizializzazione del contesto per l'hash
    if (1 != EVP_DigestInit_ex(mdctx, md, nullptr))
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_DigestInit_ex failed");
    }

    // Aggiornamento del contesto con il salt
    if (1 != EVP_DigestUpdate(mdctx, salt.c_str(), salt.size()))
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_DigestUpdate failed");
    }

    // Aggiornamento del contesto con i dati
    if (1 != EVP_DigestUpdate(mdctx, input.c_str(), input.size()))
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_DigestUpdate failed");
    }

    // Buffer per l'output dell'hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    // Finalizzazione del calcolo dell'hash
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash))
    {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_DigestFinal_ex failed");
    }

    // Deallocazione del contesto
    EVP_MD_CTX_free(mdctx);

    // Convertiamo l'hash in una stringa esadecimale
    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i)
    {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

string calculateHMAC(string key, string message, const EVP_MD *evp_md)
{
    EVP_PKEY *pkey = nullptr;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *result = nullptr;
    size_t result_len = 0;
    string hmac;

    if (!ctx)
    {
        throw runtime_error("Errore nella creazione del contesto EVP_MD_CTX");
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, (const unsigned char *)key.c_str(), key.size());
    if (!pkey)
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Errore nella creazione della chiave HMAC");
    }

    if (EVP_DigestSignInit(ctx, nullptr, evp_md, nullptr, pkey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore nell'inizializzazione dell'HMAC con EVP_DigestSignInit");
    }

    if (EVP_DigestSignUpdate(ctx, message.c_str(), message.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore nell'aggiornamento del contesto HMAC con il messaggio");
    }

    if (EVP_DigestSignFinal(ctx, nullptr, &result_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore nel recupero della dimensione del risultato HMAC");
    }

    result = (unsigned char *)OPENSSL_malloc(result_len);
    if (!result)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore nell'allocazione della memoria per il risultato HMAC");
    }

    if (EVP_DigestSignFinal(ctx, result, &result_len) != 1)
    {
        OPENSSL_free(result);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore nella finalizzazione del calcolo HMAC");
    }

    // Conversione del risultato HMAC in una stringa esadecimale
    char hex_result[result_len * 2 + 1]; // Per memorizzare la rappresentazione esadecimale del risultato

    for (size_t i = 0; i < result_len; i++)
        sprintf(hex_result + i * 2, "%02x", result[i]);

    hex_result[result_len * 2] = '\0'; // Terminazione della stringa

    hmac = hex_result;

    OPENSSL_free(result);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return hmac;
}

string calculateHMAC(string key, string message)
{
    const EVP_MD *evp_md = EVP_sha256();
    return calculateHMAC(key, message, evp_md);
}

bool verifyHMAC(string key, string message, string HMACtoVerify)
{
    string m = calculateHMAC(key, message); // protection from timing attacks.
    return (computeHash(m) == computeHash(HMACtoVerify)); // The adversary cannot know which byte are being verified.
}

bool checkSaltedPasswordDigest(string inputPassword, string passwordDigest, string salt = "")
{
    string m = computeHash(inputPassword, salt); // protection from timing attacks.
    return (computeHash(m) == computeHash(passwordDigest));  // The adversary cannot know which byte are being verified.
}

vector<unsigned char> stringToUnsignedCharVector(const string &str)
{
    return vector<unsigned char>(str.begin(), str.end());
}

void stringToCharArray(const string &str, char *charArray, size_t maxLen)
{
    strncpy(charArray, str.c_str(), maxLen - 1);
    charArray[maxLen - 1] = '\0'; // Ensure null termination
}

// ----------------------------- AES -------------------------------------------
// Funzione per cifrare una stringa
vector<unsigned char> encrypt_AES(const string &plaintext, const string &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("AES Encr - Errore nella creazione del contesto di cifratura");
    }

    // Genera un IV casuale
    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (!RAND_bytes(iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc())))
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES Encr - Errore nella generazione dell'IV");
    }

    // Inizializzazione della cifratura
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.data()), iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES Encr - Errore nell'inizializzazione della cifratura");
    }

    // Aggiungi padding al plaintext
    int plaintext_len = plaintext.size();
    int ciphertext_len = plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    vector<unsigned char> ciphertext(ciphertext_len + EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    // Copia l'IV nel ciphertext
    memcpy(ciphertext.data(), iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    int len;
    unsigned char *ciphertext_ptr = ciphertext.data() + EVP_CIPHER_iv_length(EVP_aes_256_cbc());

    if (EVP_EncryptUpdate(ctx, ciphertext_ptr, &len, reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES Encr - Errore nella cifratura del testo");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext_ptr + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES Encr - Errore nella finalizzazione della cifratura");
    }
    ciphertext_len += len;

    // Truncate the ciphertext to the actual size
    ciphertext.resize(ciphertext_len + EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Funzione per decifrare una stringa
string decrypt_AES(const vector<unsigned char> &ciphertext, const string &key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw runtime_error("AES Decr - Errore nella creazione del contesto di decifratura");
    }

    // Estrai l'IV dal ciphertext
    unsigned char iv[EVP_MAX_IV_LENGTH];
    memcpy(iv, ciphertext.data(), EVP_CIPHER_iv_length(EVP_aes_256_cbc()));

    // Inizializzazione della decifratura
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.data()), iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES Decr - Errore nell'inizializzazione della decifratura");
    }

    // Decifra il testo
    int ciphertext_len = ciphertext.size() - EVP_CIPHER_iv_length(EVP_aes_256_cbc());
    vector<unsigned char> paddedPlaintext(ciphertext_len);

    int len;
    if (EVP_DecryptUpdate(ctx, paddedPlaintext.data(), &len, ciphertext.data() + EVP_CIPHER_iv_length(EVP_aes_256_cbc()), ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES Decr - Errore nella decifratura del testo");
    }
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, paddedPlaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("AES Decr - Errore nella finalizzazione della decifratura");
    }
    plaintext_len += len;

    // Truncate the plaintext to the actual size
    paddedPlaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return string(paddedPlaintext.begin(), paddedPlaintext.end());
}

string decrypt_AES(const string &ciphertext, const string &key)
{
    return decrypt_AES(stringToVectorUnsignedChar(ciphertext), key);
}

// --------------- RSA -----------------------------------------------------------------------------------------------

// Funzione per convertire vector<unsigned char> in EVP_PKEY*
EVP_PKEY *convertToEVP_PKEY(const vector<unsigned char> &privateKeyVec)
{
    const unsigned char *keyData = privateKeyVec.data();
    BIO *bio = BIO_new_mem_buf(keyData, privateKeyVec.size());
    if (!bio)
    {
        throw runtime_error("Errore nella creazione del BIO");
    }

    // Legge la chiave privata RSA dal BIO
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey)
    {
        BIO_free(bio);
        throw runtime_error("Errore nella lettura della chiave privata dal BIO");
    }

    BIO_free(bio);
    return pkey;
}

// Funzione per convertire un EVP_PKEY* in vector<unsigned char>
vector<unsigned char> convertEVP_PKEYToVector(const EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        throw runtime_error("Errore nella creazione del BIO");
    }

    // Scrive la chiave privata nel BIO
    if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr))
    {
        BIO_free(bio);
        throw runtime_error("Errore nella scrittura della chiave privata nel BIO");
    }

    // Recupera i dati dal BIO
    char *bioData;
    long bioLen = BIO_get_mem_data(bio, &bioData);
    if (bioLen <= 0)
    {
        BIO_free(bio);
        throw runtime_error("Errore nel recupero dei dati dal BIO");
    }

    // Converte i dati in un vector<unsigned char>
    vector<unsigned char> keyVec(bioData, bioData + bioLen);

    BIO_free(bio);
    return keyVec;
}

// Funzione per convertire una stringa contenente una chiave privata in EVP_PKEY*
EVP_PKEY *convertStringToPrivateEVP_PKEY(const string &privateKeyStr)
{
    BIO *bio = BIO_new_mem_buf(privateKeyStr.data(), privateKeyStr.size());
    if (!bio)
    {
        throw runtime_error("Errore nella creazione del BIO");
    }

    // Legge la chiave privata RSA dal BIO
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey)
    {
        BIO_free(bio);
        throw runtime_error("Errore nella lettura della chiave privata dal BIO");
    }

    BIO_free(bio);
    return pkey;
}

// Funzione per convertire un EVP_PKEY* in una stringa contenente una chiave privata
string convertPrivateEVP_PKEYToString(const EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        throw runtime_error("Errore nella creazione del BIO");
    }

    // Scrive la chiave privata nel BIO
    if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr))
    {
        BIO_free(bio);
        throw runtime_error("Errore nella scrittura della chiave privata nel BIO");
    }

    // Converte il BIO in una stringa
    char *bioData;
    long bioLen = BIO_get_mem_data(bio, &bioData);
    string privateKeyStr(bioData, bioLen);

    BIO_free(bio);
    return privateKeyStr;
}

// Helper function to convert EVP_PKEY to string
string convertPublicEVP_PKEYToString(const EVP_PKEY *pkey)
{
    unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!PEM_write_bio_PUBKEY(bio.get(), pkey))
    {
        throw runtime_error("Error writing public key to BIO");
    }

    BUF_MEM *bufferPtr;
    BIO_get_mem_ptr(bio.get(), &bufferPtr);
    BIO_set_close(bio.get(), BIO_NOCLOSE);

    string publicKey(bufferPtr->data, bufferPtr->length);
    return publicKey;
}

// Helper function to convert string to EVP_PKEY
EVP_PKEY *convertStringToPublicEVP_PKEY(const string &publicKeyStr)
{
    unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(publicKeyStr.data(), publicKeyStr.length()), BIO_free);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!pkey)
    {
        throw runtime_error("Error reading public key from BIO");
    }
    return pkey;
}

// Funzione per caricare una chiave RSA da file
EVP_PKEY *loadRSAKey(const char *path, const bool public_key)
{
    EVP_PKEY *pkey = nullptr;
    FILE *file = fopen(path, "r");

    if (!file)
    {
        throw std::runtime_error("RSA Keys file cannot be opened!");
    }

    if (public_key)
    {
        pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    }
    else
    {
        pkey = PEM_read_PrivateKey(file, nullptr, nullptr, (void *)PRIVATE_ENC);
    }

    fclose(file);

    if (!pkey)
    {
        throw std::runtime_error("RSA Keys cannot be loaded!");
    }

    return pkey;
}

string rsa_encrypt(const string &plainText, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    EVP_PKEY_free(pkey);
    if (ctx == nullptr)
    {
        throw runtime_error("Errore creazione contesto EVP_PKEY_CTX per cifratura");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Errore inizializzazione operazione di cifratura");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Errore impostazione padding RSA");
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (const unsigned char *)plainText.c_str(), plainText.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Errore determinazione dimensione buffer per cifratura");
    }

    string cipherText(outlen, '\0');
    if (EVP_PKEY_encrypt(ctx, (unsigned char *)cipherText.data(), &outlen, (const unsigned char *)plainText.c_str(), plainText.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Errore cifratura dati");
    }

    EVP_PKEY_CTX_free(ctx);

    return cipherText;
}

string rsa_decrypt(const string &cipherText, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (ctx == nullptr)
    {
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore creazione contesto EVP_PKEY_CTX per decifratura");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore inizializzazione operazione di decifratura");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore impostazione padding RSA");
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, (const unsigned char *)cipherText.c_str(), cipherText.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore determinazione dimensione buffer per decifratura");
    }

    string plainText(outlen, '\0');
    if (EVP_PKEY_decrypt(ctx, (unsigned char *)plainText.data(), &outlen, (const unsigned char *)cipherText.c_str(), cipherText.length()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Errore decifratura dati");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Truncate the string to the actual size of decrypted data
    plainText.resize(outlen);

    return plainText;
}

// Function to create a digital signature as a vector of unsigned char
vector<unsigned char> createDigitalSignature(const string &message, EVP_PKEY *pkey)
{
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
    {
        throw runtime_error("Failed to create message digest context");
    }

    if (EVP_DigestSignInit(mdCtx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
    {
        EVP_MD_CTX_free(mdCtx);
        throw runtime_error("Failed to initialize signing operation");
    }

    if (EVP_DigestSignUpdate(mdCtx, message.c_str(), message.size()) <= 0)
    {
        EVP_MD_CTX_free(mdCtx);
        throw runtime_error("Failed to add message to signing operation");
    }

    size_t signatureLen;
    if (EVP_DigestSignFinal(mdCtx, nullptr, &signatureLen) <= 0)
    {
        EVP_MD_CTX_free(mdCtx);
        throw runtime_error("Failed to finalize signing operation to get signature length");
    }

    vector<unsigned char> signature(signatureLen);
    if (EVP_DigestSignFinal(mdCtx, signature.data(), &signatureLen) <= 0)
    {
        EVP_MD_CTX_free(mdCtx);
        throw runtime_error("Failed to finalize signing operation to get the actual signature");
    }

    EVP_MD_CTX_free(mdCtx);

    return signature;
}

// Function to verify a digital signature
bool verifyDigitalSignature(const string &message, const vector<unsigned char> &signature, EVP_PKEY *pkey)
{
    // Create the message digest context
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
    {
        throw runtime_error("Failed to create message digest context");
    }

    // Initialize the verification operation
    if (EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
    {
        EVP_MD_CTX_free(mdCtx);
        throw runtime_error("Failed to initialize verification operation");
    }

    // Add the message to be verified
    if (EVP_DigestVerifyUpdate(mdCtx, message.c_str(), message.size()) <= 0)
    {
        EVP_MD_CTX_free(mdCtx);
        throw runtime_error("Failed to add message to verification operation");
    }

    // Perform the verification
    const int result = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());

    EVP_MD_CTX_free(mdCtx);

    return result == 1;
}

bool verifyDigitalSignature(const string &message, const string &signature, EVP_PKEY *pkey)
{
    vector<unsigned char> vec = stringToVectorUnsignedChar(signature);
    return verifyDigitalSignature(message, vec, pkey);
}

// Funzione per estrarre la chiave pubblica da un certificato X509
EVP_PKEY *extractPublicKeyFromCert(X509 *cert)
{
    if (!cert)
    {
        throw std::invalid_argument("Invalid certificate provided!");
    }

    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (!pubkey)
    {
        throw std::runtime_error("Failed to extract public key from certificate!");
    }

    return pubkey; // Nota: l'oggetto EVP_PKEY restituito deve essere liberato successivamente
}

// Funzione per verificare se un certificato è associato a una data chiave pubblica
bool verifyCertWithPublicKey(X509 *cert, EVP_PKEY *public_key)
{
    if (!cert || !public_key)
    {
        throw std::invalid_argument("Invalid certificate or public key provided for verification!");
    }

    EVP_PKEY *cert_pubkey = extractPublicKeyFromCert(cert);

// Sopprimere l'avviso di deprecazione per EVP_PKEY_cmp
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    int result = EVP_PKEY_cmp(cert_pubkey, public_key);
#pragma GCC diagnostic pop

    EVP_PKEY_free(cert_pubkey); // Libera la chiave pubblica estratta

    if (result == 1)
    {
        return true;
    }
    else if (result == 0)
    {
        return false;
    }
    else
    {
        throw std::runtime_error("Error comparing public keys!");
    }
}

// Funzione per caricare un certificato da un file .pem e restituire l'oggetto X509*
X509 *loadCertFromPEM(const char *cert_path)
{
    FILE *file = fopen(cert_path, "r");
    if (!file)
    {
        throw std::runtime_error("Certificate file cannot be opened!");
    }

    X509 *cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!cert)
    {
        throw std::runtime_error("Certificate cannot be loaded!");
    }

    return cert;
}

// Funzione per convertire un oggetto X509* in una stringa PEM
std::string certToString(X509 *cert)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        throw std::runtime_error("BIO allocation failed!");
    }

    if (!PEM_write_bio_X509(bio, cert))
    {
        BIO_free(bio);
        throw std::runtime_error("Failed to write certificate to BIO!");
    }

    char *bio_data;
    long bio_length = BIO_get_mem_data(bio, &bio_data);

    std::string cert_str(bio_data, bio_length);
    BIO_free(bio);

    return cert_str;
}

// Funzione per convertire una stringa PEM in un oggetto X509*
X509 *stringToCert(const std::string &cert_str)
{
    BIO *bio = BIO_new_mem_buf(cert_str.data(), cert_str.size());
    if (!bio)
    {
        throw std::runtime_error("BIO allocation failed!");
    }

    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert)
    {
        throw std::runtime_error("Failed to read certificate from BIO!");
    }

    return cert;
}

// Funzione per verificare se un certificato X.509 è ancora valido
bool isCertificateValid(X509 *cert)
{
    if (!cert)
    {
        throw std::invalid_argument("Invalid certificate provided!");
    }

    // Ottieni la data corrente
    time_t now = time(nullptr);

    // Ottieni la data di scadenza dal certificato (puntatore costante)
    const ASN1_TIME *cert_expiry = X509_get0_notAfter(cert);
    if (!cert_expiry)
    {
        throw std::runtime_error("Failed to extract certificate expiration date!");
    }

    // Converti ASN1_TIME in struct tm
    struct tm cert_tm;
    if (!ASN1_TIME_to_tm(cert_expiry, &cert_tm))
    {
        throw std::runtime_error("Failed to convert ASN1_TIME to tm structure!");
    }

    // Converti la data di scadenza in time_t
    time_t cert_expiry_time = mktime(&cert_tm);

    // Confronta la data di scadenza con la data corrente
    if (cert_expiry_time < now)
    {
        // Il certificato è scaduto
        return false;
    }
    else
    {
        // Il certificato è ancora valido
        return true;
    }
}

// --------------- Generazione Numero Random --------------------------------------------------------------------------------

uint8_t generate_secure_random_8_unsigned_int()
{
    uint8_t random_number;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&random_number), sizeof(uint8_t)) != 1)
    {
        throw runtime_error("RAND_bytes failed");
    }
    return random_number;
}

uint16_t generate_secure_random_16_unsigned_int()
{
    uint16_t random_number;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&random_number), sizeof(uint16_t)) != 1)
    {
        throw runtime_error("RAND_bytes failed");
    }
    return random_number;
}

uint64_t generate_secure_random_64_unsigned_int()
{
    uint64_t random_number;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&random_number), sizeof(uint64_t)) != 1)
    {
        throw runtime_error("RAND_bytes failed");
    }
    return random_number;
}

int generate_secure_random_int()
{
    int random_number;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&random_number), sizeof(int)) != 1)
    {
        throw runtime_error("RAND_bytes failed");
    }
    return random_number;
}

string generateRandomSalt(size_t length = 64)
{
    vector<unsigned char> salt(length);

    if (!RAND_bytes(salt.data(), salt.size()))
    {
        throw runtime_error("Error generating random bytes for salt");
    }

    // Convert the salt to a hexadecimal string (if needed)
    ostringstream oss;
    for (size_t i = 0; i < salt.size(); ++i)
    {
        oss << hex << setw(2) << setfill('0') << static_cast<int>(salt[i]);
    }

    return oss.str();
}

string generateRandomKey(size_t length = 64)
{
    vector<unsigned char> aesKey(length);
    if (!RAND_bytes(aesKey.data(), aesKey.size()))
    {
        throw runtime_error("Error in the generation of the AES key");
    }
    return vectorUnsignedCharToString(aesKey);
}

void generateRSAKeyPair(string &publicKey, string &privateKey, int bits = 2048)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx)
    {
        throw runtime_error("Error creating EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Error initializing keygen context");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Error setting RSA key length");
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Error generating RSA key pair");
    }

    // Extract the private key
    BIO *privateBIO = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(privateBIO, pkey, nullptr, nullptr, 0, nullptr, nullptr))
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(privateBIO);
        throw runtime_error("Error writing private key to BIO");
    }

    // Extract the public key
    BIO *publicBIO = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(publicBIO, pkey))
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        BIO_free_all(privateBIO);
        BIO_free_all(publicBIO);
        throw runtime_error("Error writing public key to BIO");
    }

    // Convert the BIOs to strings
    char *privateKeyData;
    long privateKeyLen = BIO_get_mem_data(privateBIO, &privateKeyData);
    privateKey.assign(privateKeyData, privateKeyLen);

    char *publicKeyData;
    long publicKeyLen = BIO_get_mem_data(publicBIO, &publicKeyData);
    publicKey.assign(publicKeyData, publicKeyLen);

    // Free resources
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free_all(privateBIO);
    BIO_free_all(publicBIO);
}

#endif
