#include "../../dataStructures/messageStructures/simpleMessage.h"
#include "../../dataStructures/messageStructures/contentMessage.h"
#include "../../dataStructures/messageStructures/RSAEMessage.h"
#include "../securityLib/security.h"

#ifndef MESSAGEPACKINGLIBRARY_H
#define MESSAGEPACKINGLIBRARY_H


string packSimpleMessage(string recvString)
{
    string ret;
    SimpleMessage msg;
    msg.setContent(recvString);
    msg.concatenateFields(ret); // Concatenate the entire message in a single string.
    return ret;
}

string packContentMessage(string recvString, string K, uint8_t IV_lenght = 16)
{
    string ret;
    ContentMessage msg;
    msg.setIV(generateRandomKey(IV_lenght)); // Generate a 16-bit random IV.
    msg.setC(vectorUnsignedCharToString(encrypt_AES(recvString, K))); // create the encrypted text.
    msg.setHMAC(calculateHMAC(msg.getIV(), msg.getC())); // Compute the HMAC on the encrypted text.
    msg.concatenateFields(ret); // Concatenate the entire message in a single string.
    return ret;
}

string ContentMessageGetContent(ContentMessage& msg, string K){
    return decrypt_AES(msg.getC() , K); // Decrypt and return the content of a content message.
}

bool verifyContentMessageHMAC(string result , ContentMessage& msg)
{
    msg.deconcatenateAndAssign(result); // From the string we reconstruct the content message.
    return verifyHMAC(msg.getIV(), msg.getC(), msg.getHMAC()); // Using the method we verify the integrity of the message.
}


bool verifyContentMessageHMAC(string result)
{
    ContentMessage msg;
    return verifyContentMessageHMAC(result , msg);
}

#endif