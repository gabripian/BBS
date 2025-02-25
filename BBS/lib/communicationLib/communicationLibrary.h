#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <time.h>
#include <wait.h>
#include <signal.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>

#include "../securityLib/security.h"

#ifndef COMMUNICATIONLIBRARY_H
#define COMMUNICATIONLIBRARY_H

// Funzione per inviare una stringa tramite un socket
bool sendString(int socketDescriptor, string message)
{
    vector<uint8_t> buffer(message.begin(), message.end()); // Converto la stringa in una sequenza di byte
    size_t length = buffer.size();                          // Calcolo la lunghezza della stringa da inviare.
    // Invio la lunghezza della stringa
    if (send(socketDescriptor, &length, sizeof(length), 0) == -1)
    {
        cerr << "Errore nell'invio della lunghezza della stringa\n";
        return false;
    }
    // Invio i dati della stringa
    if (send(socketDescriptor, buffer.data(), buffer.size(), 0) == -1)
    {
        cerr << "Errore nell'invio dei dati della stringa\n";
        return false;
    }
    return true; // L'invio ha avuto successo.
}

// Funzione per inviare una stringa tramite un socket
bool sendString(int socketDescriptor, string message, string K)
{
    string cipher = vectorUnsignedCharToString(encrypt_AES(message, K));
    return sendString(socketDescriptor, cipher);
}

// Funzione per ricevere una stringa tramite un socket
std::string receiveString(int socketDescriptor)
{
    // Ricevo la lunghezza della stringa
    size_t length = 0;
    if (recv(socketDescriptor, &length, sizeof(length), 0) < 0)
    {
        pthread_exit((void *)NULL); // Not valid received string, the thread will kill itself.
    }

    if (length == 0)
    {
        pthread_exit((void *)NULL);  // Not valid received string, the thread will kill itself.
    }

    // Alloco un buffer per ricevere i dati della stringa
    vector<uint8_t> buffer(length);

    // Ricevo i dati della stringa
    if (recv(socketDescriptor, buffer.data(), length, 0) < 0)
    {
        pthread_exit((void *)NULL);  // Not valid received string, the thread will kill itself.
    }

    if (length == 0)
    {
        pthread_exit((void *)NULL);  // Not valid received string, the thread will kill itself.
    }

    string message(buffer.begin(), buffer.end());  // Converto il buffer in una stringa.
    return message;
}

// Funzione per ricevere una stringa tramite un socket
std::string receiveString(int socketDescriptor, string K)
{
    return decrypt_AES(stringToUnsignedCharVector(receiveString(socketDescriptor)), K);
}

void sendIntegerNumber(int sd, int mess)
{
    uint32_t msg = htonl(mess);
    if (send(sd, (void *)&msg, sizeof(uint32_t), 0) < 0)
    {
        pthread_exit((void *)NULL);
    }
}

int receiveIntegerNumber(int sd)
{
    uint32_t msg = 0;
    if (recv(sd, (void *)&msg, sizeof(uint32_t), 0) < 0)
    {
        pthread_exit((void *)NULL); // Not valid received string, the thread will kill itself.
    }
    else
    {
        return (int)(ntohl(msg));
    }
}

#endif