#include <iostream>
#include <string>
#include <sstream>
#include <vector>

using namespace std;

#ifndef CONTENTMESSAGE_H
#define CONTENTMESSAGE_H

class ContentMessage
{
private:
    size_t IVdim;
    size_t Cdim;
    size_t HMACdim;
    string IV;
    string C;
    string HMAC;

public:
    // Costruttore di default
    ContentMessage() {}

    // Costruttore parametrizzato
    ContentMessage(const string &IV, const string &C, const string &HMAC)
    {
        this->IV = IV;
        this->C = C;
        this->HMAC = HMAC;
        this->IVdim = this->IV.size();
        this->Cdim = this->C.size();
        this->HMACdim = this->HMAC.size();
    }

    // Costruttore parametrizzato
    ContentMessage(string &IV, string &C, string &HMAC)
    {
        this->IV = IV;
        this->C = C;
        this->HMAC = HMAC;
        this->IVdim = this->IV.size();
        this->Cdim = this->C.size();
        this->HMACdim = this->HMAC.size();
    }

    // Getter e Setter per IVdim
    size_t getIVdim() const
    {
        return IVdim;
    }

    void setIVdim(size_t IVdim)
    {
        this->IVdim = IVdim;
    }

    // Getter e Setter per Cdim
    size_t getCdim() const
    {
        return Cdim;
    }

    void setCdim(size_t Cdim)
    {
        this->Cdim = Cdim;
    }

    // Getter e Setter per HMACdim
    size_t getHMACdim() const
    {
        return HMACdim;
    }

    void setHMACdim(size_t HMACdim)
    {
        this->HMACdim = HMACdim;
    }

    // Getter e Setter per IV
    string getIV() const
    {
        return IV;
    }

    void setIV(const string &IV)
    {
        this->IV = IV;
        this->IVdim = IV.size();
    }

    // Getter e Setter per C
    string getC() const
    {
        return C;
    }

    void setC(const string &C)
    {
        this->C = C;
        this->Cdim = C.size();
    }

    // Getter e Setter per HMAC
    string getHMAC() const
    {
        return HMAC;
    }

    void setHMAC(const string &HMAC)
    {
        this->HMAC = HMAC;
        this->HMACdim = HMAC.size();
    }

    // Metodo per concatenare i campi in una stringa
    void concatenateFields(string &str) const
    {
        ostringstream oss;
        const char delimiter = '-';
        oss << IVdim << delimiter
            << Cdim << delimiter
            << HMACdim << delimiter
            << IV
            << C
            << HMAC;
        str = oss.str();
    }

    // Metodo per deconcatenare i campi da una stringa
    void deconcatenateFields(vector<string> &result, const string &input) const
    {
        result.clear();
        istringstream iss(input);
        string part;

        // Leggi le dimensioni
        getline(iss, part, '-');
        size_t lengthIV = stoull(part);
        getline(iss, part, '-');
        size_t lengthC = stoull(part);
        getline(iss, part, '-');
        size_t lengthHMAC = stoull(part);

        // Leggi i campi
        result.push_back(input.substr(iss.tellg(), lengthIV));
        iss.seekg(iss.tellg() + streampos(lengthIV));
        result.push_back(input.substr(iss.tellg(), lengthC));
        iss.seekg(iss.tellg() + streampos(lengthC));
        result.push_back(input.substr(iss.tellg(), lengthHMAC));
    }

    // Metodo per deconcatenare e assegnare i campi da una stringa
    void deconcatenateAndAssign(const string &input)
    {
        vector<string> stringVector;
        this->deconcatenateFields(stringVector, input);
        if (stringVector.size() == 3)
        {
            this->IV = stringVector[0];
            this->C = stringVector[1];
            this->HMAC = stringVector[2];
            this->IVdim = IV.size();
            this->Cdim = C.size();
            this->HMACdim = HMAC.size();
        }
    }
};

#endif
