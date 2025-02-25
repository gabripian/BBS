#include "../../lib/utilityLib/utility.h"
using namespace std;

#ifndef MESSAGEBBS_H
#define MESSAGEBBS_H

class messageBBS{
private:
    uint32_t id;
    string author;
    string title;
    string body;

public:
     // Costruttore di default
    messageBBS() {}

    // Costruttore che inizializza tutti i membri della classe
    messageBBS(uint32_t newId, string newAuthor, string newTitle, string newBody){
        this->id = newId;
        this->author = newAuthor;
        this->title = newTitle;
        this->body = newBody;
    }

    messageBBS(int newId, string newAuthor, string newTitle, string newBody){
        this->id = static_cast<uint32_t>(newId);
        this->author = newAuthor;
        this->title = newTitle;
        this->body = newBody;
    }

    // Distruttore
    ~messageBBS() {
        // In questo caso, non è necessario fare nulla nel distruttore
    }

    void setId(uint32_t newId)
    {
        id = newId;
    }

    void setId(int newId)
    {
        id = static_cast<uint32_t>(newId);
    }

    void setAuthor(string newAuthor)
    {
        author = newAuthor;
    }

    void setTitle(string newTitle)
    {
        title = newTitle;
    }

    void setBody(const string &newBody)
    {
        body = newBody;
    }

    // Metodi get per ottenere i valori dei membri della classe
    uint32_t getId() const
    {
        return id;
    }

    string getAuthor() const
    {
        return author;
    }

    string getTitle() const
    {
        return title;
    }

    string getBody() const
    {
        return body;
    }

    void concatenateFields(string &str) {
        ostringstream oss;
        const char delimiter = '-';
        oss << this->id << delimiter
            << this->author.length() << delimiter
            << this->title.length() << delimiter
            << this->body.length() << delimiter
            << this->author
            << this->title
            << this->body;
        str = oss.str();
    }

    void deconcatenateAndAssign(string& input) {
        vector<string> stringVector;
        this->deconcatenateFields(stringVector, input);
        if (stringVector.size() == 3) {
            this->author = stringVector[0];
            this->title = stringVector[1];
            this->body = stringVector[2];
        }
    }

    void deconcatenateFields(vector<string> &result, string &input) {
        result.clear();
        istringstream iss(input);
        string part;

        // Read the id
        getline(iss, part, '-');
        this->id = stoul(part);

        // Read the lengths
        int lengthAuthor, lengthTitle, lengthBody;
        getline(iss, part, '-');
        lengthAuthor = stoi(part);
        getline(iss, part, '-');
        lengthTitle = stoi(part);
        getline(iss, part, '-');
        lengthBody = stoi(part);

        // Read the actual fields based on the lengths
        result.push_back(input.substr(iss.tellg(), lengthAuthor));
        iss.seekg(iss.tellg() + streampos(lengthAuthor));
        result.push_back(input.substr(iss.tellg(), lengthTitle));
        iss.seekg(iss.tellg() + streampos(lengthTitle));
        result.push_back(input.substr(iss.tellg(), lengthBody));
    }

    void computeMAC(string &MAC)
    {
        MAC = "That MAC";
    }

    void encrypt(string &c)
    {
        c = "Cypher";
    }

    // Metodo per convertire l'oggetto in formato JSON
   string toJSON() const {
        string json = "{";
        json.append("\"id\": \"").append(to_string(this->id)).append("\",");
        json.append("\"author\": \"").append(author).append("\",");
        json.append("\"title\": \"").append(title).append("\",");
        json.append("\"body\": \"").append(body).append("\"");
        json.append("}");
        return json;
    }

    string toListed(){
        string ret = this->getAuthor() + " - " + this->getTitle() + " - " + this->getBody() + "\n" + "\n";  
        return ret;
    }
    
    bool invalidMessage(){
        return this->getId() == 0;
    }
};

#endif
