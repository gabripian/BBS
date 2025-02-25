#include <mutex>
#include <thread>

#include "lib/communicationLib/communicationLibrary.h"
#include "lib/communicationLib/messagePackingLibrary.h"

#include "configuration.h"

#include "lib/utilityLib/utilityFile.h"

#include "dataStructures/models/userBBS.h"
#include "dataStructures/models/messageBBS.h"
#include "dataStructures/models/connectionInformation.h"

#define MAXIMUM_NUMBER_OF_THREAD 100
#define MAXIMUM_REQUEST_NUMBER 1000
#define SNAPSHOT_PERIOD 30
#define CONNECTION_INFO_CHECK_PERIOD 15

#define MESSAGE_FILE_PATH "fileStorage/messageFile.txt"
#define USERS_FILE_PATH "fileStorage/userFile.txt"
#define USERS_PASSWORDS_FILE_PATH "fileStorage/userPasswords.txt"
#define CONNECTION_INFORMATION_FILE_PATH "fileStorage/connectionInfo.txt"

using namespace std;
// Variabili dei Threads
mutex mutexBBS;
mutex mutexUserList;
mutex mutexOpenSSL; // Required because OpenSSL is not thread-safe.
mutex mutexConnections;

mutex mutexFileStorage;

uint32_t threadNumber = 0;
uint32_t numberOfMessages = 0;
uint32_t id_tracker = 0;

vector<messageBBS> messageBoard;
vector<userBBS> userList;
vector<thread> threadMixer; // Vector of the threads descriptors.
vector<connectionInformation> connections;

EVP_PKEY *serverPrivateKey;
std::string encryptedAesKey;
std::string aesKey;

void threadSuicide()
{
    pthread_exit((void *)NULL);
}

string List(int n)
{
    string listed = "";
    if (n <= 0)
    {
        return listed;
    }
    mutexBBS.lock();
    if (numberOfMessages < n)
    {
        n = numberOfMessages;
    }

    uint32_t id = 0, i;
    for (i = 0; i < n; i++)
    {
        id = messageBoard[id_tracker - i].getId();
        if (id == 0)
        {
            continue; // Not valid post, so we go on.
        }
        listed += to_string(id) + " - " + messageBoard[id_tracker - i].getTitle() + '\n';
    }
    mutexBBS.unlock();

    if (listed == "")
    {
        listed = "No available messages";
    }
    return listed;
}

messageBBS Get(int mid)
{
    messageBBS m;
    mutexBBS.lock();
    if (mid <= 0 || mid > id_tracker)
    {
        m = messageBoard[0]; // not valid id.
    }
    else
    {
        if (messageBoard[mid].getId() == 0)
        {
            m = messageBoard[0]; // not valid message.
        }
        else
        {
            m = messageBoard[mid];
        }
    }
    mutexBBS.unlock();

    return m;
}

void insertNewMessage(messageBBS m, uint8_t mode = 0)
{
    // This function should insert the message in the perfect spot.
    if (mode == 0)
    {
        messageBoard.push_back(m); // Insert the new message in the back.
    }
}

void Add(string title, string author, string body)
{
    messageBBS m(0, author, title, body);
    mutexBBS.lock();
    id_tracker++;       // Autoincremental id.
    numberOfMessages++; // We got a new message in the board.
    m.setId(id_tracker);
    insertNewMessage(m);
    mutexBBS.unlock();
}

void Remove(uint32_t id)
{
    // To do.
    mutexBBS.lock();
    // numberOfMessages--;           // We got a new message in the board.
    messageBoard.at(id).setId(0); // Invalidate the message
    mutexBBS.unlock();
}

// insert all the users inside the file of users
void insertUserInFile(vector<userBBS> userList)
{
    string filenameGeneric("fileStorage/userFile.txt");
    string filenamePasswords("fileStorage/userPasswords.txt");
    // Delete the content of the entire file
    clearFileContent(filenameGeneric);
    clearFileContent(filenamePasswords);

    fstream userFile;
    userFile.open(filenameGeneric, std::fstream::app); // Open the file in append.
    if (userFile.is_open())
    {
        // ad a row in the file for each user
        for (uint64_t i = 0; i < userList.size(); i++)
        {
            userFile << userList.at(i).getNickname() + "-" +
                            userList.at(i).getSalt() + "-" +
                            userList.at(i).getEmail() + "-" +
                            userList.at(i).getCounter()
                     << endl;
        }
    }
    else
    {
        cout << "Error during the file opening" << endl;
    }
    userFile.close(); // Close the file.

    userFile.open(filenamePasswords, std::fstream::app); // Open the file in append.
    if (userFile.is_open())
    {
        // ad a row in the file for each user
        for (uint64_t i = 0; i < userList.size(); i++)
        {
            userFile << userList.at(i).getNickname() + "-" + userList.at(i).getPasswordDigest() << endl;
        }
    }
    else
    {
        cout << "Error during the file opening" << endl;
    }
    userFile.close(); // Close the file.
}

uint64_t checkUserListIndex(vector<userBBS> &userList, string inputNickname)
{
    uint64_t index = 0;
    const size_t size = userList.size();
    for (size_t i = 0; i < size; i++)
    {
        if (userList[i].getNickname() == inputNickname)
        {
            index = i;
            break;
        }
    }
    return index;
}

// insert all the users from the file into the vector
void insertUserInVector(vector<userBBS> &userList, string pathUsers = USERS_FILE_PATH, string pathPasswords = USERS_PASSWORDS_FILE_PATH)
{
    userList.clear();
    ifstream filenameGeneric(pathUsers);
    if (filenameGeneric.is_open())
    {
        string line;
        vector<string> ret;

        // for each line of the file extract all the attributes of a user and insert it into the vector
        while (getline(filenameGeneric, line))
        {
            deconcatenateFields(ret, line);
            // Assign each attribute to the user
            userBBS newUser;
            newUser.setNickname(ret.at(0));
            newUser.setSalt(ret.at(1));
            newUser.setEmail(ret.at(2));
            newUser.setCounter(ret.at(3));

            userList.push_back(newUser); // tail-insert the user inside the user list.
            ret.clear();
        }
    }
    else
    {
        cout << "Error during the users file opening" << endl;
    }
    filenameGeneric.close(); // Close the file

    ifstream filenamePasswords(pathPasswords);
    if (filenamePasswords.is_open())
    {
        string line;
        vector<string> ret;
        uint64_t index;

        // for each line of the file extract all the attributes of a user and insert it into the vector
        while (getline(filenamePasswords, line))
        {
            deconcatenateFields(ret, line);
            index = checkUserListIndex(userList, ret.at(0));
            userList[index].setPasswordDigest(ret.at(1));
            ret.clear();
        }
    }
    else
    {
        cout << "Error during the users passwords file opening" << endl;
    }
    filenamePasswords.close(); // Close the file
}

// insert all the messages inside the file of messages
void insertMessageInFile(vector<messageBBS> messageList, string path = MESSAGE_FILE_PATH)
{
    string filename(path);
    clearFileContent(filename); // delete the content of the entire file

    fstream messageFile;
    messageFile.open(filename, std::fstream::app); // open the file in append

    if (messageFile.is_open())
    {
        // ad a row in the file for each message
        for (uint64_t i = 0; i < messageList.size(); i++)
        {
            messageFile << to_string(messageList.at(i).getId()) + "-" + messageList.at(i).getAuthor() + "-" + messageList.at(i).getTitle() + "-" + messageList.at(i).getBody() << endl;
        }
    }
    else
    {
        cout << "Error during the file opening" << endl;
    }

    messageFile.close();
}

// insert all the messages from the file into the vector
void insertMessageInVector(vector<messageBBS> &messageList, string path = MESSAGE_FILE_PATH)
{
    ifstream filename(path);
    if (filename.is_open())
    {

        string line;
        vector<string> ret;

        // for each line of the file extract all the attributes of a message and insert it into the vector
        while (getline(filename, line))
        {
            // Here we must decrypt the line.
            deconcatenateFields(ret, line);
            // assign each attribute to the user
            messageBBS newMessage;
            newMessage.setId(stoi(ret.at(0))); // convert a string into a u_int32_t for the id field
            newMessage.setAuthor(ret.at(1));
            newMessage.setTitle(ret.at(2));
            newMessage.setBody(ret.at(3));

            // insert inside the vector
            messageList.push_back(newMessage);

            ret.clear();
        }
    }
    else
    {
        cout << "Error during the file opening" << endl;
    }

    filename.close(); // close file
}

// insert all the messages inside the file of messages
void insertConnectionInformationInFile(vector<connectionInformation> connList, string path = CONNECTION_INFORMATION_FILE_PATH)
{
    string filename(path);
    clearFileContent(filename); // delete the content of the entire file

    fstream connFile;
    connFile.open(filename, std::fstream::app); // open the file in append

    if (connFile.is_open())
    {
        // ad a row in the file for each message
        for (uint64_t i = 0; i < connList.size(); i++)
        {
            connFile << to_string(connList.at(i).getSocketDescriptor()) + "-" +
                            connList.at(i).getNickname() + "-" +
                            connList.at(i).getLoginTimestamp() + "-" +
                            connList.at(i).getLastActivityTimeStamp() + "-" +
                            to_string(connList.at(i).getLogged())
                     << endl;
        }
    }
    else
    {
        cout << "Error during the file opening" << endl;
    }

    connFile.close();
}

// insert all the messages from the file into the vector
void insertConnectionInformationInVector(vector<connectionInformation> &connList, string path = CONNECTION_INFORMATION_FILE_PATH)
{
    ifstream filename(path);

    if (filename.is_open())
    {
        string line;
        vector<string> ret;

        // for each line of the file extract all the attributes of a message and insert it into the vector
        while (getline(filename, line))
        {

            // Here we must decrypt the line.

            deconcatenateFields(ret, line);

            // assign each attribute to the user
            connectionInformation conn;
            conn.setSocketDescriptor(stoi(ret.at(0))); // convert a string into a u_int32_t for the id field
            conn.setNickname(ret.at(1));
            conn.setLoginTimestamp(ret.at(2));
            conn.setLastActivityTimeStamp(ret.at(3));
            conn.setLogged(stoi(ret.at(4)));

            connList.push_back(conn); // insert inside the vector.

            ret.clear();
        }
    }
    else
    {
        cout << "Error during the file opening" << endl;
    }

    filename.close(); // close file
}

void periodicCheckOfTheBoard()
{
    // This function should check for delete non valid messages.
}

void doConnectionListCheck()
{
    mutexConnections.lock();
    const size_t size = connections.size();
    for (size_t i = 0; i < size; i++)
    {
        if (!connections[i].checkValidityOfTheConnection() && connections[i].getLogged() == true)
        {
            // Connessione scaduta, l'utente ha chiuso il programma senza fare logout o è inattivo da troppo tempo.
            connections[i].setLogged(false);
        }
    }
    mutexConnections.unlock();
}

void periodicCheckOfTheConnectionsList()
{
    while (true)
    {
        this_thread::sleep_for(std::chrono::seconds(CONNECTION_INFO_CHECK_PERIOD));
        doConnectionListCheck();
    }
}

bool getConnectionInfoOfUser(string inputNickname, connectionInformation &conn)
{
    bool found = false;
    mutexConnections.lock();
    const size_t size = connections.size();
    for (size_t i = 0; i < size; i++)
    {
        if (connections[i].getNickname() == inputNickname)
        {
            conn = connections[i];
            found = true;
            break;
        }
    }
    mutexConnections.unlock();
    return found;
}

bool checkUserList(string inputNickname, userBBS &us)
{
    bool res = false;
    mutexUserList.lock();
    const size_t size = userList.size();
    for (size_t i = 0; i < size; i++)
    {
        if (userList[i].getNickname() == inputNickname)
        {
            us = userList[i];
            res = true;
            break;
        }
    }
    mutexUserList.unlock();
    return res;
}

bool checkUserList(string inputNickname)
{
    bool res = false;
    mutexUserList.lock();
    const size_t size = userList.size();
    for (size_t i = 0; i < size; i++)
    {
        if (userList[i].getNickname() == inputNickname)
        {
            res = true;
            break;
        }
    }
    mutexUserList.unlock();
    return res;
}

uint64_t getUserCounter(uint64_t index)
{
    uint64_t res;
    mutexUserList.lock();
    res = userList[index].getUintCounter();
    mutexUserList.unlock();
    return res;
}

void IncrementUserCounter(uint64_t index)
{
    mutexUserList.lock();
    userList[index].incrCounter(1);
    mutexUserList.unlock();
}

uint64_t checkUserListIndex(string inputNickname)
{

    uint64_t index = 0;
    mutexUserList.lock();
    const size_t size = userList.size();
    for (size_t i = 0; i < size; i++)
    {
        if (userList[i].getNickname() == inputNickname)
        {
            index = i;
            break;
        }
    }
    mutexUserList.unlock();
    return index;
}

bool checkUserEmail(string inputEmail)
{
    bool res = false;
    mutexUserList.lock();
    const size_t size = userList.size();

    for (size_t i = 0; i < size; i++)
    {
        if (userList[i].getEmail() == inputEmail)
        {
            res = true;
            break;
        }
    }
    mutexUserList.unlock();
    return res;
}

void refreshConnectionInformation(string inputNickname, int sd, string type = "generic")
{
    mutexConnections.lock();
    const size_t size = connections.size();
    for (size_t i = 0; i < size; i++)
    {
        if (connections[i].getNickname() == inputNickname)
        {
            if (type == "login")
            {
                connections[i].refreshLogin(sd);
            }
            else if (type == "logout")
            {
                connections[i].refreshLogout();
            }
            else if (type == "generic")
            {
                connections[i].refreshLastActionTimestamp();
            }
            break;
        }
    }
    mutexConnections.unlock();
}

void loadSnapshot()
{
    mutexFileStorage.lock();
    insertUserInVector(userList);
    insertMessageInVector(messageBoard);
    numberOfMessages = messageBoard.size();
    id_tracker = numberOfMessages - 1;
    insertConnectionInformationInVector(connections);
    mutexFileStorage.unlock();
}

void doSnapshot()
{
    // this function updates all the files in the fileStorage.
    mutexFileStorage.lock();
    insertUserInFile(userList);
    insertMessageInFile(messageBoard);
    insertConnectionInformationInFile(connections);
    mutexFileStorage.unlock();
}

void periodicSnaphot()
{
    while (true)
    {
        this_thread::sleep_for(std::chrono::seconds(SNAPSHOT_PERIOD));
        doSnapshot();
    }
}

uint8_t checkUserConnectionInfoAtLoginOrRegistration(string nickname)
{
    connectionInformation conn;

    if (getConnectionInfoOfUser(nickname, conn))
    {
        // There exists a connection of this user...
        if (conn.getLogged())
        {
            // The user is already logged!
            return 1;
        }

        if (!conn.checkValidityOfTheConnection())
        {
            // The connection info has errors!
            return 2;
        }
    }
    return 0;
}

void registrationProcedure(int socketDescriptor, bool &result, string &status, string &nickName, string K)
{
    bool valid = false;
    string req;
    userBBS ut;
    do
    {
        req = receiveString(socketDescriptor); // CONTENT MESSAGE - Receive the credentials from the client.

        ContentMessage msg;
        if (!verifyContentMessageHMAC(req, msg)) // Verify the HMAC of the received message.
        {
            // Not valid HMAC.
            close(socketDescriptor);
            threadSuicide();
        }

        try
        {
            req = ContentMessageGetContent(msg, K); // Extract (decrypt) the content from the message.
            ut.deconcatenateAndAssign(req);         // Extract the user info.
            ut.setCounter(0);                       // It is a registration, so we start from 0.
        }
        catch (const char *e)
        {
            cout << "not valid" << endl;
            continue;
        }

        string statusLocal = "ERROR-";

        result = true;

        if (!checkEmailFormat(ut.getEmail()))
        {
            result = false;
            string as = "Wrong email format\n";
            statusLocal = statusLocal + as;
        }

        if (checkUserEmail(ut.getEmail()))
        {
            result = false;
            string as = "This email already exists\n";
            statusLocal = statusLocal + as;
        }

        if (ut.getNickname().length() < 3)
        {
            result = false;
            string as = "Nickname must be at least of 3 characters\n";
            statusLocal = statusLocal + as;
        }

        if (ut.getPasswordDigest().length() < 5)
        {
            result = false;
            string as = "Password must be at least of 5 characters\n";
            statusLocal = statusLocal + as;
        }

        if (checkUserList(ut.getNickname())) // Check if the nickname have already been used.
        {
            result = false;
            string as = "This nickname already exists\n";
            statusLocal = statusLocal + as;
        }

        if (result)
        {
            valid = true;
            statusLocal = "ok";
        }

        status = statusLocal;
        sendString(socketDescriptor, packContentMessage(status, K)); // CONTENT MESSAGE - send the registration operation result.

    } while (!valid);

    // -------------------CHALLENGE -------------------------------

    string sendReq = to_string(generate_secure_random_16_unsigned_int()); // generate the challenge, a 16 bit unsigned int.
    sendString(socketDescriptor, packContentMessage(sendReq, K));         // CONTENT MESSAGE - Send the challenge.

    string recvReq = receiveString(socketDescriptor); // CONTENT MESSAGE -Receive the challenge.
    ContentMessage msg;
    if (verifyContentMessageHMAC(recvReq, msg))
    {
        if (sendReq == ContentMessageGetContent(msg, K))
        {
            // Challenge win!
            ut.setSalt(generateRandomSalt(8));
            ut.setPasswordDigest(computeHash(ut.getPasswordDigest(), ut.getSalt()));

            // We can insert the user in the list.
            mutexUserList.lock();
            userList.push_back(ut); // We insert the new user in the list.
            mutexUserList.unlock();

            connectionInformation c(socketDescriptor, ut.getNickname(), getCurrentTimestamp(), getCurrentTimestamp(), true);
            mutexConnections.lock();
            connections.push_back(c); // We insert the new user connection info in the list.
            mutexConnections.unlock();

            result = true;
            status = "User registered!";
            sendIntegerNumber(socketDescriptor, 1); // INTEGER MESSAGE - Send the result of the login/registration process.
            nickName = ut.getNickname();            // Save the nickname for later.
        }
        else
        {
            // Challenge failed.
            result = false;
            sendIntegerNumber(socketDescriptor, -1); // INTEGER MESSAGE - Send the result of the login/registration process.
            close(socketDescriptor);
            threadSuicide(); // The server thread terminates.
        }
    }
    else
    {
        // Not valid HMAC.
        close(socketDescriptor);
        threadSuicide();
    }
}

void loginProcedure(int socketDescriptor, bool &result, string &status, string &nickName, string K)
{
    string req;
    string statusLocal;
    userBBS ut;
    ContentMessage msg;
    vector<string> recvStrings;
    do
    {
        recvStrings.clear();
        result = true;
        statusLocal = "ERROR-";
        req = receiveString(socketDescriptor); // CONTENT MESSAGE - Receive the credentials from the client.

        if (!verifyContentMessageHMAC(req, msg)) // Verify the HMAC of the received message.
        {
            // Not valid HMAC.
            close(socketDescriptor);
            result = false;
            statusLocal = "No HMAC";
            return;
        }

        req = ContentMessageGetContent(msg, K); // Extract the content (credentials) from the content message.

        recvStrings = divideString(req); // Parse the credentials string.

        if (recvStrings[0].length() < 3)
        {
            result = false;
            string as = "Nickname must be at least of 3 characters\n";
            statusLocal = statusLocal + as;
        }

        if (recvStrings[1].length() < 5)
        {
            result = false;
            string as = "Password must be at least of 5 characters\n";
            statusLocal = statusLocal + as;
        }

        if (!checkUserList(recvStrings[0], ut)) // Check if the nickname have already been used.
        {
            result = false;
            string as = "This user does not exist\n";
            statusLocal = statusLocal + as;
        }
        else
        {
            if (ut.getPasswordDigest() != computeHash(recvStrings[1], ut.getSalt()))
            {
                result = false;
                string as = "Wrong password!\n";
                statusLocal = statusLocal + as;
            }
            else
            {
                if (checkUserConnectionInfoAtLoginOrRegistration(ut.getNickname()) == 1)
                {
                    result = false;
                    string as = "The user is already logged in!\n";
                    statusLocal = statusLocal + as;
                }
            }
        }

        if (result)
        {
            status = "ok-" + ut.getCounter();
            sendString(socketDescriptor, packContentMessage(status, K)); // CONTENT MESSAGE - Send the result of the login operation.

            // if the password of the choosen nickname is correct.
            refreshConnectionInformation(ut.getNickname(), socketDescriptor, "login");

            result = true;
            status = "Login ok!";
            sendIntegerNumber(socketDescriptor, 1); // INTEGER MESSAGE - Send the result of the login/registration process.
            nickName = ut.getNickname();
        }
        else
        {
            sendString(socketDescriptor, packContentMessage(statusLocal, K)); // CONTENT MESSAGE - Send the result of the login operation.
            // sendIntegerNumber(socketDescriptor, 0);                              // INTEGER MESSAGE - Send the result of the login/registration process.
        }

    } while (!result);
}

void BBSsession(int socketDescriptor, string nickNameRecv, string K)
{
    refreshConnectionInformation(nickNameRecv, socketDescriptor, "login");
    string req;
    ContentMessage msg;
    vector<string> requests;
    string content;
    int requestType;
    const uint64_t userIndex = checkUserListIndex(nickNameRecv);
    uint64_t counterCurrent = getUserCounter(userIndex);

    while (true)
    {
        req = receiveString(socketDescriptor); // CONTENT MESSAGE - Get the request from the client.

        msg.deconcatenateAndAssign(req);
        content = ContentMessageGetContent(msg, K); // Extract (decrypt) the test from the message.
        requests = divideString(content, '-');      // Parse the content of the message to elaborate the request.

        if (requests[0] == "logout")
        {
            uint64_t counterMsg = stoull(requests[1]);
            if (counterMsg == counterCurrent + 1)
            {
                refreshConnectionInformation(nickNameRecv, socketDescriptor, "logout");
                IncrementUserCounter(userIndex);
                counterCurrent++;
            }
            break;
        }
        else
        {
            if (stoull(requests[2]) == counterCurrent + 1)
            {
                // If the counter is correct
                requestType = stoi(requests[0]);

                if (requestType == LIST_REQUEST_TYPE)
                {
                    string pack = packContentMessage(List(stoi(requests[1])), K);
                    sendString(socketDescriptor, pack); // CONTENT MESSAGE - send the wanted operation result.
                }
                else if (requestType == GET_REQUEST_TYPE)
                {
                    string pack = packContentMessage(Get(stoi(requests[1])).toListed(), K);
                    sendString(socketDescriptor, pack); // CONTENT MESSAGE - send the wanted operation result.
                }
                else if (requestType == ADD_REQUEST_TYPE)
                {
                    vector<string> requestParts = divideString(requests[1], '|');
                    Add(requestParts[0], nickNameRecv, requestParts[1]);
                    sendIntegerNumber(socketDescriptor, 1); // INTEGER NUMBER - Send the result of the ADD operation.
                }

                refreshConnectionInformation(nickNameRecv, socketDescriptor, "generic"); // The user did something, so we record it.
                IncrementUserCounter(userIndex);                                         // The user sent a valid/invalid message, so we record it.
                counterCurrent++;
            }
        }
    }
    doSnapshot(); // Wen the session ends, we do a snapshot of the primary memory.
}

void threadServerCode(int new_sd)
{
    string nickNameSession = ""; // Temporary variable that keeps the nickname of the user that have just logged in.
    bool howItEnded = false;     // It becomes true if the procedure goes fine.
    string status = "";          // Explain the result of the procedure.

    string recvReq = receiveString(new_sd); // SIMPLE MESSAGE - Receive the first message from the client.
    SimpleMessage simpleMsg;
    simpleMsg.deconcatenateAndAssign(recvReq);

    vector<string> requestAndR = divideString(simpleMsg.getContent(), '-');

    const uint64_t R = stoull(requestAndR[1]);

    // ------------------ BEGIN RSAE ---------------------------

    string Tpubkey, Tprivkey;
    generateRSAKeyPair(Tpubkey, Tprivkey); // Generate the RSA temporary keys.

    RSAEMessage messageRSAE;
    messageRSAE.setPublicKey(Tpubkey);
    messageRSAE.computeDigitalFirm(R, loadRSAKey("serverPrivateKey/rsa_privkey.pem", false));
    messageRSAE.setCert(loadCertFromPEM("serverPublicKey/cacert.pem"));
    messageRSAE.concatenateFields(recvReq);

    sendString(new_sd, recvReq); // RSAE MESSAGE - Send the RSAE Message

    recvReq = receiveString(new_sd); // No TYPE MESSAGE - Receive the client response, which contains the sessione key.

    const string K = rsa_decrypt(recvReq, convertStringToPrivateEVP_PKEY(Tprivkey));
    // ------------------ END RSAE ---------------------------

    if (requestAndR[0] == "reg") // Registration.
    {
        registrationProcedure(new_sd, howItEnded, status, nickNameSession, K);
        if (howItEnded)
        {
            // If the registration went fine...
            BBSsession(new_sd, nickNameSession, K); // The actual session.
        }

        close(new_sd);
    }
    else if (requestAndR[0] == "log") // Registration.
    {

        loginProcedure(new_sd, howItEnded, status, nickNameSession, K);
        if (howItEnded)
        {
            // If the login procedure went fine...
            BBSsession(new_sd, nickNameSession, K); // The actual session.
        }
        close(new_sd);
    }
}

int main()
{
    int serverSocket, clientSocket, maxFd, activity;
    sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrSize = sizeof(clientAddr);
    fd_set readFds;
    std::vector<std::thread> threads;
    std::mutex clientSocketsMutex; // Mutex for synchronizing access to clientSockets vector.

    // load each file in the respective vector
    loadSnapshot();

    thread snapshotter(periodicSnaphot);
    snapshotter.detach();

    thread connectionListChecker(periodicCheckOfTheConnectionsList);
    connectionListChecker.detach();

    // Creazione del socket del server
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVER_PORT);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "bind failed: " << strerror(errno) << std::endl;
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, 5) == -1)
    {
        std::cerr << "listen failed: " << strerror(errno) << std::endl;
        close(serverSocket);
        return 1;
    }

    std::cout << "Server is listening on port 8080..." << std::endl;

    while (true)
    {
        // Clear and set the file descriptor set
        FD_ZERO(&readFds);
        FD_SET(serverSocket, &readFds);
        maxFd = serverSocket;

        // Wait for activity on the server socket
        activity = select(maxFd + 1, &readFds, nullptr, nullptr, nullptr);
        if (activity < 0 && errno != EINTR)
        {
            std::cerr << "select error: " << strerror(errno) << std::endl;
            close(serverSocket);
            return 1;
        }

        // If something happened on the server socket, it means a new connection
        if (FD_ISSET(serverSocket, &readFds))
        {
            clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrSize);
            if (clientSocket == -1)
            {
                std::cerr << "accept failed: " << strerror(errno) << std::endl;
                continue;
            }
            std::cout << "New client connected." << std::endl;

            // Crea un nuovo thread per gestire il client
            std::lock_guard<std::mutex> lock(clientSocketsMutex);
            threads.emplace_back(threadServerCode, clientSocket);
        }
    }

    // Chiudi il server socket
    close(serverSocket);

    for (auto &thread : threads)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }

    return 0;
}
