"""
    ##  Implementation of registry
    ##  150114822 - Eren Ulaş
"""

from socket import *
import threading
import select
import logging
import db
import re

# Password validation phase 2 :/
def is_password_valid(password):
    # at least 8 characters
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    # contains at least one numeral
    if not re.search(r'\d', password):
        return False, "Password must contain at least one numeral."
    # contains at least one capital letter
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one capital letter."
    # contains at least one special character
    if not re.search(r'\W', password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."

# Password hashing phase 2 :/
def hash_password(password):
    # Hash a password for the first time
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed.decode()

def check_password(hashed_password, user_password):
    # Check hashed password
    return bcrypt.checkpw(user_password.encode(), hashed_password.encode())

while True:
    try:
        # waits for incoming messages from peers
        message = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.ip + ":" + str(self.port) + " -> " + " ".join(message))
        #   JOIN    #
        if message[0] == "JOIN":
            # join-exist is sent to peer,
            # if an account with this username already exists
            if db.is_account_exist(message[1]):
                response = "join-exist"
                print("From-> " + self.ip + ":" + str(self.port) + " " + response)
                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                self.tcpClientSocket.send(response.encode())
            # join-success is sent to peer,
            # if an account with this username is not exist, and the account is created
            # edited this section to add hashing
            else:
                is_valid, validation_message = is_password_valid(message[2])
                if is_valid:
                    hashed_password = hash_password(message[2])
                    db.register(message[1], hashed_password)
                    response = "join-success"
                else:
                    response = "join-invalid-password: " + validation_message
                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                self.tcpClientSocket.send(response.encode())
    except Exception as e:
        logging.error(str(e))


    # main of the thread
    def run(self):
        # locks for thread which will be used for thread synchronization
        self.lock = threading.Lock()
        print("Connection from: " + self.ip + ":" + str(port))
        print("IP Connected: " + self.ip)

        while True:
            try:
                # waits for incoming messages from peers
                message = self.tcpClientSocket.recv(1024).decode().split()
                logging.info("Received from " + self.ip + ":" + str(self.port) + " -> " + " ".join(message))
                #   JOIN    #
                if message[0] == "JOIN":
                    # join-exist is sent to peer,
                    # if an account with this username already exists
                    if db.is_account_exist(message[1]):
                        response = "join-exist"
                        print("From-> " + self.ip + ":" + str(self.port) + " " + response)
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # join-success is sent to peer,
                    # if an account with this username is not exist, and the account is created
                    # edited this section to add hashing
                    else:
                        is_valid, validation_message = is_password_valid(message[2])
                        if is_valid:
                            hashed_password = hash_password(message[2])
                            db.register(message[1], hashed_password)
                            response = "join-success"
                        else:
                            response = "join-invalid-password: " + validation_message
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                #   LOGIN    #
                elif message[0] == "LOGIN":
                    # login-account-not-exist is sent to peer,
                    # if an account with the username does not exist
                    if not db.is_account_exist(message[1]):
                        response = "login-account-not-exist"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # login-online is sent to peer,
                    # if an account with the username already online
                    elif db.is_account_online(message[1]):
                        response = "login-online"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # login-success is sent to peer,
                    # if an account with the username exists and not online
                    else:
                        # retrieves the account's hashed password, and checks
                        # if the one entered by the user(after hashing it) is correct
                        hashed_password = db.get_password(message[1])
                        if check_password(hashed_password, message[2]):
                            self.username = message[1]
                            self.lock.acquire()
                            try:
                                tcpThreads[self.username] = self
                            finally:
                                self.lock.release()

                            db.user_login(message[1], self.ip, message[3])
                            # login-success is sent to peer,
                            # and an udp server thread is created for this peer, and thread is started
                            # timer thread of the udp server is started
                            response = "login-success"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                            self.udpServer = UDPServer(self.username, self.tcpClientSocket)
                            self.udpServer.start()
                            self.udpServer.timer.start()
                        # if password not matches and then login-wrong-password response is sent
                        else:
                            response = "login-wrong-password"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())

                #   LOGOUT  #
                elif message[0] == "LOGOUT":
                    # if user is online,
                    # removes the user from onlinePeers list
                    # and removes the thread for this user from tcpThreads
                    # socket is closed and timer thread of the udp for this
                    # user is cancelled
                    if len(message) > 1 and message[1] is not None and db.is_account_online(message[1]):
                        db.user_logout(message[1])
                        self.lock.acquire()
                        try:
                            if message[1] in tcpThreads:
                                del tcpThreads[message[1]]
                        finally:
                            self.lock.release()
                        print(self.ip + ":" + str(self.port) + " is logged out")
                        self.tcpClientSocket.close()
                        self.udpServer.timer.cancel()
                        break
                    else:
                        self.tcpClientSocket.close()
                        break
                #   SEARCH  #
                elif message[0] == "SEARCH":
                    # checks if an account with the username exists
                    if db.is_account_exist(message[1]):
                        # checks if the account is online
                        # and sends the related response to peer
                        if db.is_account_online(message[1]):
                            peer_info = db.get_peer_ip_port(message[1])
                            response = "search-success " + peer_info[0] + ":" + peer_info[1]
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                        else:
                            response = "search-user-not-online"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                    # enters if username does not exist 
                    else:
                        response = "search-user-not-found"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))

    # function for resetting the timeout for the udp timer thread
    def resetTimeout(self):
        self.udpServer.resetTimer()


# implementation of the udp server thread for clients
class UDPServer(threading.Thread):

    # udp server thread initializations
    def __init__(self, username, clientSocket):
        threading.Thread.__init__(self)
        self.username = username
        # timer thread for the udp server is initialized
        self.timer = threading.Timer(3, self.waitHelloMessage)
        self.tcpClientSocket = clientSocket

    # if hello message is not received before timeout
    # then peer is disconnected
    def waitHelloMessage(self):
        if self.username is not None:
            db.user_logout(self.username)
            if self.username in tcpThreads:
                del tcpThreads[self.username]
        self.tcpClientSocket.close()
        print("Removed " + self.username + " from online peers")

    # resets the timer for udp server
    def resetTimer(self):
        self.timer.cancel()
        self.timer = threading.Timer(3, self.waitHelloMessage)
        self.timer.start()


# tcp and udp server port initializations
print("Registry started...")
port = 15600
portUDP = 15500

# db initialization
db = db.DB()

# gets the ip address of this peer
# first checks to get it for Windows devices
# if the device that runs this application is not windows
# it checks to get it for macOS devices
hostname = gethostname()
try:
    host = gethostbyname(hostname)
except gaierror:
    import netifaces as ni

    host = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

print("Registry IP address: " + host)
print("Registry port number: " + str(port))

# onlinePeers list for online account
onlinePeers = {}
# accounts list for accounts
accounts = {}
# tcpThreads list for online client's thread
tcpThreads = {}

# tcp and udp socket initializations
tcpSocket = socket(AF_INET, SOCK_STREAM)
udpSocket = socket(AF_INET, SOCK_DGRAM)
tcpSocket.bind((host, port))
udpSocket.bind((host, portUDP))
tcpSocket.listen(5)

# input sockets that are listened
inputs = [tcpSocket, udpSocket]

# log file initialization
logging.basicConfig(filename="registry.log", level=logging.INFO)

# as long as at least a socket exists to listen registry runs
while inputs:

    print("Listening for incoming connections...")
    # monitors for the incoming connections
    readable, writable, exceptional = select.select(inputs, [], [])
    for s in readable:
        # if the message received comes to the tcp socket
        # the connection is accepted and a thread is created for it, and that thread is started
        if s is tcpSocket:
            tcpClientSocket, addr = tcpSocket.accept()
            newThread = ClientThread(addr[0], addr[1], tcpClientSocket)
            newThread.start()
        # if the message received comes to the udp socket
        elif s is udpSocket:
            # received the incoming udp message and parses it
            message, clientAddress = s.recvfrom(1024)
            message = message.decode().split()
            # checks if it is a hello message
            if message[0] == "HELLO":
                # checks if the account that this hello message 
                # is sent from is online
                if message[1] in tcpThreads:
                    # resets the timeout for that peer since the hello message is received
                    tcpThreads[message[1]].resetTimeout()
                    print("Hello is received from " + message[1])
                    logging.info(
                        "Received from " + clientAddress[0] + ":" + str(clientAddress[1]) + " -> " + " ".join(message))

# registry tcp socket is closed
tcpSocket.close()
