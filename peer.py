"""
    ## Extending Eran Ulas' Chatting Application
    ## Team 24
"""

import select
import logging
from socket import *
import threading
import CliEditor
import datetime


# Server side of peer
class PeerServer(threading.Thread):

    # Peer server initialization
    def __init__(self, username, peerServerPort, roomServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.peerServerHostname = None
        self.username = username
        # tcp socket for peer server
        self.tcpServerSocket = socket(AF_INET, SOCK_STREAM)
        self.udpServerSocket = socket(AF_INET, SOCK_DGRAM)
        # port number of the peer server
        self.peerServerPort = peerServerPort
        self.roomServerPort = roomServerPort
        # if 1, then user is already chatting with someone
        # if 0, then user is not chatting with anyone
        self.isChatRequested = 0
        # keeps the socket for the peer that is connected to this peer
        self.connectedPeerSocket = None
        # keeps the ip of the peer that is connected to this peer's server
        self.connectedPeerIP = None
        # keeps the port number of the peer that is connected to this peer's server
        self.connectedPeerPort = None
        # online status of the peer
        self.isOnline = True
        # keeps the username of the peer that this peer is chatting with
        self.chattingClientName = None
        self.chat = 0
        self.room = 0
        # def get_chatroom_hostname(self):

    #     return self.chatroomServerHostname

    # main method of the peer server thread
    def run(self):

        CliEditor.green_message("Peer server started...")

        # gets the ip address of this peer
        # first checks to get it for Windows devices
        # if the device that runs this application is not windows
        # it checks to get it for macOS devices
        hostname = gethostname()
        try:
            self.peerServerHostname = gethostbyname(hostname)
        except gaierror:
            import netifaces as ni
            self.peerServerHostname = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']
        try:
            self.udpServerSocket.bind((self.peerServerHostname, self.roomServerPort))
            # ip address of this peer
            # self.peerServerHostname = 'localhost'
            # socket initializations for the server of the peer
            self.tcpServerSocket.bind((self.peerServerHostname, self.peerServerPort))
            self.tcpServerSocket.listen(4)
        except OSError:
            CliEditor.red_message_without_space("This port number is already used.")

        # inputs sockets that should be listened
        inputs = [self.udpServerSocket, self.tcpServerSocket]
        # server listens as long as there is a socket to listen in the inputs list and the user is online
        while inputs and self.isOnline:
            # monitors for the incoming connections
            try:
                readable, writable, exceptional = select.select(inputs, [], [])
                # If a server waits to be connected enters here
                for s in readable:
                    # if the socket that is receiving the connection is
                    # the tcp socket of the peer's server, enters here
                    if s is self.tcpServerSocket and self.room == 0:
                        # accepts the connection, and adds its connection socket to the inputs list
                        # so that we can monitor that socket as well
                        connected, addr = s.accept()
                        connected.setblocking(0)
                        inputs.append(connected)
                        # if the user is not chatting, then the ip and the socket of
                        # this peer is assigned to server variables
                        if self.isChatRequested == 0:
                            CliEditor.green_message(self.username + " is connected from " + str(addr))
                            self.connectedPeerSocket = connected
                            self.connectedPeerIP = addr[0]
                    # if the socket that is receiving the connection is
                    # the udp socket of the peer's server, enters here
                    elif s is self.udpServerSocket and self.room == 1:
                        while 1:
                            data, address = self.udpServerSocket.recvfrom(1024)
                            CliEditor.format_message(messageReceived)
                            CliEditor.activate_link(messageReceived)
                            messageReceived = data.decode()
                            CliEditor.green_message(
                                messageReceived + "  " + str(datetime.datetime.now().strftime('%H:%M')))
                            if self.room == 0:
                                break

                    # if the socket that receives the data is the one that
                    # is used to communicate with a connected peer, then enters here
                    elif self.room == 0:
                        # message is received from connected peer
                        messageReceived = s.recv(1024).decode()
                        # logs the received message
                        logging.info("Received from " + str(self.connectedPeerIP) + " -> " + str(messageReceived))
                        # if message is a request message it means that this is the receiver side peer server
                        # so evaluate the chat request
                        if len(messageReceived) > 11 and messageReceived[:12] == "CHAT-REQUEST":
                            # text for proper input choices is printed however OK or REJECT is taken as input in main
                            # process of the peer if the socket that we received the data belongs to the peer that we
                            # are chatting with, enters here
                            if s is self.connectedPeerSocket:
                                # parses the message
                                messageReceived = messageReceived.split()
                                # gets the port of the peer that sends the chat request message
                                self.connectedPeerPort = int(messageReceived[1])
                                # gets the username of the peer sends the chat request message
                                self.chattingClientName = messageReceived[2]
                                # prints prompt for the incoming chat request
                                CliEditor.blue_message(
                                    "Incoming chat request from " + self.chattingClientName + " >> ")

                                print("Enter " + CliEditor.green_message_without_space(
                                    'OK ') + "to accept or " + CliEditor.red_message_without_space(
                                    'REJECT ') + "to reject: ")
                                # makes isChatRequested = 1 which means that peer is chatting with someone
                                self.isChatRequested = 1
                            # if the socket that we received the data does not belong to the peer that we are
                            # chatting with and if the user is already chatting with someone else(isChatRequested =
                            # 1), then enters here
                            elif s is not self.connectedPeerSocket and self.isChatRequested == 1:
                                # sends a busy message to the peer that sends a chat request when this peer is
                                # already chatting with someone else
                                message = "BUSY"
                                s.send(message.encode())
                                # remove the peer from the inputs list so that it will not monitor this socket
                                inputs.remove(s)
                        # if an OK message is received then is_chat_requested is made 1 and then next messages will
                        # be shown to the peer of this server
                        elif messageReceived == "OK":
                            CliEditor.yellow_message("\nWrite :q to quit chat.")
                            self.isChatRequested = 1
                        # if an REJECT message is received then is_chat_requested is made 0 so that it can receive
                        # any other chat requests
                        elif messageReceived == "REJECT":
                            self.isChatRequested = 0
                            inputs.remove(s)
                        # if a message is received, and if this is not a quit message ':q' and
                        # if it is not an empty message, show this message to the user

                        elif messageReceived[:2] != ":q" and len(messageReceived) != 0:
                            CliEditor.format_message(messageReceived)
                            CliEditor.activate_link(messageReceived)
                            CliEditor.blue_message(self.chattingClientName + ": " + messageReceived + "  " + str(
                                datetime.datetime.now().strftime('%H:%M')))
                        # if the message received is a quit message ':q',
                        # makes is_chat_requested 1 to receive new incoming request messages
                        # removes the socket of the connected peer from the inputs list
                        elif messageReceived[:2] == ":q":
                            if self.room == 1:
                                self.room = 0  # user quit chatroom
                            else:
                                self.isChatRequested = 0
                                inputs.clear()
                                inputs.append(self.tcpServerSocket)
                                # ######## UPDATE HERE #########
                                # self.tcpServerSocket.close()
                                self.chat = 0
                                # self.peerClient.flag = None
                                # connected peer ended the chat
                                if len(messageReceived) == 2:
                                    CliEditor.red_message("The user you're chatting has ended the chat")
                                    print("Press enter to quit the chat")
                        # if the message is an empty one, then it means that the
                        # connected user suddenly ended the chat(an error occurred)
                        elif len(messageReceived) == 0:
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            CliEditor.red_message("The user you're chatting with suddenly ended the chat")
                            CliEditor.blue_message("Press enter to quit the chat")
            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))


# Client side of peer
def get_local_ip():
    # Dynamically obtain the local IP address
    hostname = gethostname()
    try:
        return gethostbyname(hostname)
    except gaierror:
        import netifaces as ni
        return ni.ifaddresses('en0')[ni.AF_INET][0]['addr']


class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, ipToConnect, portToConnect, username, peerServer, responseReceived, flag, roomId,
                 room_peers: list, registry_name=None):
        threading.Thread.__init__(self)
        # keeps the ip address of the peer that this will connect
        # ip address of the registry

        self.ipToConnect = ipToConnect
        self.registryName = registry_name or get_local_ip()
        # self.registryName = 'localhost'
        # port number of the registry
        self.registryPort = 15600

        # keeps the username of the peer
        self.username = username
        # keeps the port number that this client should connect
        self.portToConnect = portToConnect
        # client side tcp socket initialization
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        self.udpClientSocket = socket(AF_INET, SOCK_DGRAM)
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the phrase that is used when creating the client
        # if the client is created with a phrase, it means this one received the request
        # this phrase should be none if this is the client of the requester peer
        self.responseReceived = responseReceived
        # keeps if this client is ending the chat or not
        self.isEndingChat = False
        # flag to indicate room or normal chat
        self.flag = flag
        # RoomID
        self.roomId = roomId
        # list of room_peers
        self.room_peers = room_peers
        self.isRoomEmpty = False

    # this function is used to exit the room
    def update_peers(self):
        message = "UPDATE " + str(self.roomId)
        self.tcpClientSocket.send(message.encode())
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        response = self.tcpClientSocket.recv(1024).decode()
        list_start = response.index('[')
        list_end = response.index(']') + 1
        list_string = response[list_start:list_end]
        response = response.split()
        response2 = eval(list_string)
        self.room_peers = response2

    def exit(self):
        # Need to access peerServerObject to get roomPortNo to remove from list
        port_to_remove = self.peerServer.roomServerPort
        # Then go to registry and remove him
        request = "EXIT " + str(self.roomId) + " " + str(port_to_remove)
        # print("Sending EXIT request:", request)
        self.tcpClientSocket.send(request.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        # print("Received EXIT response:", response)

        # Display Message ("USERNAME Disconnected")
        return response

    # main method of the peer client thread
    def run(self):

        if self.flag == '1':  # indicates one-to-one chat started
            CliEditor.green_message("Peer client has started...")
            # connects to the server of other peer
            CliEditor.green_message("Connecting to " + self.ipToConnect + ":" + str(self.portToConnect) + "...")

            self.tcpClientSocket.connect((self.ipToConnect, self.portToConnect))
            # if the server of this peer is not connected by someone else and if this is the requester side peer client
            # then enters here
            if self.peerServer.isChatRequested == 0 and self.responseReceived is None:
                # composes a request message and this is sent to server and then this waits a response message from the
                # server this client connects
                requestMessage = "CHAT-REQUEST " + str(self.peerServer.peerServerPort) + " " + self.username
                # logs the chat request sent to other per
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + requestMessage)
                # sends the chat request
                self.tcpClientSocket.send(requestMessage.encode())
                CliEditor.green_message("Request message " + requestMessage + " is sent...")
                # received a response from the peer which the request message is sent to
                try:
                    self.responseReceived = self.tcpClientSocket.recv(1024).decode()
                    logging.info("Received from " + self.ipToConnect + ":" + str(
                        self.portToConnect) + " -> " + self.responseReceived)
                except ConnectionResetError:
                    logging.error("ConnectionResetError: The connection was forcibly closed by the remote host.")
                CliEditor.green_message("Response is " + self.responseReceived)
                # parses the response for the chat request
                self.responseReceived = self.responseReceived.split()
                # if response is ok then incoming messages will be evaluated as client messages and will be sent to the
                # connected server
                if self.responseReceived[0] == "OK":
                    # changes the status of this client's server to chatting
                    self.peerServer.isChatRequested = 1
                    # sets the server variable with the username of the peer that this one is chatting
                    self.peerServer.chattingClientName = self.responseReceived[1]

                    # as long as the server status is chatting, this client can send messages
                    while self.peerServer.isChatRequested == 1:
                        # message input prompt
                        messageSent = input()

                        # sends the message to the connected peer, and logs it
                        self.tcpClientSocket.send(messageSent.encode())
                        logging.info(
                            "Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                        # if the quit message is sent, then the server status is changed to not chatting
                        # and this is the side that is ending the chat
                        if messageSent == ":q":
                            self.peerServer.isChatRequested = 0
                            self.isEndingChat = True
                            # broadcast a system message to all users in the room
                            system_message = "SYSTEM MESSAGE: " + self.username + " has left the room."
                            CliEditor.red_message(system_message)
                            self.tcpClientSocket.send(system_message.encode())
                            break
                    # if peer is not chatting, checks if this is not the ending side
                    if self.peerServer.isChatRequested == 0:
                        if not self.isEndingChat:
                            # tries to send a quit message to the connected peer
                            # logs the message and handles the exception
                            try:
                                self.tcpClientSocket.send(":q ending-side".encode())
                                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                            except BrokenPipeError as bpErr:
                                logging.error("BrokenPipeError: {0}".format(bpErr))
                        # closes the socket
                        self.flag = None
                        self.peerServer.room = 0
                        self.peerServer.chat = 0
                        self.tcpClientSocket.close()
                # if the request is rejected, then changes the server status, sends a reject message to the connected
                # peer's server logs the message and then the socket is closed
                elif self.responseReceived[0] == "REJECT":
                    self.peerServer.isChatRequested = 0
                    # client of requester is closing...
                    CliEditor.red_message("Your request has been rejected")
                    self.tcpClientSocket.send("REJECT".encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> REJECT")
                    self.tcpClientSocket.close()
                # if a busy response is received, closes the socket
                elif self.responseReceived[0] == "BUSY":
                    # Receiver peer is busy
                    CliEditor.red_message("The user you're trying to reach is busy")
                    self.tcpClientSocket.close()
            # if the client is created with OK message it means that this is the client of receiver side peer. so it sends
            # an OK message to the requesting side peer server that it connects and then waits for the user inputs.
            elif self.responseReceived == "OK":
                # server status is changed
                self.peerServer.isChatRequested = 1
                # ok response is sent to the requester side
                okMessage = "OK"
                self.tcpClientSocket.send(okMessage.encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + okMessage)
                # Client accepted, one to one chatting is created...
                CliEditor.blue_message("You can start chatting now")
                CliEditor.yellow_message("\nWrite :q to quit the chat.")

                # client can send messages as long as the server status is chatting
                while self.peerServer.isChatRequested == 1:
                    # input prompt for user to enter message
                    messageSent = input()
                    self.tcpClientSocket.send(messageSent.encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                    # if a quit message is sent, server status is changed
                    if messageSent == ":q":
                        self.peerServer.isChatRequested = 0
                        self.isEndingChat = True
                        CliEditor.red_message(self.username + " left the room successfully.")
                        break
                # if server is not chatting, and if this is not the ending side
                # sends a quitting message to the server of the other peer
                # then closes the socket
                if self.peerServer.isChatRequested == 0:
                    if not self.isEndingChat:
                        self.tcpClientSocket.send(":q ending-side".encode())
                        logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                    self.responseReceived = None
                    self.flag = None
                    self.peerServer.room = 0
                    self.peerServer.chat = 0
                    self.tcpClientSocket.close()

        elif self.flag == '2':
            self.tcpClientSocket.connect((self.registryName, self.registryPort))
            CliEditor.green_message("Joined Room Successfully ...")
            join_message = f"{self.username} joined the room."
            CliEditor.yellow_message("\nWrite :q to quit chat.")

            for peer in self.room_peers:
                try:
                    # Convert peer to an integer to ensure it's a valid port number
                    port = int(peer)
                    if 0 <= port <= 65535:
                        # Send the join message using UDP
                        self.udpClientSocket.sendto(join_message.encode(), (self.ipToConnect, port))
                    else:
                        print(f"Error: Port number {port} out of range.")
                except ValueError:
                    print(f"Error: Invalid port number {peer}. Must be an integer.")
            while 1:
                self.update_peers()
                if not self.room_peers:
                    break

                message = input()
                message = f"{self.username}: {message}"

                self.update_peers()
                if len(message) != 0 and message.split()[1] == ":q":
                    if self.exit() == "SUCCESS":
                        message = f"{self.username} left the room."
                        for peer in self.room_peers:
                            self.udpClientSocket.sendto(message.encode(), (self.ipToConnect, int(peer)))
                        self.peerServer.room = 0
                        self.udpClientSocket.close()
                        self.flag = None
                        break

                else:
                    for peer in self.room_peers:
                        if int(peer) != self.peerServer.roomServerPort:
                            self.udpClientSocket.sendto(message.encode(), (self.ipToConnect, int(peer)))

            if not self.room_peers:
                CliEditor.red_message("Chatroom closed.")
                self.flag = None

        # main process of the peer


class peerMain:

    # peer initializations
    def __init__(self):
        # ip address of the registry
        CliEditor.title("Welcome to\nPingWhen")
        # port number of the registry
        self.registryPort = 15600
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        while True:
            try:
                self.registryName = input("Enter IP address of registry: ")
                # tcp socket connection to registry
                self.tcpClientSocket.connect((self.registryName, self.registryPort))
                break
            except OSError:
                CliEditor.red_message("Please enter the correct IP address.")
        # self.registryName = 'localhost'

        # initializes udp socket which is used to send hello messages
        self.udpClientSocket = socket(AF_INET, SOCK_DGRAM)
        # udp port of the registry
        self.registryUDPPort = 15500
        # login info of the peer
        self.loginCredentials = (None, None)
        # online status of the peer
        self.isOnline = False
        # server port number of this peer
        self.peerServerPort = None
        self.roomServerPort = None
        # server of this peer
        self.peerServer = None
        # client of this peer
        self.peerClient = None
        # timer initialization
        self.timer = None

        choice = "0"
        logging.basicConfig(filename="peer.log", level=logging.INFO)
        while choice != "3":
            if not self.isOnline:
                # Display options for a user who is not logged in
                choice = input("Choose: \nCreate account: 1\nLogin: 2\nExit: 3\n")

                if choice == "1":
                    username = input("username: ")
                    CliEditor.yellow_message(
                        "Please make sure that the password exceeds 7 characters containing atleast one "
                        "(Uppercase letter, Number, and a Special character)")
                    password = input("password: ")
                    self.createAccount(username, password)
                elif choice == "2" and not self.isOnline:

                    # asks for the port number for server's tcp socket
                    try:
                        while True:
                            username = input("Enter your username: ")
                            password = input("Enter your password: ")

                            # Indicate the allowed port number ranges
                            CliEditor.yellow_message(
                                "Choose port numbers for peer server and room server within the following ranges:")
                            CliEditor.blue_message("Peer Server Port Range: 1024 - 49151")
                            CliEditor.blue_message("Room Server Port Range: 49152 - 65535")

                            peerServerPort = int(input("Enter a port number for peer server: "))

                            # Check if the chosen port for the peer server is within the allowed range
                            if 1024 <= peerServerPort <= 49151:
                                roomServerPort = int(input("Enter a port number to join chat rooms: "))

                                # Check if the chosen port for the room server is within the allowed range
                                if 49152 <= roomServerPort <= 65535:
                                    # Perform the login with the provided credentials and port numbers
                                    status = self.login(username, password, peerServerPort)
                                    break
                                else:
                                    CliEditor.red_message(
                                        "Please enter a valid room server port within the range 49152 - 65535.")
                            else:
                                CliEditor.red_message(
                                    "Please enter a valid peer server port within the range 1024 - 49151.")

                    except ValueError:
                        CliEditor.red_message("Invalid input. Please enter valid numeric values for port numbers.")

                    # if user logs in successfully, peer variables are set
                    if status == 1:
                        self.isOnline = True
                        self.loginCredentials = (username, password)
                        self.peerServerPort = peerServerPort
                        self.roomServerPort = roomServerPort
                        # creates the server thread for this peer, and runs it
                        self.peerServer = PeerServer(self.loginCredentials[0], self.peerServerPort, self.roomServerPort)
                        self.peerServer.start()
                        # hello message is sent to registry
                        self.sendHelloMessage()

                elif choice == "3":
                    self.logout(2)

            elif self.isOnline:
                # Display options for a user who is logged in
                choice = input(
                    "Choose: \nSearch: 1\nStart a chat: 2\nLogout: 3\nDelete Account: 4\nOnline users list: 5\nCreate "
                    "room: 6\nList of rooms: 7\nJoin room: 8\nDelete room: 9\n")

                if choice == "1":
                    username = input("Username to be searched: ")
                    searchStatus = self.searchUser(username)
                    if searchStatus is not None and searchStatus != 0:
                        CliEditor.blue_message("IP address of " + username + " is " + searchStatus)
                elif choice == "2" and self.isOnline:
                    username = input("Enter the username of the user to start chatting: ")
                    searchStatus = self.searchUser(username)
                    # if searched user is found, then its ip address and port number is retrieved
                    # and a client thread is created
                    # main process waits for the client thread to finish its chat
                    if searchStatus is not None and searchStatus != 0:
                        searchStatus = searchStatus.split(":")
                        self.peerServer.chat = 1
                        self.peerClient = PeerClient(ipToConnect=searchStatus[0], portToConnect=int(searchStatus[1]),
                                                     username=self.loginCredentials[0], peerServer=self.peerServer,
                                                     responseReceived=None, flag='1', roomId=None, room_peers=None)
                        self.peerClient.start()
                        self.peerClient.join()
                elif choice == "3" and self.isOnline:
                    self.logout(1)
                    self.isOnline = False
                    self.loginCredentials = (None, None)
                    self.peerServer.isOnline = False
                    self.peerServer.tcpServerSocket.close()
                    if self.peerClient is not None:
                        self.peerClient.tcpClientSocket.close()
                    CliEditor.green_message(username+ " Logged out successfully")

                elif choice == "4" and self.isOnline:
                    self.deleteUser(self.loginCredentials[0])
                    self.logout(1)
                    self.isOnline = False
                    self.loginCredentials = (None, None)
                    self.peerServer.isOnline = False
                    self.peerServer.tcpServerSocket.close()
                    if self.peerClient is not None:
                        self.peerClient.tcpClientSocket.close()
                    CliEditor.green_message(username + " Logged out successfully")
                    break

                elif choice == "5" and self.isOnline:
                    self.onlineList()

                elif choice == "6" and self.isOnline:
                    # This choice creates a new chatroom and saves it in the database
                    try:
                        roomId = input("Enter a Chat room ID: ")
                        self.createRoom(roomId)
                    except Exception:
                        CliEditor.red_message("Please enter a valid/available room id.")

                    CliEditor.green_message("Chat room Created Successfully\n")

                elif choice == "7" and self.isOnline:
                    self.roomList()
                    # if createStatus:
                    # CliEditor.green_message("Chat room created successfully.")

                elif choice == "8" and self.isOnline:
                    # while True:
                    try:
                        roomId = input("Enter a Chat room ID: ")
                        search_status = self.joinRoom(roomId)

                        if search_status != 0 and search_status is not None:
                            ipToConnect = self.registryName or get_local_ip()
                            self.peerServer.chat = 0
                            self.peerServer.room = 1
                            self.peerClient = PeerClient(ipToConnect, None, self.loginCredentials[0], self.peerServer,
                                                         None,
                                                         '2', roomId, search_status)
                            self.peerClient.start()
                            self.peerClient.join()
                    except OSError:
                        CliEditor.red_message("Please enter a valid chat room id.")
                        # is user logs in successfully, peer variables are set
                # if createStatus:
                # CliEditor.green_message("Chat room created successfully.")
                elif choice == "9" and self.isOnline:
                    # This choice creates a new chatroom and saves it in the database
                    try:
                        roomId = input("Enter the chat room's id to be deleted: ")
                        self.deleteRoom(roomId)
                    except Exception:
                        CliEditor.red_message("Please enter a valid chat room id.")


                # if this is the receiver side then it will get the prompt to accept an incoming request during
                # the main loop that's why response is evaluated in main process not the server thread even
                # though the prompt is printed by server if the response is ok then a client is created for this
                # peer with the OK message and that's why it will directly send an OK message to the requesting
                # side peer server and waits for the user input main process waits for the client thread to
                # finish its chat
                elif choice == "OK" and self.isOnline:
                    okMessage = "OK " + self.loginCredentials[0]
                    logging.info("Send to " + self.peerServer.connectedPeerIP + " -> " + okMessage)
                    self.peerServer.connectedPeerSocket.send(okMessage.encode())
                    self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort,
                                                 self.loginCredentials[0], self.peerServer, "OK", '1', None, None)
                    self.peerClient.start()
                    self.peerClient.join()
                    # if user rejects the chat request then reject message is sent to the requester side
                elif choice == "REJECT" and self.isOnline:
                    self.peerServer.connectedPeerSocket.send("REJECT".encode())
                    self.peerServer.isChatRequested = 0
                    logging.info("Send to " + self.peerServer.connectedPeerIP + " -> REJECT")
                    # if choice is cancel timer for hello message is cancelled
                elif choice == "CANCEL":
                    self.timer.cancel()
                    break

            # if main process is not ended with cancel selection
            # socket of the client is closed
        if choice != "CANCEL":
            self.tcpClientSocket.close()

    # account creation function
    def createAccount(self, username, password):
        # join message to create an account is composed and sent to registry
        # if response is success then informs the user for account creation
        # if response is existed then informs the user for account existence
        message = "JOIN " + username + " " + password
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "join-success":
            CliEditor.green_message("Account created...")
        elif response == "join-exist":
            CliEditor.red_message("choose another username or login...")
        elif response == "password-not-long":
            CliEditor.red_message("Password must be at least 8 characters long.")
        elif response == "pass-not-contain-number":
            CliEditor.red_message("Password must contain at least one numeral.")
        elif response == "pass-not-contain-cap":
            CliEditor.red_message("Password must contain at least one capital letter")
        elif response == "pass-not-contain-special":
            CliEditor.red_message("Password must contain at least one special character.")

    # login function
    def login(self, username, password, peerServerPort):
        # a login message is composed and sent to registry
        # an integer is returned according to each response
        message = "LOGIN " + username + " " + password + " " + str(peerServerPort)
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "login-success":
            CliEditor.green_message("Logged in successfully...")
            return 1
        elif response == "login-account-not-exist":
            CliEditor.red_message("Account does not exist...")
            return 0
        elif response == "login-online":
            CliEditor.red_message("Account is already online...")
            return 2
        elif response == "login-wrong-password":
            CliEditor.red_message("Wrong password...")
            return 3

    # logout function
    def logout(self, option):
        # a logout message is composed and sent to registry
        # timer is stopped
        if option == 1:
            message = "LOGOUT " + self.loginCredentials[0]
            self.timer.cancel()
        else:
            message = "LOGOUT"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())

    # function for searching an online user
    def searchUser(self, username):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "SEARCH " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response[0] == "search-success":
            CliEditor.green_message(username + " is found successfully...")
            return response[1]
        elif response[0] == "search-user-not-online":
            CliEditor.red_message(username + " is not online...")

            return 0
        elif response[0] == "search-user-not-found":
            CliEditor.red_message(username + " is not found")
            return None

    # function for creating room
    # create message is sent to registry, if response is create-room-success then inform user of room creation
    # if response is chat-room-exist then inform user room exist
    def createRoom(self, roomId):
        # join message to create an account is composed and sent to registry
        # if response is success then informs the user for account creation
        # if response exists then informs the user for account existence
        message = "CREATE-ROOM " + roomId
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "create-room-success":
            CliEditor.green_message("Chat room created successfully.")
        elif response == "chat-room-exist":
            CliEditor.red_message("chat room already exits")
        # else:
        #     CliEditor.red_message("Chat room already exists.")

        # function for joining room
        # join room message is sent to registry, if response is join-room-success then inform user of room creation
        # if response is join-room-fail then inform user room exist

    def joinRoom(self, roomId):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "JOIN-ROOM " + roomId + " " + str(self.roomServerPort)
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        if '[' in response and ']' in response:
            list_start = response.index('[')
            list_end = response.index(']') + 1
            list_string = response[list_start:list_end]
            response2 = eval(list_string)

            response = response.split()
            logging.info("Received from " + self.registryName + " -> " + " ".join(response))
            if response[0] == "join-room-success":
                CliEditor.green_message(roomId + " is found successfully...")
                return response2

            elif response[0] == "join-room-fail":
                print(roomId + " is not found")
                return 0
        else:
            CliEditor.red_message("Chat room doesn't exist")
            return 0

    def roomList(self):
        message = "ROOM-LIST"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        CliEditor.green_message(str(response))
        logging.info("Received from " + self.registryName + " -> " + response)

    def onlineList(self):
        message = "ONLINE"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        CliEditor.green_message(str(response))
        logging.info("Received from " + self.registryName + " -> " + response)

    def deleteRoom(self, roomId):
        message = "DELETE-ROOM " + roomId
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()

        if response == "delete-room-success":
            CliEditor.green_message("Room with ID: " + roomId + " deleted successfully")
        elif response == "delete-room-fail":
            CliEditor.red_message("Failed to delete room, since room doesn't exist")

    # *********************UNDER TESTING***************************#
    def deleteUser(self, username):
        message = "DELETE-USER " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()

        if response == "delete-user-success":
            CliEditor.green_message("User: " + username + " has been deleted successfully")
        elif response == "delete-user-fail":
            CliEditor.red_message("Failed to delete user, since user doesn't exist")
    # *********************UNDER TESTING***************************#

    # function for sending hello message

    # a timer thread is used to send hello messages to udp socket of registry
    def sendHelloMessage(self):
        try:
            message = "HELLO " + self.loginCredentials[0]
            logging.info("Send to " + self.registryName + ":" + str(self.registryUDPPort) + " -> " + message)
            self.udpClientSocket.sendto(message.encode(), (self.registryName, self.registryUDPPort))
        except Exception as e:
            logging.error(f"Error in sendHelloMessage: {e}")

        self.timer = threading.Timer(1, self.sendHelloMessage)
        self.timer.start()


# peer is started
main = peerMain()
