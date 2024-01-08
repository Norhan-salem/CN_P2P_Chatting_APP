import unittest
from unittest.mock import patch, MagicMock, Mock
from peer import PeerClient, get_local_ip, PeerClientGroupChat, peerMain, PeerServer, gaierror
from registry import is_password_valid, check_password, hash_password, ClientThread, UDPServer
import threading
import time
import socket


class TestPeerServerInit(unittest.TestCase):
    def test_init_with_valid_values(self):
        username = "test_user"
        peerServerPort = 12345
        roomServerPort = 54321
        peer_server = PeerServer(username, peerServerPort, roomServerPort)
        self.assertEqual(peer_server.username, username)
        self.assertEqual(peer_server.peerServerPort, peerServerPort)
        self.assertEqual(peer_server.roomServerPort, roomServerPort)

    def test_init_with_invalid_values(self):
        username = "test_user"
        peerServerPort = 12345
        roomServerPort = 54321
        peer_server = PeerServer(username, peerServerPort, roomServerPort)
        self.assertNotEqual(peer_server.username, "invalid_user")
        self.assertNotEqual(peer_server.peerServerPort, 9999)
        self.assertNotEqual(peer_server.roomServerPort, 8888)


class TestPeerServerRun(unittest.TestCase):
    def test_run_peer_server_hostname(self):
        username = "test_user"
        peerServerPort = 12345
        roomServerPort = 54321
        peer_server = PeerServer(username, peerServerPort, roomServerPort)
        peer_server.run()
        self.assertIsNotNone(peer_server.peerServerHostname)

    def test_run_tcp_server_socket(self):
        username = "test_user"
        peerServerPort = 12345
        roomServerPort = 54321
        peer_server = PeerServer(username, peerServerPort, roomServerPort)
        peer_server.run()
        self.assertIsNotNone(peer_server.tcpServerSocket)

    def test_run_udp_server_socket(self):
        username = "test_user"
        peerServerPort = 12345
        roomServerPort = 54321
        peer_server = PeerServer(username, peerServerPort, roomServerPort)
        peer_server.run()
        self.assertIsNotNone(peer_server.udpServerSocket)

    def test_run_is_chat_requested(self):
        username = "test_user"
        peerServerPort = 12345
        roomServerPort = 54321
        peer_server = PeerServer(username, peerServerPort, roomServerPort)
        peer_server.run()
        self.assertEqual(peer_server.isChatRequested, 0)

    def test_run_is_online(self):
        username = "test_user"
        peerServerPort = 12345
        roomServerPort = 54321
        peer_server = PeerServer(username, peerServerPort, roomServerPort)
        peer_server.run()
        self.assertTrue(peer_server.isOnline)


class TestPeerClient(unittest.TestCase):
    def test_peer_client_initialization(self):
        ipToConnect = "192.168.56.1"
        portToConnect = 12345
        username = "test_user"
        peerServer = MagicMock()
        responseReceived = None
        client = PeerClient(ipToConnect, portToConnect, username, peerServer, responseReceived)
        self.assertEqual(client.ipToConnect, ipToConnect)
        self.assertEqual(client.portToConnect, portToConnect)
        self.assertEqual(client.username, username)
        self.assertEqual(client.peerServer, peerServer)
        self.assertEqual(client.responseReceived, responseReceived)
        self.assertFalse(client.isEndingChat)

    @patch('peer.CliEditor.green_message')
    @patch('socket.socket')
    def test_peer_client_run(self, mock_socket, mock_green_message):
        ipToConnect = "192.168.56.1"
        portToConnect = 12345
        username = "test_user"
        peerServer = MagicMock()
        responseReceived = None
        client = PeerClient(ipToConnect, portToConnect, username, peerServer, responseReceived)
        client.run()
        mock_green_message.assert_called_with("Peer client started...")
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        client.tcpClientSocket.connect.assert_called_with((ipToConnect, portToConnect))


class TestPeerClientGroupChat(unittest.TestCase):
    def test_peer_client_group_chat_initialization(self):
        ipToConnect = "192.168.56.1"
        portToConnect = 12345
        username = "test_user"
        peerServer = MagicMock()
        responseReceived = None
        roomId = 1
        room_peers = [12345, 54321]
        client = PeerClientGroupChat(ipToConnect, portToConnect, username, peerServer, responseReceived, roomId,
                                     room_peers)
        self.assertEqual(client.ipToConnect, ipToConnect)
        self.assertEqual(client.portToConnect, portToConnect)
        self.assertEqual(client.username, username)
        self.assertEqual(client.peerServer, peerServer)
        self.assertEqual(client.responseReceived, responseReceived)
        self.assertEqual(client.roomId, roomId)
        self.assertEqual(client.room_peers, room_peers)
        self.assertFalse(client.isRoomEmpty)

    @patch('peer.CliEditor.green_message')
    @patch('socket.socket')
    def test_peer_client_group_chat_run(self, mock_socket, mock_green_message):
        ipToConnect = "192.168.56.1"
        portToConnect = 12345
        username = "test_user"
        peerServer = MagicMock()
        responseReceived = None
        roomId = 1
        room_peers = [12345, 54321]
        client = PeerClientGroupChat(ipToConnect, portToConnect, username, peerServer, responseReceived, roomId,
                                     room_peers)
        client.run()
        mock_green_message.assert_called_with("Joined Room Successfully ...")
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        client.tcpClientSocket.connect.assert_called_with((client.registryName, client.registryPort))


class TestPeerMain(unittest.TestCase):
    def test_peer_main_initialization(self):
        peer_main = peerMain()
        self.assertEqual(peer_main.registryPort, 15600)
        self.assertIsInstance(peer_main.tcpClientSocket, MagicMock)
        self.assertIsInstance(peer_main.udpClientSocket, MagicMock)
        self.assertEqual(peer_main.registryUDPPort, 15500)
        self.assertEqual(peer_main.loginCredentials, (None, None))
        self.assertFalse(peer_main.isOnline)
        self.assertIsNone(peer_main.peerServerPort)
        self.assertIsNone(peer_main.roomServerPort)
        self.assertIsNone(peer_main.peerServer)
        self.assertIsNone(peer_main.peerClient)
        self.assertIsNone(peer_main.timer)

    @patch('peer.CliEditor.yellow_message')
    @patch('builtins.input', side_effect=["2", "test_user", "test_password", "12345", "54321"])
    def test_peer_main_login(self, mock_input, mock_yellow_message):
        peer_main = peerMain()
        peer_main.loginCredentials = ("test_user", "test_password")
        peer_main.login()
        mock_yellow_message.assert_called_with(
            "Choose port numbers for peer server and room server within the following ranges since they're safe:")
        self.assertTrue(peer_main.isOnline)
        self.assertEqual(peer_main.peerServerPort, 12345)
        self.assertEqual(peer_main.roomServerPort, 54321)


class TestPeerClient(unittest.TestCase):

    @patch('peer.CliEditor.yellow_message')
    @patch('peer.CliEditor.blue_message')
    @patch('peer.CliEditor.red_message')
    @patch('peer.CliEditor.green_message')
    @patch('builtins.input', side_effect=["test_user", "test_password", "12345", "54321"])
    @patch('socket.socket')
    @patch('peer.PeerServer')
    @patch('peer.PeerClient.login')
    @patch('peer.PeerClient.sendHelloMessage')
    def test_peer_client_run(self, mock_send_hello, mock_login, mock_peer_server,
                             mock_socket, mock_input, mock_green_message, mock_red_message,
                             mock_blue_message, mock_yellow_message):
        ipToConnect = "192.168.56.1"
        portToConnect = 12345

        # Mocking input values
        mock_input.return_value = "test_user"

        # Mocking socket and PeerServer
        mock_socket_instance = mock_socket.return_value
        mock_peer_server_instance = mock_peer_server.return_value

        # Mocking PeerClient
        client = PeerClient(ipToConnect, portToConnect)

        # Mocking the login function to return 1
        mock_login.return_value = 1

        # Running the test
        with patch('builtins.input', side_effect=["test_user", "test_password", "12345", "54321"]):
            with patch('socket.socket'):
                with patch('peer.CliEditor.yellow_message'):
                    client.run()

        # Assertions
        mock_green_message.assert_called_with("Choose port numbers for peer server and room server within the following ranges since they're safe (Dynamic Ports):")
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_input.assert_called_with("Enter your username: ")
        mock_input.assert_called_with("Enter your password: ")
        mock_peer_server.assert_called_with("test_user", 12345, 54321)
        mock_peer_server_instance.start.assert_called_once()
        mock_send_hello.assert_called_once()

class TestCreateAccount(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_create_account_success(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "join-success"
        peer_main.createAccount("test_user", "test_password")
        mock_green_message.assert_called_with("Account created...")

    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_create_account_exist(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "join-exist"
        peer_main.createAccount("test_user", "test_password")
        mock_red_message.assert_called_with("choose another username or login...")


class TestLogin(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_login_success(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "login-success"
        result = peer_main.login("test_user", "test_password", 12345)
        mock_green_message.assert_called_with("Logged in successfully...")
        self.assertEqual(result, 1)

    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_login_account_not_exist(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "login-account-not-exist"
        result = peer_main.login("test_user", "test_password", 12345)
        mock_red_message.assert_called_with("Account does not exist...")
        self.assertEqual(result, 0)


class TestLogout(unittest.TestCase):
    @patch('peer.Timer')
    def test_logout_with_timer(self, mock_timer):
        peer_main = peerMain()
        peer_main.timer = MagicMock()
        peer_main.logout(1)
        peer_main.timer.cancel.assert_called_once()

    @patch('peer.Timer')
    def test_logout_without_timer(self, mock_timer):
        peer_main = peerMain()
        peer_main.timer = MagicMock()
        peer_main.logout(0)
        peer_main.timer.cancel.assert_not_called()


class TestSearchUser(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_search_user_found(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "search-success test_user_id"
        result = peer_main.searchUser("test_user")
        mock_green_message.assert_called_with("test_user is found successfully...")
        self.assertEqual(result, "test_user_id")

    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_search_user_not_online(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "search-user-not-online"
        result = peer_main.searchUser("test_user")
        mock_red_message.assert_called_with("test_user is not online...")
        self.assertEqual(result, 0)


class TestCreateRoom(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_create_room_success(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "create-room-success"
        peer_main.createRoom("test_room_id")
        mock_green_message.assert_called_with("Chat room created successfully...")

    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_create_room_exist(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "chat-room-exist"
        peer_main.createRoom("test_room_id")
        mock_red_message.assert_called_with("chat room already exits")


class TestJoinRoom(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_join_room_success(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "join-room-success test_room_id"
        result = peer_main.joinRoom("test_room_id")
        mock_green_message.assert_called_with("test_room_id is found successfully...")
        self.assertEqual(result, "test_room_id")

    @patch('peer.CliEditor.red_message')
    def test_join_room_fail(self, mock_red_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "join-room-fail"
        result = peer_main.joinRoom("test_room_id")
        mock_red_message.assert_called_with("Chat room doesn't exist")
        self.assertEqual(result, 0)


class TestRoomList(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    def test_room_list(self, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "[{'roomId': 'room1'}, {'roomId': 'room2'}]"
        peer_main.roomList()
        mock_green_message.assert_called_with("Here are the room ID(s) for Available rooms: room1, room2")


class TestOnlineList(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    def test_online_list(self, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "[{'username': 'user1'}, {'username': 'user2'}]"
        peer_main.onlineList()
        mock_green_message.assert_called_with("online users are: user1, user2")


class TestDeleteRoom(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_delete_room_success(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "delete-room-success"
        peer_main.deleteRoom("test_room_id")
        mock_green_message.assert_called_with("Room with ID: test_room_id deleted successfully")

    @patch('peer.CliEditor.red_message')
    def test_delete_room_fail(self, mock_red_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "delete-room-fail"
        peer_main.deleteRoom("test_room_id")
        mock_red_message.assert_called_with("Failed to delete room, since room doesn't exist")


class TestDeleteUser(unittest.TestCase):
    @patch('peer.CliEditor.green_message')
    @patch('peer.CliEditor.red_message')
    def test_delete_user_success(self, mock_red_message, mock_green_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "delete-user-success"
        peer_main.deleteUser("test_username")
        mock_green_message.assert_called_with("User: test_username has been deleted successfully")

    @patch('peer.CliEditor.red_message')
    def test_delete_user_fail(self, mock_red_message):
        peer_main = peerMain()
        peer_main.tcpClientSocket = MagicMock()
        peer_main.tcpClientSocket.recv.return_value = "delete-user-fail"
        peer_main.deleteUser("test_username")
        mock_red_message.assert_called_with("Failed to delete user, since user doesn't exist")


class TestSendHelloMessage(unittest.TestCase):
    @patch('peer.threading.Timer')
    def test_send_hello_message(self, mock_timer):
        peer_main = peerMain()
        peer_main.udpClientSocket = MagicMock()
        peer_main.loginCredentials = ["test_username"]
        peer_main.sendHelloMessage()
        mock_timer.assert_called()


class TestIsPasswordValid(unittest.TestCase):
    def test_valid_password(self):
        password = "StrongPass123!"
        result, message = is_password_valid(password)
        self.assertTrue(result)
        self.assertEqual(message, "Password is valid.")

    def test_invalid_password_too_short(self):
        password = "weak"
        result, message = is_password_valid(password)
        self.assertFalse(result)
        self.assertEqual(message, "password-not-long")

    def test_invalid_password_no_number(self):
        password = "NoNumberPass!"
        result, message = is_password_valid(password)
        self.assertFalse(result)
        self.assertEqual(message, "pass-not-contain-number")

    def test_invalid_password_no_capital_letter(self):
        password = "nocapital123!"
        result, message = is_password_valid(password)
        self.assertFalse(result)
        self.assertEqual(message, "pass-not-contain-cap")

    def test_invalid_password_no_special_character(self):
        password = "NoSpecial123"
        result, message = is_password_valid(password)
        self.assertFalse(result)
        self.assertEqual(message, "pass-not-contain-special")


class TestHashPassword(unittest.TestCase):
    def test_hash_password(self):
        password = "StrongPass123!"
        hashed_password = hash_password(password)
        self.assertNotEqual(hashed_password, password)


class TestCheckPassword(unittest.TestCase):
    def test_correct_password(self):
        user_password = "StrongPass123!"
        hashed_password = hash_password(user_password)
        result = check_password(hashed_password, user_password)
        self.assertTrue(result)

    def test_incorrect_password(self):
        user_password = "StrongPass123!"
        incorrect_password = "WrongPass456!"
        hashed_password = hash_password(user_password)
        result = check_password(hashed_password, incorrect_password)
        self.assertFalse(result)


class TestUDPServer(unittest.TestCase):
    def setUp(self):
        self.username = "test_user"
        self.clientSocket = Mock()
        self.udp_server = UDPServer(self.username, self.clientSocket)

    def test_udp_server_initialization(self):
        self.assertEqual(self.udp_server.username, self.username)
        self.assertEqual(self.udp_server.clientSocket, self.clientSocket)
        self.assertIsInstance(self.udp_server.timer, threading.Timer)

    def test_udp_server_wait_hello_message(self):
        with patch('registry.db.user_logout') as mock_user_logout:
            with patch('registry.tcpThreads', {'test_user': Mock()}) as mock_tcpThreads:
                self.udp_server.waitHelloMessage()
                mock_user_logout.assert_called_once_with(self.username)
                self.assertTrue(self.username not in mock_tcpThreads)
                self.clientSocket.close.assert_called_once()
                # Add more assertions as needed

    def test_udp_server_reset_timer(self):
        with patch('threading.Timer') as mock_timer:
            self.udp_server.resetTimer()
            mock_timer.assert_called_once_with(3, self.udp_server.waitHelloMessage)
            mock_timer.return_value.cancel.assert_called_once()
            mock_timer.return_value.start.assert_called_once()


if __name__ == '__main__':
    unittest.main()
