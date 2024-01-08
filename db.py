from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError


class DB:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['p2p-chat']

    def is_account_exist(self, username):
        return self.db.accounts.count_documents({'username': username}) > 0

    def register(self, username, password):
        account = {
            "username": username,
            "password": password
        }
        self.db.accounts.insert_one(account)

    def get_password(self, username):
        user_data = self.db.accounts.find_one({"username": username})
        return user_data["password"] if user_data else None

    def is_account_online(self, username):
        return self.db.online_peers.count_documents({"username": username}) > 0

    def user_login(self, username, ip, port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port
        }
        self.db.online_peers.insert_one(online_peer)

    def user_logout(self, username):
        self.db.online_peers.delete_one({"username": username})

    def get_peer_ip_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return (res["ip"], res["port"]) if res else (None, None)

    def register_room(self, roomId):
        # Check if the roomId already exists in the database
        if self.db.rooms.find_one({"roomId": roomId}):
            raise ValueError(f"Room with id {roomId} already exists.")

        room = {
            "roomId": roomId,
            "peers": []
        }

        # Store the room information in the database
        self.db.rooms.insert_one(room)

    def get_available_rooms(self):
        projection = {'roomId': 1, '_id': 0}
        return list(self.db.rooms.find({}, projection))

    def get_online_list(self):
        projection = {'username': 1, '_id': 0}
        return list(self.db.online_peers.find({}, projection))

    # checks if an room with the id exists
    def is_room_exist(self, roomId):
        if len(list(self.db.rooms.find({'roomId': roomId}))) > 0:
            return True
        else:
            return False

    # Needed when we flood a message
    def get_room_peers(self, roomId):
        res = self.db.rooms.find_one({"roomId": roomId})
        return res["_id"], res["peers"]

    def update_room(self, roomId, peers):
        projection = {"_id": roomId}
        update_data = {
            "$set": {"peers": peers}
        }
        self.db.rooms.update_one(projection, update_data)

    def remove_peer(self, roomId, peer):
        projection = {"roomId": roomId}
        update_data = {
            "$pull": {"peers": peer}
        }
        self.db.rooms.update_one(projection, update_data)

    def delete_user(self, username):
        # Delete user from accounts collection
        self.db.accounts.delete_one({"username": username})

        # Delete user from online_peers collection
        self.db.online_peers.delete_one({"username": username})

    def delete_room(self, roomId):
        # Delete room from rooms collection
        self.db.rooms.delete_one({"roomId": roomId})


