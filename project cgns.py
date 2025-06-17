import bcrypt
import random
import string

class UserAuthSystem:
    def __init__(self):
        self.users = {}       # username -> hashed_password
        self.sessions = {}    # session_id -> username

    def hash_password(self, password: str) -> bytes:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed

    def verify_password(self, stored_hash: bytes, password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

    def is_valid_password(self, password: str) -> bool:
        if len(password) < 8:
            return False
        if not any(char.isdigit() for char in password):
            return False
        if not any(char in string.punctuation for char in password):
            return False
        return True

    def register_user(self, username: str, password: str) -> bool:
        if username in self.users:
            print(f"[!] User '{username}' already exists.")
            return False
        if not self.is_valid_password(password):
            print("[!] Password is too weak. Must be at least 8 characters long, contain a digit, and a special character.")
            return False
        hashed_password = self.hash_password(password)
        self.users[username] = hashed_password
        print(f"[+] User '{username}' registered successfully.")
        return True

    def login(self, username: str, password: str) -> bool:
        if username not in self.users:
            print(f"[!] User '{username}' not found.")
            return False
        stored_hash = self.users[username]
        if self.verify_password(stored_hash, password):
            session_id = self.create_session(username)
            print(f"[✓] Authentication successful for user '{username}'. Session ID: {session_id}")
            return True
        else:
            print(f"[✗] Authentication failed for user '{username}'.")
            return False

    def create_session(self, username: str) -> str:
        session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        self.sessions[session_id] = username
        return session_id

    def validate_session(self, session_id: str) -> bool:
        return session_id in self.sessions

    def logout(self, session_id: str) -> bool:
        if session_id in self.sessions:
            del self.sessions[session_id]
            print(f"[+] User logged out successfully.")
            return True
        else:
            print(f"[!] Invalid session ID.")
            return False

    def change_password(self, session_id: str, old_password: str, new_password: str) -> bool:
        if session_id not in self.sessions:
            print("[!] You are not logged in.")
            return False
        username = self.sessions[session_id]
        if not self.verify_password(self.users[username], old_password):
            print("[!] Old password is incorrect.")
            return False
        if not self.is_valid_password(new_password):
            print("[!] New password is too weak.")
            return False
        self.users[username] = self.hash_password(new_password)
        print(f"[+] Password changed successfully for user '{username}'.")
        return True

    def delete_user(self, session_id: str, username: str) -> bool:
        if session_id not in self.sessions:
            print("[!] You are not logged in.")
            return False
        if username not in self.users:
            print(f"[!] User '{username}' does not exist.")
            return False
        if self.sessions[session_id] != username:
            print(f"[!] You cannot delete another user's account.")
            return False
        del self.users[username]
        del self.sessions[session_id]
        print(f"[+] User '{username}' deleted successfully.")
        return True

    def list_users(self) -> None:
        if not self.users:
            print("[!] No users registered.")
        else:
            print("\nList of registered users:")
            for username in self.users:
                print(f"- {username}")

    def view_user_profile(self, session_id: str) -> None:
        if session_id not in self.sessions:
            print("[!] You are not logged in.")
            return
        username = self.sessions[session_id]
        print(f"\nProfile of {username}:")
        print(f"Username: {username}")
        print("[+] You are currently logged in.")

def main():
    auth_system = UserAuthSystem()

    while True:
        print("\n===== PASSWORD AUTH SYSTEM =====")
        print("1. Register")
        print("2. Login")
        print("3. Change Password")
        print("4. Logout")
        print("5. Delete User")
        print("6. List Users")
        print("7. View Profile")
        print("8. Exit")
        choice = input("Enter choice: ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            auth_system.register_user(username, password)

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            auth_system.login(username, password)

        elif choice == '3':
            session_id = input("Enter session ID: ")
            old_password = input("Enter old password: ")
            new_password = input("Enter new password: ")
            auth_system.change_password(session_id, old_password, new_password)

        elif choice == '4':
            session_id = input("Enter session ID: ")
            auth_system.logout(session_id)

        elif choice == '5':
            session_id = input("Enter session ID: ")
            username = input("Enter username to delete: ")
            auth_system.delete_user(session_id, username)

        elif choice == '6':
            auth_system.list_users()

        elif choice == '7':
            session_id = input("Enter session ID: ")
            auth_system.view_user_profile(session_id)

        elif choice == '8':
            print("Exiting... Goodbye!")
            break

        else:
            print("[!] Invalid option. Try again.")

if __name__ == "__main__":
    main()
