import socket
import json
import getpass  # Import getpass for hidden password input

# Function to get user credentials
def get_user_credentials():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")  # Password input is hidden
    return username, password

# Function to display options and get user choice
def get_action():
    print("\nChoose an option:")
    print("1. Sign Up")
    print("2. Log In")
    choice = input("Enter choice (1 or 2): ")
    if choice == "1":
        return "signup"
    elif choice == "2":
        return "login"
    else:
        print("Invalid choice.")
        return get_action()

# Main client function
def main():
    while True:
        # Get action (sign-up or login)
        action = get_action()
        
        # Get credentials from user
        username, password = get_user_credentials()

        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("localhost", 65432))

        # Prepare data and send to server
        request = {"action": action, "username": username, "password": password}
        client_socket.send(json.dumps(request).encode())

        # Receive response from server
        response = client_socket.recv(1024).decode()
        print("Server response:", response)

        client_socket.close()

        # Exit loop if login is successful
        if action == "login" and response == "Login successful.":
            break

if __name__ == "__main__":
    main()
