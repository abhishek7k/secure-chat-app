import sys
import socket
import threading
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
    QWidget, QTextEdit, QLineEdit, QPushButton, QLabel, QGroupBox, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QTextCharFormat, QColor, QTextCursor

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- AESCipher Class (Handles AES encryption/decryption) ---
class AESCipher:
    """
    A class to handle AES encryption and decryption using GCM mode.
    GCM provides both confidentiality and integrity (authenticity).
    """
    def __init__(self, key: bytes):
        """
        Initializes the AESCipher with a given key.
        The key must be 16, 24, or 32 bytes (128, 192, or 256 bits).
        """
        if not isinstance(key, bytes) or len(key) not in [16, 24, 32]:
            raise ValueError("AES key must be 16, 24, or 32 bytes.")
        self.key = key
        self.backend = default_backend()

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext using AES in GCM mode.
        Returns the IV, authentication tag, and ciphertext concatenated.
        """
        # GCM nonce (IV) should be 12 bytes and unique for each encryption.
        iv = os.urandom(12) 
        
        # Create AES cipher with the key and GCM mode with the unique IV
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Encrypt the plaintext. .update() processes data, .finalize() handles padding/finalization.
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # The authentication tag is crucial for integrity verification during decryption.
        tag = encryptor.tag
        
        # Return IV + Tag + Ciphertext. All three are needed for successful decryption.
        return iv + tag + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts data that was encrypted with AES in GCM mode.
        Requires the IV, authentication tag, and ciphertext.
        Performs integrity check using the authentication tag.
        """
        # Minimum size: 12 bytes (IV) + 16 bytes (GCM tag)
        if len(encrypted_data) < 28:
            return b"Error: Malformed encrypted data (too short for IV and tag)."

        # Extract IV, tag, and ciphertext from the concatenated data
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        # Create AES cipher with the key, GCM mode, and the received IV and tag
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()

        try:
            # Decrypt the ciphertext. Finalize() will verify the tag.
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            # An exception during finalize() usually means the tag verification failed,
            # indicating tampering or an incorrect key.
            print(f"Decryption failed (integrity check failed): {e}")
            return b"Message could not be decrypted (tampered or wrong key/IV/tag)."

# --- NetworkManager Class (Handles network communication in a separate thread) ---
class NetworkManager(QThread):
    """
    Manages network connections (client or server) in a separate thread
    to prevent the GUI from freezing. Emits signals to update the GUI.
    """
    # Signals to communicate with the main GUI thread
    message_received_signal = pyqtSignal(bytes)
    status_update_signal = pyqtSignal(str, str) # message, color

    def __init__(self, host: str, port: int, is_server: bool = False, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.is_server = is_server
        self.client_socket = None
        self.server_socket = None
        self.connection = None # The active connection (client_socket for client, accepted_socket for server)
        self.running = False
        self.encryption_cipher = None # AESCipher instance, set externally

    def run(self):
        """
        The main loop for the QThread. Handles connection establishment and data reception.
        """
        self.running = True
        if self.is_server:
            self._start_server()
        else:
            self._start_client()

    def _start_server(self):
        """Starts the server and listens for incoming connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)
            self.status_update_signal.emit(f"Listening on {self.host}:{self.port}...", "green")
            self.connection, addr = self.server_socket.accept() # This blocks until a connection is made
            self.status_update_signal.emit(f"Accepted connection from {addr[0]}:{addr[1]}", "green")
            self._receive_data() # Start receiving data from the accepted connection
        except Exception as e:
            if self.running:
                self.status_update_signal.emit(f"Failed to start server or accept connection: {e}", "red")
            self.stop()
        finally:
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None

    def _start_client(self):
        """Connects to a server and starts receiving data."""
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.status_update_signal.emit(f"Attempting to connect to {self.host}:{self.port}...", "green")
            self.client_socket.connect((self.host, self.port))
            self.connection = self.client_socket
            self.status_update_signal.emit("Connected!", "green")
            self._receive_data() # Start receiving data from the established connection
        except Exception as e:
            if self.running:
                self.status_update_signal.emit(f"Connection failed: {e}", "red")
            self.stop()

    def _receive_data(self):
        """Continuously receives data from the active connection."""
        while self.running and self.connection:
            try:
                # Receive data in chunks. A real protocol would prepend message length.
                data = self.connection.recv(4096)
                if not data:
                    self.status_update_signal.emit("Disconnected by peer.", "orange")
                    self.stop()
                    break

                # Decrypt the received data if an encryption cipher is set
                if self.encryption_cipher:
                    try:
                        decrypted_data = self.encryption_cipher.decrypt(data)
                        if b"Message could not be decrypted" in decrypted_data:
                            # Emit a special message if decryption/integrity check fails
                            self.status_update_signal.emit(f"Peer: [DECRYPTION FAILED - POSSIBLY TAMPERED/BAD KEY]", "red")
                        else:
                            self.message_received_signal.emit(decrypted_data)
                    except Exception as crypto_e:
                        self.status_update_signal.emit(f"Crypto error during decryption: {crypto_e}", "red")
                        self.status_update_signal.emit(f"Peer (raw, possibly garbled): {data.decode('utf-8', errors='ignore')}", "red")
                else:
                    # If no encryption cipher is set, display raw data and a warning
                    self.status_update_signal.emit(f"Raw received (no encryption): {data.decode('utf-8', errors='ignore')}", "purple")
                    self.status_update_signal.emit("Warning: Encryption not initialized for incoming messages!", "red")

            except ConnectionResetError:
                self.status_update_signal.emit("Connection reset by peer.", "orange")
                self.stop()
                break
            except Exception as e:
                if self.running:
                    self.status_update_signal.emit(f"Receive error: {e}", "red")
                self.stop()
                break
        self.stop() # Ensure stop is called when the receive loop exits

    def send_data(self, data: bytes):
        """Sends data over the active connection."""
        if self.connection:
            try:
                self.connection.sendall(data)
            except Exception as e:
                self.status_update_signal.emit(f"Send error: {e}", "red")
                self.stop()
        else:
            self.status_update_signal.emit("Not connected to send data.", "red")

    def stop(self):
        """Stops the network thread and closes sockets."""
        if not self.running: # Already stopped
            return

        self.running = False
        if self.connection:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            except OSError as e:
                print(f"Error during connection shutdown/close: {e}")
            self.connection = None
        
        if self.client_socket: # For client mode, close client_socket if it's not the connection
            try:
                self.client_socket.close()
            except OSError as e:
                print(f"Error during client_socket close: {e}")
            self.client_socket = None

        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError as e:
                print(f"Error during server_socket close: {e}")
            self.server_socket = None
        
        self.status_update_signal.emit("Network stopped.", "gray")
        self.quit() # End the QThread's event loop
        self.wait() # Wait for the thread to finish execution

# --- SecureChatApp Class (Main PyQt5 Application Window) ---
class SecureChatApp(QMainWindow):
    """
    The main PyQt5 application window for the secure messaging app.
    Manages UI, AES encryption, and network communication.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat App")
        self.setGeometry(100, 100, 700, 600) # Initial window size

        self.aes_key = None # Stores the AES key (bytes)
        self.crypto_manager = None # Instance of AESCipher
        self.network_manager = None # Instance of NetworkManager (QThread)

        self._init_ui() # Initialize all UI components

    def _init_ui(self):
        """Initializes and lays out all the widgets for the GUI."""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- Key Management Group ---
        key_group = QGroupBox("Encryption Key (AES-256 GCM)")
        key_layout = QHBoxLayout()
        key_group.setLayout(key_layout)

        key_layout.addWidget(QLabel("AES Key (64 hex chars):"))
        self.key_entry = QLineEdit()
        self.key_entry.setPlaceholderText("Enter a 32-byte (64 hex char) AES key")
        self.key_entry.setMaxLength(64)
        key_layout.addWidget(self.key_entry)

        self.set_key_button = QPushButton("Set Key")
        self.set_key_button.clicked.connect(self.set_encryption_key)
        key_layout.addWidget(self.set_key_button)
        
        main_layout.addWidget(key_group)

        # --- Connection Settings Group ---
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QHBoxLayout()
        conn_group.setLayout(conn_layout)

        conn_layout.addWidget(QLabel("Host IP:"))
        self.host_entry = QLineEdit("127.0.0.1") # Default to localhost
        conn_layout.addWidget(self.host_entry)

        conn_layout.addWidget(QLabel("Port:"))
        self.port_entry = QLineEdit("65432") # Default port
        self.port_entry.setValidator(QIntValidator(1, 65535, self)) # Ensure valid port number
        conn_layout.addWidget(self.port_entry)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_peer)
        conn_layout.addWidget(self.connect_button)

        self.listen_button = QPushButton("Listen")
        self.listen_button.clicked.connect(self.start_listening)
        conn_layout.addWidget(self.listen_button)
        
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.clicked.connect(self.disconnect_peer)
        conn_layout.addWidget(self.disconnect_button)

        main_layout.addWidget(conn_group)

        # --- Chat Display Area ---
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True) # Make it read-only
        main_layout.addWidget(self.chat_display, 1) # Stretch factor 1 to take available space

        # --- Message Input Area ---
        message_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.returnPressed.connect(self.send_message) # Send on Enter key
        message_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        message_layout.addWidget(self.send_button)
        
        main_layout.addLayout(message_layout)
        
        self._setup_text_formats() # Define colors for chat messages

    def _setup_text_formats(self):
        """Defines Q_TextCharFormat objects for different message colors."""
        self.formats = {}
        colors = {
            "black": QColor("black"),
            "blue": QColor("blue"),      # For your sent messages
            "darkblue": QColor("#00008B"), # For received messages
            "green": QColor("green"),    # For success/connection status
            "red": QColor("red"),        # For errors
            "orange": QColor("orange"),  # For warnings/disconnections
            "purple": QColor("purple"),  # For raw data warnings
            "gray": QColor("gray")       # For general status updates
        }
        for name, color in colors.items():
            fmt = QTextCharFormat()
            fmt.setForeground(color)
            self.formats[name] = fmt

    def display_message(self, message: str, color_name: str = "black"):
        """
        Appends a message to the chat display with a specified color.
        This method is thread-safe as it's called via a signal.
        """
        format = self.formats.get(color_name, self.formats["black"])
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(message + "\n", format)
        self.chat_display.setTextCursor(cursor) # Set cursor to end to ensure auto-scroll
        self.chat_display.ensureCursorVisible() # Ensure the last message is visible

    def set_encryption_key(self):
        """
        Sets the AES encryption key from the input field.
        The key must be 32 bytes (64 hexadecimal characters).
        """
        key_hex = self.key_entry.text().strip()
        if len(key_hex) == 64: # 32 bytes = 64 hex characters
            try:
                self.aes_key = bytes.fromhex(key_hex)
                self.crypto_manager = AESCipher(self.aes_key)
                self.display_message("Encryption key set successfully!", "green")
                # If network is already running, update its crypto_manager
                if self.network_manager and self.network_manager.isRunning():
                    self.network_manager.encryption_cipher = self.crypto_manager
            except ValueError:
                self.display_message("Invalid hex key. Please enter 64 hex characters (0-9, a-f, A-F).", "red")
            except Exception as e:
                self.display_message(f"Error setting key: {e}", "red")
        else:
            self.display_message("AES key must be 32 bytes (64 hex characters).", "red")

    def connect_to_peer(self):
        """Initiates a connection to a peer as a client."""
        if not self._check_preconditions():
            return
        
        host = self.host_entry.text()
        port = int(self.port_entry.text()) # QIntValidator ensures this is a valid int

        self.network_manager = NetworkManager(host, port, is_server=False)
        self.network_manager.encryption_cipher = self.crypto_manager
        # Connect signals from NetworkManager to this GUI's slots
        self.network_manager.message_received_signal.connect(self._handle_received_message)
        self.network_manager.status_update_signal.connect(self.display_message)
        self.network_manager.start()

    def start_listening(self):
        """Starts listening for incoming connections as a server."""
        if not self._check_preconditions():
            return

        host = self.host_entry.text()
        # For listening on all available interfaces, use '0.0.0.0'
        if host == "127.0.0.1": # Suggest '0.0.0.0' if local host is set for listening
            reply = QMessageBox.question(self, "Listen Host IP", 
                                        "For listening, it's often better to use '0.0.0.0' to accept connections from any interface. Use '127.0.0.1' for local testing only. Continue with current IP?",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return
        
        port = int(self.port_entry.text())

        self.network_manager = NetworkManager(host, port, is_server=True)
        self.network_manager.encryption_cipher = self.crypto_manager
        self.network_manager.message_received_signal.connect(self._handle_received_message)
        self.network_manager.status_update_signal.connect(self.display_message)
        self.network_manager.start()

    def disconnect_peer(self):
        """Disconnects the current network connection."""
        if self.network_manager and self.network_manager.isRunning():
            self.network_manager.stop()
            # Wait for thread to finish to ensure proper cleanup before clearing reference
            self.network_manager.wait() 
            self.network_manager = None
        else:
            self.display_message("Not connected or listening.", "orange")

    def send_message(self):
        """
        Encrypts and sends the message from the input field.
        """
        message_text = self.message_input.text()
        if not message_text:
            return # Don't send empty messages

        if not self.network_manager or not self.network_manager.isRunning():
            self.display_message("Not connected. Cannot send message.", "red")
            return
        
        if not self.crypto_manager:
            self.display_message("Encryption key not set. Cannot send securely.", "red")
            return

        self.display_message(f"You: {message_text}", "blue")
        self.message_input.clear() # Clear the input field after sending

        try:
            encrypted_msg = self.crypto_manager.encrypt(message_text.encode('utf-8'))
            self.network_manager.send_data(encrypted_msg)
        except Exception as e:
            self.display_message(f"Encryption/Send failed: {e}", "red")

    def _handle_received_message(self, decrypted_data: bytes):
        """
        Slot to handle messages received from the NetworkManager thread.
        Updates the chat display with the decrypted message.
        """
        try:
            # Decode using UTF-8, ignore errors for robustness with varied input
            self.display_message(f"Peer: {decrypted_data.decode('utf-8', errors='ignore')}", "darkblue")
        except Exception as e:
            self.display_message(f"Error decoding received message: {e}", "red")
            self.display_message(f"Peer (raw bytes): {decrypted_data.hex()}", "red")

    def _check_preconditions(self) -> bool:
        """Checks if key is set and network is not already running."""
        if not self.crypto_manager:
            self.display_message("Please set an encryption key first.", "red")
            return False
        
        if self.network_manager and self.network_manager.isRunning():
            self.display_message("Already connected or listening. Disconnect first.", "orange")
            return False
        
        try:
            port = int(self.port_entry.text())
            if not (1024 <= port <= 65535): # Standard ephemeral port range or above 1023
                self.display_message("Port must be between 1024 and 65535.", "red")
                return False
        except ValueError:
            self.display_message("Invalid port number. Please enter a valid integer.", "red")
            return False
            
        return True

    def closeEvent(self, event):
        """Overrides the close event to ensure proper cleanup of network thread."""
        if self.network_manager and self.network_manager.isRunning():
            self.network_manager.stop()
            self.network_manager.wait(5000) # Wait up to 5 seconds for thread to finish
            if self.network_manager.isRunning():
                print("Warning: NetworkManager thread did not terminate gracefully.")
        event.accept() # Accept the close event


# --- Main Application Entry Point ---
if __name__ == "__main__":
    from PyQt5.QtGui import QIntValidator # Import here for local scope if needed

    app = QApplication(sys.argv)
    window = SecureChatApp()
    window.show()
    sys.exit(app.exec_())
