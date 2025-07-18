Secure Chat App for Windows
Project Overview
This project is a peer-to-peer secure messaging application built for Windows using Python and PyQt5 for the user interface. Its primary purpose is to demonstrate the implementation of strong symmetric encryption (AES-256 GCM) for confidential and authenticated communication over a network. This application serves as a practical showcase of cybersecurity principles, including cryptography, network programming, and secure UI design.

Features
End-to-End Encryption: All messages are encrypted using AES-256 in GCM (Galois/Counter Mode) before transmission and decrypted upon reception. GCM provides both data confidentiality and integrity, ensuring messages remain private and untampered.

Intuitive PyQt5 GUI: A modern and user-friendly graphical interface built with PyQt5, offering a clear chat display, message input, and connection controls.

Multi-threaded Network Operations: Network communication (listening, connecting, sending, receiving) runs in a separate thread to ensure the user interface remains responsive.

Peer-to-Peer Communication: Supports direct connection between two instances of the application (one acting as a server, one as a client).

Status Updates: Provides real-time status messages in the chat window for connection events, errors, and warnings.

Technologies Used
Python 3.x: The core programming language.

PyQt5: Python binding for the Qt cross-platform application framework, used for building the graphical user interface.

cryptography library: A powerful and secure library for cryptographic operations, specifically used for AES-256 GCM encryption and decryption.

socket module (Python Standard Library): Used for low-level network communication (TCP sockets).

threading module (Python Standard Library): Used to manage concurrent network operations without freezing the UI.

Getting Started
Prerequisites
Python 3.x installed on your Windows machine(s).

pip (Python package installer) installed.

Installation
Clone the repository:

git clone https://github.com/abhishek7k/secure-chat-app.git
cd secure-chat-app

Install required Python packages:

pip install PyQt5 cryptography

Usage
Run the application:
Open your command prompt or terminal and navigate to the project directory. Then run:

python secure-chat-app.py

You will need to run two instances of this application (one for each participant in the chat).

Set the AES Encryption Key:

Crucial Step: Both instances of the app must use the exact same 32-byte AES key.

In the "AES Key (64 hex chars)" field, enter a 64-character hexadecimal string. This represents a 32-byte (256-bit) key.

Example Key (for testing ONLY - DO NOT USE IN PRODUCTION):
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

You can generate a random 32-byte hex key in a Python interpreter:

import os
print(os.urandom(32).hex())

Click the "Set Key" button. The app will confirm if the key was set successfully.

Establish Connection (Local Network Example):

PC 1 (Server - Listening):

Find your PC's Local IP Address: Open Command Prompt (cmd), type ipconfig, and look for "IPv4 Address" (e.g., 192.168.1.100).

In the app, set "Host IP" to 0.0.0.0 (to listen on all interfaces) and "Port" to a chosen number (e.g., 65432).

Click the "Listen" button. The app will show "Listening on 0.0.0.0:65432...".

Important: Ensure your firewall (e.g., Windows Defender Firewall) on PC 1 allows inbound TCP connections on the chosen port (65432). You might need to create a new inbound rule.

PC 2 (Client - Connecting):

In the app, set the "Host IP" to the Local IP Address of PC 1 (e.g., 192.168.1.100).

Set the "Port" to the same port number as PC 1 (e.g., 65432).

Click the "Connect" button.

Start Chatting!

If the connection is successful, both apps will display "Connected!".

You can now type messages in the input field and press Enter or click "Send". Messages will be encrypted by the sender and decrypted by the receiver.

Security Considerations
Key Management (Crucial): For this demonstration, a pre-shared AES key is used. In a real-world secure messaging application, the secure exchange of cryptographic keys is paramount and would typically involve asymmetric cryptography (e.g., Diffie-Hellman key exchange) to establish a session key securely. The current method of sharing the key out-of-band is for demonstration purposes only and is not suitable for production environments.

Network Firewalls: Ensure local firewalls are configured to allow the application's network traffic.

Public IP / Port Forwarding: For communication over the internet (between different networks), the "server" PC's network router would require port forwarding configured to direct incoming traffic on the chosen port to the server PC's local IP address. This carries inherent security risks and should be done with caution.

Project Highlights
This project demonstrates proficiency in:

Cryptography Implementation: Practical application of AES-256 GCM for strong encryption, ensuring both message confidentiality and integrity.

Network Programming: Hands-on experience with Python's socket module for building peer-to-peer communication.

Multithreading: Effective use of threading (via PyQt's QThread) to create a responsive GUI that doesn't freeze during network operations.

GUI Development: Design and implementation of an intuitive and modern user interface using PyQt5.

Security Principles: Understanding and application of fundamental security concepts like encryption modes, key management challenges, and network communication security.

Problem-Solving: Addressing challenges related to network connectivity, data serialization, and thread synchronization.

Future Enhancements
Implement a secure Diffie-Hellman key exchange protocol to establish session keys dynamically.

Add user authentication (e.g., username/password, public-key authentication).

Implement message history storage (encrypted on disk).

Add support for multiple clients/peers (a more complex server architecture).

Include error logging to a file for easier debugging.

Improve network robustness with better error handling and reconnection logic.
