
# Secure Chat App for Windows (Python & AES)

## Project Overview

This project is a secure peer-to-peer messaging application designed for the Windows environment. Its core function is to facilitate private and authenticated communication between two users by implementing strong cryptographic principles. The app serves as a practical demonstration of my skills in applied cybersecurity, including cryptography, network programming, and developing a functional user interface.

## Key Features

* **End-to-End Encryption:** All messages are encrypted using **AES-256 GCM**, a robust symmetric encryption algorithm. The GCM mode ensures not only message **confidentiality** but also **integrity and authenticity** by detecting any attempts to tamper with the data in transit.
* **Intuitive PyQt5 GUI:** The application features a clean, responsive, and user-friendly graphical interface built with **PyQt5**. It provides a clear chat display and intuitive controls for a smooth user experience.
* **Real-time Peer-to-Peer Communication:** The app uses Python's standard **`socket`** module to establish a direct, real-time connection between two instances. **Multithreading** is employed to keep the GUI responsive during all network operations.

## Technologies Used

* **Python 3.x:** The core programming language.
* **`cryptography` library:** A secure, well-vetted Python library used for all cryptographic operations.
* **PyQt5:** A powerful framework for building the application's GUI.
* **`socket` and `threading`:** Python's standard libraries for handling network communication and managing concurrency.

## Getting Started

### Prerequisites

* Python 3.x installed on your Windows machine(s).
* `pip` (Python's package installer).

### Installation

1.  Clone the repository:
    ```bash
    git clone [https://github.com/](https://github.com/)[YourGitHubUsername]/[your-repo-name].git
    cd [your-repo-name]
    ```
    *(Note: Please replace `[YourGitHubUsername]` and `[your-repo-name]` with your actual GitHub details.)*

2.  Install the required Python packages:
    ```bash
    pip install PyQt5 cryptography
    ```

### Usage

To use the app, you need to run two separate instances. One will act as the server, and the other as the client.

1.  **Set the AES Key:** Both instances **must** use the exact same 32-byte (64 hex characters) key. Enter the key in the dedicated input field and click **"Set Key"**.
    * **Example Key (for testing ONLY):** `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
    * You can generate a random 32-byte key in Python: `import os; os.urandom(32).hex()`

2.  **Establish a Connection (on a Local Network):**
    * **Server PC:** Enter `0.0.0.0` for the host IP and a port number (e.g., `65432`), then click **"Listen"**. Remember to configure your Windows Firewall to allow inbound connections on this port.
    * **Client PC:** Enter the **local IP address of the server PC** (e.g., `192.168.1.100`) and the **same port number**, then click **"Connect"**.

3.  **Start Chatting!**
    * The app will display "Connected!" upon a successful connection. All messages you type will be encrypted and transmitted in real-time.

## Security Acknowledgment

This project uses a pre-shared key for demonstration purposes. In a real-world, production-grade application, this method is not secure. A proper implementation would require a secure **key exchange protocol** (e.g., Diffie-Hellman) to generate a unique session key for each communication, ensuring the key is never transmitted over an insecure channel.

---

## Resume Highlights

This project demonstrates proficiency in:

* **Cryptography:** Practical application of AES-256 GCM encryption.
* **GUI Development:** Experience building a user-friendly interface with PyQt5.
* **Networking:** Hands-on knowledge of peer-to-peer communication with Python sockets.
* **Multithreading:** Ability to create responsive applications by managing concurrent tasks.
* **Security Principles:** A deep understanding of confidentiality, integrity, and the challenges of key management.

## License

This project is licensed under the MIT License.

## Contact

For any questions or feedback, please contact me at **abhishek.kumar.secops@gmail.com**.

