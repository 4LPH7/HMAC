
# Encryption Utility with HMAC and AES

This is a Python-based encryption utility that allows users to encrypt and decrypt messages using AES encryption, generate HMAC (Hash-based Message Authentication Code) values for integrity verification, and save/load encrypted data in JSON format.

## Features
- **Encrypt and Decrypt Messages**: Encrypt a message using AES encryption in CBC mode and decrypt it.
- **Generate HMAC**: Create an HMAC for a message using a secret key.
- **Save Encrypted Data**: Save the encrypted message, initialization vector (IV), and HMAC in a JSON file.
- **Load Encrypted Data**: Load encrypted data from a JSON file and decrypt it.
- **User-friendly GUI**: A simple graphical interface built with `customtkinter` for easy interaction.

## Requirements

- Python 3.x
- **Libraries**:
  - `cryptography`: For AES encryption and decryption.
  - `hmac` and `hashlib`: For HMAC generation.
  - `customtkinter`: A custom extension of Tkinter to create a modern, professional-looking GUI.
  - `json`: For saving and loading encrypted data in JSON format.
  
To install the required libraries, run the following commands:

```bash
pip install cryptography customtkinter
```

## Installation

1. Clone or download the repository.
2. Install the required dependencies by running the command above.
3. Run the `HMAC.py` file to start the application.

## How to Use

1. **Encrypt a Message**:
   - Enter the message you want to encrypt and the secret key (16, 24, or 32 characters).
   - Click the "Encrypt" button to get the encrypted message, IV, and HMAC.
   
2. **Generate HMAC**:
   - Enter the message and key, and click "Generate HMAC" to generate an HMAC for the message.

3. **Save Encrypted Message**:
   - After encrypting a message, click the "Save Encrypted Message" button to save the encrypted data (IV, ciphertext, HMAC) in a JSON file.

4. **Decrypt Message from File**:
   - Click "Decrypt from JSON File" to select a JSON file containing encrypted data and decrypt it using the provided key.

5. **Clear Output**:
   - Click the "Clear Output" button to clear the output window.

## GUI Overview

- **Message**: Enter the message to be encrypted or HMAC to be generated.
- **Key**: Enter the encryption key (16, 24, or 32 characters).
- **Encrypt**: Encrypt the message with AES encryption.
- **Decrypt from JSON File**: Load a JSON file containing encrypted data and decrypt it.
- **Generate HMAC**: Create an HMAC for the message using the key.
- **Save Encrypted Message**: Save the IV, ciphertext, and HMAC to a JSON file.
- **Clear Output**: Clear the output text box.

## Example Workflow

1. Enter a message like "Hello, world!" and a key (e.g., `1234567890abcdef`).
2. Click **Encrypt** to see the output, which includes the IV, ciphertext, and HMAC.
3. Save the encrypted message by clicking **Save Encrypted Message**.
4. Later, load the saved JSON file and click **Decrypt from JSON File** to view the original message.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- GitHub: [@4LPH7](https://github.com/4LPH7)

Feel free to contribute or suggest improvements!

---
### Show your support

Give a ⭐ if you like this website!

<a href="https://buymeacoffee.com/arulartadg" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-violet.png" alt="Buy Me A Coffee" height= "60px" width= "217px" ></a>
