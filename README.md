# H-tool
 This simple tool is generally used to hash (sha256, md5, base64) a password and crack a hashed password

About the codes in this Project:
Since md5 and sha256 hashing codes are similar, code complexity is reduced by using a single function. 
Since the Hashlib library does not have a decryption function for sha256 and md5, a simple function is written. 
This function hashes the passwords in the given word list and looks for similarities between them and the given hash value. 
Since the Base64 library has both encryption and decryption functions, no additional function is written.
