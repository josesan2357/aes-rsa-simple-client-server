"""
CLIENT
CS475 P2
RAUL DELIOTH
"""

#!/usr/bin/env python3
import socket
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

#server address
HOST = 'isoptera.lcsc.edu'
PORT = 5101

#private key generation
key = RSA.generate(2048)
private_key = key.export_key()
print('Private key: ', private_key, '\n')

#public key generation
public_key = key.publickey().export_key()
print('Public key: ', public_key, '\n')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.connect((HOST,PORT))

	#send public key
	s.send(public_key)
	print('Public key sent \n')

	#receive encrypted AES key
	enc_session_key = s.recv(256)
	print('Encrypted AES key received: ', enc_session_key, '\n')

	#decript AES key with private key
	cipher_rsa = PKCS1_OAEP.new(key)
	session_key = cipher_rsa.decrypt(enc_session_key)
	print('Decripted AES key with private key: ', session_key, '\n')

	#messages
	while True:
		#enter message
		data = bytes(input('>>> Enter message: '), 'utf-8')

		#encrypt message
		cipher = AES.new(session_key, AES.MODE_EAX)
		nonce = cipher.nonce
		ciphertext, tag = cipher.encrypt_and_digest(data)
		print('Encrypted message: ', ciphertext, '\n')
		#print('Lenght of Encrypted message: ', len(enc_session_key), '\n')

		#send encrypted message
		s.send(ciphertext)
		s.send(nonce)
		s.send(tag)
		print('Sent encrypted messsage. Waiting for reply...')

		#receive encrypted message
		ciphertext = s.recv(256)
		nonce = s.recv(16)
		tag = s.recv(16)
		print('Received encrypted message: ', ciphertext, '\n')

		#decrypt message
		cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
		plaintext = cipher.decrypt(ciphertext)
		print("Decrypted message: ", plaintext.decode('utf-8'), '\n')

