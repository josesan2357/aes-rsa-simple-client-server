"""
SERVER
CS475 P2
RAUL DELIOTH
"""

#!/usr/bin/env python3
import socket
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

#server address
HOST = '0.0.0.0'
PORT = 5101

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST,PORT))
	s.listen()
	conn, addr = s.accept()
	print('Connected to: ', addr, '\n')

	#receive public key
	received = conn.recv(2048)
	public_key = RSA.import_key(received)
	print('Received public key: ', received.decode('utf-8'), '\n')

	#generate an AES key
	session_key = get_random_bytes(16)
	print('Generated AES key: ', session_key, '\n')

	#encrypt the AES key with public key
	cipher_rsa = PKCS1_OAEP.new(public_key)
	enc_session_key = cipher_rsa.encrypt(session_key)
	print('Encrypted AES key with public key: ', enc_session_key, '\n')
	#print('Lenght of encrypted AES key: ', len(enc_session_key), '\n')

	#send encrypted AES key
	conn.send(enc_session_key)
	print('Sent encrypted AES key \n')
	print('Waiting for message... \n')

	#messages
	while True:
		#receive encrypted message
		ciphertext = conn.recv(256)
		nonce = conn.recv(16)
		tag = conn.recv(16)
		print('Received encrypted message: ', ciphertext, '\n')

		#decrypt message
		cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
		plaintext = cipher.decrypt(ciphertext)
		print("Decrypted message: ", plaintext.decode('utf-8'), '\n')

		#enter reply
		data = bytes(input('>>> Enter message: '), 'utf-8')

		#encrypt message
		cipher = AES.new(session_key, AES.MODE_EAX)
		nonce = cipher.nonce
		ciphertext, tag = cipher.encrypt_and_digest(data)
		print('Encrypted message: ', ciphertext, '\n')
		#print('Lenght of Encrypted message: ', len(enc_session_key), '\n')

		#send encrypted message
		conn.send(ciphertext)
		conn.send(nonce)
		conn.send(tag)
		print('Sent encrypted messsage. Waiting for reply...')
