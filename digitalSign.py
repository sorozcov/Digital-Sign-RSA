# Universidad del Valle de Guatemala
# Cifrado de información 2020 2
# Grupo 7
# Implementation Digital Sign.py

#We import pycryptodome library and will use hashlib to sha512
from Crypto.PublicKey import RSA
from hashlib import sha512

#Example taken from https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples


#We'll do an example of Digital Sign using RSA
print("This is an example OF Digital Signing using pycryptodome python library.")
message = b'My Secret Message'
print("The message Alice wants to send Bob is: ", message)

# First of all, Alice needs to generate a Public Key to give to Bob and a Private Key to keep secret.
# We'll do this using RSA Algorythm
#Alice Keys for signing
aliceKeys = RSA.generate(bits=1024)
nAlice=aliceKeys.n
publicKeyAlice=aliceKeys.e
privateKeyAlice=aliceKeys.d

#Bob Keys for encrypting and decrypting using RSA
bobKeys = RSA.generate(bits=1024)
nBob=bobKeys.n
publicKeyBob=bobKeys.e
privateKeyBob=bobKeys.d

#Cipher RSA
#c=m^{e}mod {n}}
#Decipher RSA
#m=c^{d}mod {n}}

print("Alice public key is: ", hex(publicKeyAlice))
print("Alice private key is: ", hex(privateKeyAlice))
print("Both keys will need the value of n: ", hex(nAlice))

print("Bob public key is: ", hex(publicKeyBob))
print("Bob private key is: ", hex(privateKeyBob))
print("Both keys will need the value of n: ", hex(nBob))

#Alice Part
#We generate a hash from our message and make a digest
hash = int.from_bytes(sha512(message).digest(), byteorder='big')
#After that we sign it using our privateKeyAlice
signature = pow(hash, privateKeyAlice,nAlice)
print("Signature of message:", hex(signature))

#If signature was altered
# signature=signature+1

#Now we encrypt our message and send it to Bob using Bobs public key
intMessage = int.from_bytes(message, byteorder='big')
encryptedMessage = pow(intMessage, publicKeyBob,nBob)
print("Message in Int: ",intMessage)
print("Encrypted message:", hex(encryptedMessage))

#Bobs Part
#Now we decrypt our message that was send from Alice using Public Key of Bob. Now Bob uses his privateKey
intDecryptedMessage = pow(encryptedMessage, privateKeyBob,nBob)
# If message was altered
# intDecryptedMessage=intDecryptedMessage+1
print("Decrypted Message in Int: ",intDecryptedMessage)
decryptedMessage = intDecryptedMessage.to_bytes((intDecryptedMessage.bit_length()+7)//8,byteorder="big")
print("Decrypted Message: ",decryptedMessage)


#Now we verify if the signature is valid
#For that we first decrypt the message
#Then we do the same verifying the hash from the message and the hash from the signature that was send
# If they match the signature is valid
hash = int.from_bytes(sha512(decryptedMessage).digest(), byteorder='big')
hashFromSignature = pow(signature, publicKeyAlice, nAlice)
print("Signature valid:", hash == hashFromSignature)