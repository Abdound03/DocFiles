import rsa

(publicKey, privateKey) = rsa.newkeys(1024)
with open('publcKey.pem', 'wb') as p:
	p.write(publicKey.save_pkcs1('PEM'))
with open('privateKey.pem', 'wb') as p:
	p.write(privateKey.save_pkcs1('PEM'))

with open('publcKey.pem', 'rb') as p:
    publicKey = rsa.PublicKey.load_pkcs1(p.read())
with open('privateKey.pem', 'rb') as p:
	privateKey = rsa.PrivateKey.load_pkcs1(p.read())

# print(privateKey)
# print("------")
# print(publicKey)

message = "testgg"
ciphertext = rsa.encrypt(message.encode('ascii'), publicKey)
print(ciphertext)
print(type(ciphertext))
print(rsa.decrypt(ciphertext, privateKey).decode('ascii'))




