from messenger_client import MessengerClient
from cryptography.hazmat.primitives.asymmetric import ec
from messenger_server import MessengerServer

class Server:
    def __init__(self):
        self.inboxes = {}
    

    def registerWithToken(self, client : MessengerClient, deliveryToken):
        self.inboxes[deliveryToken] = client
    
    def sendSealedMessage(self, deliveryToken, header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac):
        self.inboxes[deliveryToken].receiveMail(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)


print("Initializing Server")
server_sign_sk = ec.generate_private_key(ec.SECP256R1())
server_enc_sk = ec.generate_private_key(ec.SECP256R1())
server = MessengerServer(server_sign_sk, server_enc_sk)

server_sign_pk = server_sign_sk.public_key()
server_enc_pk = server_enc_sk.public_key()


print("Initializing Users")
alice = MessengerClient("alice", server_sign_pk, server_enc_pk)
bob = MessengerClient("bob", server_sign_pk, server_enc_pk)
carol = MessengerClient("carol", server_sign_pk, server_enc_pk)

print("Generating Certs")
certA = alice.generateCertificate()
certB = bob.generateCertificate()
certC = carol.generateCertificate()

print("Signing Certs")
sigA = server.signCert(certA)
sigB = server.signCert(certB)
sigC = server.signCert(certC)


print("Distributing Certs")
try:
    alice.receiveCertificate(certB, sigB)
    alice.receiveCertificate(certC, sigC)
    alice.receiveCertificate(certA, sigA)
    bob.receiveCertificate(certA, sigA)
    bob.receiveCertificate(certB, sigB)
    bob.receiveCertificate(certC, sigC)
    carol.receiveCertificate(certA, sigA)
    carol.receiveCertificate(certB, sigB)
    carol.receiveCertificate(certC, sigC)
except:
    print("certificate verification issue")


server = Server()

server.registerWithToken(deliveryToken='1', client=alice)
server.registerWithToken(deliveryToken='2', client=bob)

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = alice.sendSealedMessage('bob', 'hello')

server.sendSealedMessage('2', header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)

print(bob.messages)