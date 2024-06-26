from cryptography.hazmat.primitives.asymmetric import ec

from messenger_server import MessengerServer
from messenger_client import MessengerClient

def error(s):
  print("=== ERROR: " + s)

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
    error("certificate verification issue")


print("Testing incorrect cert issuance")
mallory = MessengerClient("mallory", server_sign_pk, server_enc_pk)
certM = mallory.generateCertificate()
try:
    alice.receiveCertificate(certM, sigC)
except:
    print("successfully detected bad signature!")
else:
    error("accepted certificate with incorrect signature")

print("Testing Reporting")
content = "inappropriate message contents"
reportPT, reportCT = alice.report("Bob", content)
decryptedReport = server.decryptReport(reportCT)
if decryptedReport != reportPT:
    error("report did not decrypt properly")
    print(reportPT)
    print(decryptedReport)
else:
    print("Reporting test successful!")


print("Testing a conversation")
header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = alice.sendSealedMessage("bob", "Hi Bob!")
msg = bob.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if msg != "Hi Bob!":
    error("message 1 was not decrypted correctly")

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = alice.sendSealedMessage("bob", "Hi again Bob!")
msg = bob.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if msg != "Hi again Bob!":
    error("message 2  was not decrypted correctly")

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = bob.sendSealedMessage("alice", "Hey Alice!")
msg = alice.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if msg != "Hey Alice!":
    error("message 3 was not decrypted correctly")

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = bob.sendSealedMessage("alice", "Can't talk now")
msg = alice.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if msg != "Can't talk now":
    error("message 4 was not decrypted correctly")

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = bob.sendSealedMessage("alice", "Started the homework too late :(")
msg = alice.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if msg != "Started the homework too late :(":
    error("message 5 was not decrypted correctly")

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = alice.sendSealedMessage("bob", "Ok, bye Bob!")
msg = bob.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if msg != "Ok, bye Bob!":
    error("message 6  was not decrypted correctly")

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac = bob.sendSealedMessage("alice", "I'll remember to start early next time!")
msg = alice.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if msg != "I'll remember to start early next time!":
    error("message 7 was not decrypted correctly")

print("conversation completed!")


print("Testing handling an incorrect message")

header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct2, sealed_mac = alice.sendSealedMessage("bob", "malformed message test")
m = bob.receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
if m != None:
    error("didn't reject incorrect message")
else:
    print("success!")


print("Testing complete")
