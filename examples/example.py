from psm import PSM

me = PSM()
you = PSM()

me.add_peer(you.publicKey_string, you.id)

you.add_peer(me.publicKey_string, me.id)

msg = you.publickey_encrypt_message([me.id], "My secret message encrypted with my secret key")
print
print "Result after encryption with private key:\n%s" % msg

dec_msg = me.decrypt_message(msg)
print
print "Result after decryption with private key:\n%s" % dec_msg

me.add_sharedKey(label="client")
msg2 = me.secretkey_encrypt_message("My secret message encrypted with a shared key", "client")
print
print "Result after encryption with shared key:\n%s" % msg2

dec_msg2 = me.decrypt_message(msg2)
print 
print "Result after decryption with shared key:\n%s" % dec_msg2

print
print "Shared key with label 'client':\n%s" % me.get_sharedKey("client")
