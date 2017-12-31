# PSM
Pretty Secure Messaging

## What
Based on NaCl, easy to use python class when in need of asymmetric and/or symmetric encryption.

## Example
  me = PSM()
  you = PSM()
  me.add_peer(you.publicKey_string, you.id)
  encrypted_msg = me.publickey_encrypt_message([you.id])
  decrypted_msg = you.decrypt_message(encrypted_msg)

