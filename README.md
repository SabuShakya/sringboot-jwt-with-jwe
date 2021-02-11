# JWE #

JSON Web Encryption provides a way to keep data opaque to third parties. Opaque in this case means unreadable.
JWE essentially provides two schemes: a shared secret scheme, and a public/private-key scheme.

The shared secret scheme works by having all parties know a shared secret. Each party that holds
the shared secret can both encrypt and decrypt information. This is analogous to the case of a
shared secret in JWS: parties holding the secret can both verify and generate signed tokens.

The public/private-key scheme, however, works differently. While in JWS the party holding the
private key can sign and verify tokens, and the parties holding the public key can only verify those
tokens, in JWE the party holding the private key is the only party that can decrypt the token. In
other words, public-key holders can encrypt data, but only the party holding the private-key can
decrypt (and encrypt) that data.

JSON Web Tokens (JWT) can be signed then encrypted to provide confidentiality of the claims.
*Why is sign-then-encrypt the preferred order?*
- Prevents attacks in which the signature is stripped, leaving just an encrypted message.
- Provides privacy for the signer.
- Signatures over encrypted text are not considered valid in some jurisdictions.