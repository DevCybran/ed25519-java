ed25519-java
============

This is a fork of str4d's implementation of EdDSA in Java. You can find the original project's description below.

This fork provides easy-to-use wrapper classes, which, while using non-standard formats, make it very easy to generate key pairs and use them to sign and verify data.
The implementation uses SHA-512 for any hash operations, PBKDF2 with a 512-bit salt and 1 million iterations to derive secret keys from passwords, and AES-256-CBC-PKCS5 for private key encryption.
Any input data will be reduced to a constant-size (512 KiB) array by hashing segments to avoid the necessity of caching large amounts of data when signing / verifying large files.

Examples
--------

First, you may want to generate a key pair. Use

`Ed25519PrivateKey myPrivateKey = Ed25519PrivateKey.generate();`

to create a new private key. You can use

`Ed25519PublicKey myPublicKey = myPrivateKey.derivePublicKey();`

to fetch your public key from the private key.

Next, you may wish to sign something, using your private key. For instance a file:

`String signature = myPrivateKey.sign(myFile, null);`

Or, if you want to store the signature directly into another file, use

`myPrivateKey.signToFile(myFile, mySignatureFile, null);`

At some point, you may wish to verify the signature of a file. Use your public key:

`boolean isSignatureValid = myPublicKey.verifyFromFile(myFile, mySignatureFile, null);`

Of course it doesn't make much sense if the keys can be kept in memory only. Save them to disk using their `saveAsFile(...)` methods, and restore them using their static `loadFromFile(...)` methods. You have to supply a password to store your private key, which will be used for strong encryption. Keep your private key, and distribute your public key.



ed25519-java (original)
=======================

This is an implementation of EdDSA in Java. Structurally, it is based on the ref10 implementation in SUPERCOP (see http://ed25519.cr.yp.to/software.html).

There are two internal implementations:
* A port of the radix-2^51 operations in ref10 - fast and constant-time, but only useful for Ed25519.
* A generic version using BigIntegers for calculation - a bit slower and not constant-time, but compatible with any EdDSA parameter specification.

There are no guarantees that this is secure for use. All unit tests are passing, including tests against [the data from the Python implementation](http://ed25519.cr.yp.to/python/sign.input), and the code has been reviewed by [an independent developer](https://github.com/BloodyRookie), but it has not yet been audited by a professional cryptographer. In particular, the constant-time properties of ref10 may not have been completely retained (although this is the eventual goal for the Ed25519-specific implementation).

The code requires Java 6 (for e.g. the `Arrays.copyOfRange()` calls in `EdDSAEngine.engineVerify()`).

The JUnit4 tests require the Hamcrest library `hamcrest-all.jar`.

This code is released to the public domain and can be used for any purpose.

Code comparison
---------------

For ease of following, here are the main methods in ref10 and their equivalents in this codebase:

| EdDSA Operation | ref10 function | Java function |
| --------------- | -------------- | ------------- |
| Generate keypair | `crypto_sign_keypair` | `EdDSAPrivateKeySpec` constructor |
| Sign message | `crypto_sign` | `EdDSAEngine.engineSign` |
| Verify signature | `crypto_sign_open` | `EdDSAEngine.engineVerify` |

| EdDSA point arithmetic | ref10 function | Java function |
| ---------------------- | -------------- | ------------- |
| `R = b * B` | `ge_scalarmult_base` | `GroupElement.scalarMultiply` |
| `R = a*A + b*B` | `ge_double_scalarmult_vartime` | `GroupElement.doubleScalarMultiplyVariableTime` |
| `R = 2 * P` | `ge_p2_dbl` | `GroupElement.dbl` |
| `R = P + Q` | `ge_madd`, `ge_add` | `GroupElement.madd`, `GroupElement.add` |
| `R = P - Q` | `ge_msub`, `ge_sub` | `GroupElement.msub`, `GroupElement.sub` |

Credits
-------

* The Ed25519 class was originally ported by k3d3 from [the Python Ed25519 reference implementation](http://ed25519.cr.yp.to/python/ed25519.py).
* Useful comments and tweaks were found in [the GNUnet implementation of Ed25519](https://gnunet.org/svn/gnunet-java/src/main/java/org/gnunet/util/crypto/) (based on k3d3's class).
* [BloodyRookie](https://github.com/BloodyRookie) reviewed the code, adding many useful comments, unit tests and literature.
