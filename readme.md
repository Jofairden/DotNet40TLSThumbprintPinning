# DotNet40TLSThumbprintPinning
Keyword: .NET 4.0, HttpWebRequest, TLS (1.2), SSL, Certificate Pinning, HPKP, Expect-CT

# About
Showcases how to perform forced TLS with a proper server validation callback
that performs certificate pinning to ensure certificate validity
and safeguards against MITM attacks. Note, the program does not perform any
form of pure HPKP. (Which is deprecated anyways, see the notes about the new
Expect-CT Header).In the example we showcase comparing the SHA-1 Thumbprint of 
the certificateto verify validity, which is possibly the easiest form of pinning 
but not the best. Other forms of pinning can be implemented such as certificate pinning 
or public key pinning, each with their pros and cons.

**This repository is meant to serve as an example on how you can enable TLS 
support for HttpWebRequest when targeting .NET 4.0 as well as performing some type 
of server certificate validation callback. It is wise to implement a more thorough
implementation of the pinning based on your needs.**

_Of course, the current implementation to enforce TLS support will not work for Unix-based systems
(Mac/Linux) and only supports Windows at this time._

Note that we are only verifying the leaf here, you can modify the code to verify
the entire certificate chain instead.

# Pinning rules
These rules count for any type of pinning that you do:

1. The client (this application) is pre-configured to know what server certificate it should expect.
1. If the server certificate does not match the pre-configured server certificate then the client will prevent the session from taking place.
