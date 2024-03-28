# Org.Websn.X509Certificates.Abstraction
A library for working with certificates, without needing to know how and where they are stored.

## Overview

### Getting a Certificate from the Store
```cs
public X509Certificate2 Get(string name, bool includePrivateKey = false)
```
+ `includePrivateKey`: Should the private key if be retrived. If there is no private key the certificate will should be returned without it.
  + Default: `false`

### Storing a Certificate in the Store
```cs
public void Store(string name, X509Certificate2 certificate, bool includePrivateKey = true)
```
+ `includePrivateKey`: Should the private key if be stored. If there is no private key the certificate will should be stored without it.
  + Default: `true`