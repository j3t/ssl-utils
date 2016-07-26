<p align="right">
  <a href="https://travis-ci.org/j3t/ssl-utils">
    <img src="https://travis-ci.org/j3t/ssl-utils.svg?branch=master" alt="Build Status Image"/>
  </a>
</p>

# ssl-utils
Is a library of utilities to assist with developing security functionality in Java applications.

In the diagram below (Source: [Oracle](http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html)), you can see how a secure connection is created in general and which compentent's are involved.

![JSSE KeyClasses](http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/classes1.jpg)

ssl-utils contains builder and helper to create and access the key material and the SSL context. The library is written in Java and requires version 7 or above.

## KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html). The KeyStore represents a storage facility for cryptographic keys and certificates (Key Material). To create a KeyStore, the type and the provider must be configured. The following examples demonstrate some common use cases.

### Create standard Windows key store
To access the Windows key store, the type must be set to 'Windows-MY' and provider to 'SunMSCAPI'.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_MY)
		.setProvider(KeyStoreProvider.SUNMSCAPI)
		.build();
```

### Create standard Windows trust store
To access the Windows trust store, the type must be set to 'Windows-ROOT' and provider to 'SunMSCAPI'.
```java
KeyStore trustStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_ROOT)
		.setProvider(KeyStoreProvider.SUNMSCAPI)
		.build();
```

### Create key store from a PKCS #12 file
To access a PKCS #12 file key store, the type must be set to 'PKCS12' and path must be the absolute path to the certificate file.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

### Create key store from a PKCS #11 provider
To access a PKCS #11 provider key store, the type must be set to 'PKCS11' and name to the name of the provider.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setProvider("Some-SunPKCS11-Provider")
		.build();
```

### Create key store from a PKCS #11 library (e.g. Smart Card Reader)
To access a PKCS #11 library key store, the type must be set to 'PKCS11' and libraryPath must be the absolute path to the library.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setLibraryPath("/path/to/external/pkcs11.dll")
		.setPassword("123456".toCharArray()) // optional, password or pin to access the store
		.build();
```

## SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html). To create a SSLContext, the KeyStore - to authenticate yourself - and the TrustStore - to define the trusted peers - must be configured. The following examples demonstrate some common use cases.

### With given key- and trust-store
```java
KeyStore trustStore = ...
KeyStore keyStore = ...
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustStore(trustStore)
		.setKeyStore(keyStore)
		.build();
```

### With password protected key store
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setKeyStorePassword("changeit")
		.build();
```

### With Windows trust-store
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustStore(KeyStoreBuilder.createWindowsRoot())
		.build();
```

### With custom key manager strategy
To control the alias selection during the authentication, no matter the alias exists or the certificate is valid, you must configure an [KeyManagerStrategy](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/strategy/KeyManagerStrategy.java).
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setKeyManagerStrategy(...)
		.build();
```

### With custom trust manager strategy
To control the trustworthiness of certificates independent of the trust manager configured in actual context, you must configure an [TrustManagerStrategy](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/strategy/TrustManagerStrategy.java).
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustManagerStrategy(...)
		.build();
```
