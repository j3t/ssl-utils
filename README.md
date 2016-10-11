[![Build Status](https://travis-ci.org/j3t/ssl-utils.svg?branch=master)](https://travis-ci.org/j3t/ssl-utils)
[![Build status](https://ci.appveyor.com/api/projects/status/pr53x6w9i7bnghwv/branch/master?svg=true)](https://ci.appveyor.com/project/j3t/ssl-utils/branch/master)
[![Download Maven Central](https://img.shields.io/badge/maven--central-deployed-blue.svg)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.github.j3t%22%20AND%20a%3A%22ssl-utils%22)
[![Apache License 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/j3t/ssl-utils/blob/master/LICENSE)
[![Code Coverage](https://img.shields.io/codecov/c/github/j3t/ssl-utils/master.svg)](https://codecov.io/github/j3t/ssl-utils?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/j3t/ssl-utils/badge.svg)](https://coveralls.io/github/j3t/ssl-utils)

# ssl-utils
Is a library of utilities to assist with developing security functionality in Java applications.

In the diagram below (Source: [Oracle](http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html)) you can see how a secure connection is created in general and which component's are involved.

![JSSE KeyClasses](http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/classes1.jpg)

ssl-utils provides some builder to create key materials easily and quickly. There are also helpers to access the key materials and to control the runtime behavior. The library is written in Java and requires version 6 or higher.

## SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html). To create a SSLContext, the KeyStore - to authenticate yourself - and the TrustStore - to define the trusted peers - must be configured.

To create the default SSL Context, nothing has to be configured. In this case the default key- and trust store of the JVM is used. The default SSL protocol is TLS v1.2 (JVM v7 or higher) or TLS v1.0 (JVM v6 or lower).
```java
SSLContext sslContext = SSLContextBuilder.create()
		.build();
```

you can also configure a key- or trust-store...
```java
KeyStore trustStore = ...
KeyStore keyStore = ...
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustStore(trustStore)
		.setKeyStore(keyStore)
		.setKeyStorePassword("changeit")
		.build();
```

To control the alias selection during the authentication, you must configure an [KeyManagerStrategy](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/strategy/KeyManagerStrategy.java).
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyManagerStrategy(() -> "MyAlias")
		.build();
```

or use the [KeyStoreHelper](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/KeyStoreHelper.java) to find an certificate/alias with a specific key usage...

```java
KeyStore keyStore = ...
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.setKeyManagerStrategy(() -> getAliases(keyStore, DIGITAL_SIGNATURE)[0])
		.build();
```

To control the trustworthiness of peer - independent of the trust manager configured in actual context - you must configure an [TrustManagerStrategy](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/strategy/TrustManagerStrategy.java).

trust all peers...
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustManagerStrategy((chain, authType) -> true)
		.build();
```

or use the [CertificateHelper](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/CertificateHelper.java) to check the issuer...
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustManagerStrategy((chain, authType) -> getIssuers(chain).contains("MyIssuer"))
		.build();
```

## KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/com/github/j3t/ssl/utils/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html). The KeyStore represents a storage facility for cryptographic keys and certificates (key materials). To create a KeyStore, the type and the provider must be configured.

To access a PKCS #12 key store, the type must be set to 'PKCS12' and path must be the absolute path to the certificate file.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

To access a PKCS #11 key store, the type must be set to 'PKCS11' and name must be the name of the provider. Note: The provider must already be registered.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setProvider("CustomProvider")
		.build();
```

To access a PKCS #11 key store with a provided library (e.g. smart card reader), the type must be set to 'PKCS11' and libraryPath must be the absolute path to the library.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setLibraryPath("/path/to/pkcs11.lib")
		.setPassword("123456") // optional, password or pin to access the store
		.build();
```
