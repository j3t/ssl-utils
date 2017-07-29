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

## KeyStoreBuilder
The [KeyStoreBuilder](src/main/java/com/github/j3t/ssl/utils/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html). The KeyStore represents a storage facility for cryptographic keys and certificates (key materials). To create a KeyStore, the type and the provider must be configured.

The following example sets up a PKCS #12 key store, while the private keys are provided by a file ...
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")  // have to be absolute
		.build();
```

It is also possible to using a custom PKCS #11 provider. Note: The provider must already be registered.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setProvider("CustomProvider") // name of the security provider
		.build();
```

An other option is to access a PKCS #11 key store via a library (e.g. smart card reader).
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setLibraryPath("/path/to/pkcs11.lib") // have to be absolute
		.setPassword("123456") // optional, password or pin to access the store
		.build();
```

## SSLContextBuilder
The [SSLContextBuilder](src/main/java/com/github/j3t/ssl/utils/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html).

To create the default SSL Context, nothing has to be configured. In this case the default key- and trust-store of the JVM is used. The default SSL protocol is TLS v1.2 (JVM v7 or higher) or TLS v1.0 (JVM v6 or lower).
```java
SSLContext sslContext = SSLContextBuilder.create()
		.build();
```

you can also build a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html) with existing key- and trust-store ...
```java
KeyStore trustStore = ...
KeyStore keyStore = ...
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustStore(trustStore)
		.setKeyStore(keyStore)
		.setKeyStorePassword("changeit")
		.build();
```

or you can also register a [KeyManagerStrategy](src/main/java/com/github/j3t/ssl/utils/strategy/KeyManagerStrategy.java) to specify an alias which will be selected when there are more than one in the key store ..
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyManagerStrategy(() -> "MyAlias")
		.build();
```

or use the [KeyStoreHelper](src/main/java/com/github/j3t/ssl/utils/KeyStoreHelper.java) to find certificates supporting a key usage.
```java
KeyStore keyStore = ...
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.setKeyManagerStrategy(() -> KeyStoreHelper.getAliases(keyStore, DIGITAL_SIGNATURE)[0])
		.build();
```

To control the trustworthiness of peers - independent of the trust manager of the actual context - the [TrustManagerStrategy](src/main/java/com/github/j3t/ssl/utils/strategy/TrustManagerStrategy.java) must be configured.

The following example overrule the result of the trust manager validation (trust any certificate/peer) ...
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustManagerStrategy((chain, authType) -> true)
		.build();
```

The next example uses the [CertificateHelper](src/main/java/com/github/j3t/ssl/utils/CertificateHelper.java) to find a certificate where the issuer is `MyIssure`...
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustManagerStrategy((chain, authType) -> CertificateHelper.getIssuers(chain).contains("CN=MyIssuer"))
		.build();
```

