# ssl-utils
ssl-utils is a library of utilities to assist with developing security functionality in Java applications. The library is written in Java and requires version 7 or above.

## KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html). To create a KeyStore, you must configure the type and the provider. The following examples shows some use cases.

### WindowsMy
To access the Windows KeyStore, the type must be set to 'Windows-MY' and provider to 'SunMSCAPI'.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_MY)
		.setProvider(KeyStoreProvider.SUNMSCAPI)
		.setFixAliases(true)
		.build();
```
The property 'fixAliases' eliminates duplicate aliases in the key store. This possibility is sometimes required for use with older version of Java 6 (see [details](http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6672015)).

### PKCS #12 via File
To access a PKCS #12 KeyStore via file, the type must be set to 'PKCS12' and path must be the absolute path to the certificate file.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

### PKCS #11 via Provider
To access a PKCS #11 KeyStore via provider, the type must be set to 'PKCS11' and name to the name of the provider.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setProvider("Some-SunPKCS11-Provider")
		.build();
```

### PKCS #11 via Library (e.g. Smart Card Reader)
To access a PKCS #11 KeyStore via library, the type must be set to 'PKCS11' and libraryPath must be the absolute path to the library.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setLibraryPath("/path/to/external/pkcs11.dll")
		.setPassword("123456") // optional, password or pin to access the store
		.build();
```

## SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html). To create a SSLContext, you have to configure an KeyStore to authenticate yourself and an TrustStore to define the trusted peers. The following examples shows some use cases.

### KeyStore and TrustStore
```java
KeyStore trustStore = ...
KeyStore keyStore = ...
SSLContext sslContext = SSLContextBuilder.create()
		.setTrustStore(trustStore)
		.setKeyStore(keyStore)
		.build();
```

### KeyStore (password protected)
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setKeyStorePassword("changeit")
		.build();
```

### TrustStore (Windows-Root)
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustStore(KeyStoreBuilder.createWindowsRoot())
		.build();
```

### KeyManagerStrategy
To control the alias selection during the authentication, no matter the alias exists or the certificate is valid, you must configure an [KeyManagerStrategy](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/utils/strategy/KeyManagerStrategy.java).
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setKeyManagerStrategy(...)
		.build();
```

### TrustManagerStrategy
To control the trustworthiness of certificates independent of the trust manager configured in actual context, you must configure an [TrustManagerStrategy](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/utils/strategy/TrustManagerStrategy.java).
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustManagerStrategy(...)
		.build();
```
