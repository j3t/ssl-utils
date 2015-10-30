# ssl-utils
ssl-utils is a bundle of factories and tools to access PublicKeyInfrastructure in Java applications.

### KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html).

##### PKI via Windows
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_MY)
		.setProvider(KeyUsage.SUNMSCAPI)
		.setFixAliases(true) // eliminate duplicate aliases
		.build();
```

##### PKI via PKCS12-certificate
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

##### PKI via PKCS11-implementation  
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setLibraryPath("/path/to/custom/pkcs11.lib")
		.build();
```

### SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html).

##### SSLContext with a KeyStore
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.build();
```

##### SSLContext with a password protected KeyStore
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.setKeyStorePassword("123456".toCharArray())
		.build();
```

##### SSLContext accepts self signed client certificates
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustManagers(TrustManagerHelper.createAllowAllTrustManagers())
		.build();
```

##### usage with the Apache HTTP Client
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();

SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.setKeyStorePassword("123456".toCharArray())
		.build();

HttpClients.custom()
		.setSslcontext(sslContext)
		.build()
		.execute(new HttpGet("https://server"));
```
