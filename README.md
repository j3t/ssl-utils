# ssl-utils
ssl-utils is a bundle of factories and tools to access PublicKeyInfrastructure in Java applications.

### KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html).

##### create a KeyStore with WindowsMy PKI
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_MY)
		.setProvider(KeyUsage.SUNMSCAPI)
		.setFixAliases(true) // is used to duplicate KeyStore aliases
		.build();
```

##### create a KeySTore with PKCS12-certificate PKI
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

##### create a KeyStore with custom PKI 
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setLibraryPath("/path/to/custom/pkcs11.lib")
		.build();
```

### SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html).

##### create a SSLContext from a KeyStore
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.build();
```

##### create a SSLContext and provide the password to access the KeyStore
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setKeyStorePassword("123456".toCharArray())
		.build();
```

##### create a SSLContext and allow self signed client certificates
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
