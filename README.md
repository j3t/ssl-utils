# ssl-utils
ssl-utils is a bundle of factories and tools to access PublicKeyInfrastructure in Java applications.

### KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html).

#### How to create a KeyStore with the KeyStoreBuilder
To create a KeyStore with the KeyStoreBuilder, you have to provide the type and the provider of the store. The following examples contains some use cases.

##### To access the Windows certificate store ...
the type must be 'Windows-MY' and the provider 'SunMSCAPI'. To prevent duplicate aliases, the property 'fixAliases' must be set to true.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_MY)
		.setProvider(KeyUsage.SUNMSCAPI)
		.setFixAliases(true)
		.build();
```

##### To access a PKCS #12 store ...
the type must be 'PKCS12' and the path to the archive file must be configured.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

##### To access a PKCS #11 store via library ...
the type must be 'PKCS11', the path to the library of the PKCS #11 implementation must be configured and Java 7 or above should be used.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setLibraryPath("/path/to/custom/pkcs11.lib")
		.build();
```

##### To access a PKCS #11 store via provider ...
the type must be 'PKCS11', the name of the provider must be configured and the provider must be already registered.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setProvider("SunPKCS11-CustomProvider")
		.build();
```

### SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html).

#### How to create a SSLContext with the SSLContextBuilder
To create a SSLContext with the SSLContextBuilder, you have to provide a KeyStore. The examples below are shown some use cases.

##### to use a KeyStore
the keyStore must be configured.
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.build();
```

##### to use a password protected KeyStore
the keyStore and the password to access the keyStore must be configured.
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.setKeyStorePassword("123456".toCharArray())
		.build();
```

##### to allow self signed client/server certificates
the trustManager must be configured.
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustManagers(TrustManagerHelper.createAllowAllTrustManagers())
		.build();
```

##### to choose an alias when more than one aliases are available in the KeyStore
the aliasSelectionStrategy must be implemented and configured.
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setAliasSelectionStrategy(new AliasSelectionStrategy()
        {
            @Override
            public String getSelection()
            {
                return KeyStoreHelper.getAliases(keyStore, KeyUsage.DIGITAL_SIGNATURE)[0];
            }
        })
		.build();
```
