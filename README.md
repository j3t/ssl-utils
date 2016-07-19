# ssl-utils
ssl-utils is a library of utilities to assist with developing PublicKeyInfrastructure functionality in Java applications.

### KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html).

#### How to create a KeyStore with the KeyStoreBuilder
To create a KeyStore with the KeyStoreBuilder, you have to provide the type and the provider of the store. The following examples show some use cases.

##### To access the Windows certificate store ...
type must be set to 'Windows-MY' and provider to 'SunMSCAPI'.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_MY)
		.setProvider(KeyUsage.SUNMSCAPI)
		.setFixAliases(true)
		.build();
```
The property 'fixAliases' eliminates duplicate aliases in the key store. This possibility is sometimes required for use with older version of Java 6 (see [details](http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6672015)).

##### To access a PKCS #12 store ...
type must be set to 'PKCS12' and path must be the absolute path to the certificate.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

##### To access a PKCS #11 store via an external library (e.g. card reader) ...
type must be set to 'PKCS11' and libraryPath must be the absolute path to the external library. This feature requires version 7 of Java or above.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setLibraryPath("/path/to/external/pkcs11.dll")
		.setPassword("123456") // optional, password or pin to access the store
		.build();
```

##### To access a PKCS #11 store via provider ...
type must be set to 'PKCS11', name to the name of the provider and the provider must be already registered (see [here] (http://docs.oracle.com/javase/7/docs/api/java/security/Security.html#getProviders()).
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setProvider("Some-SunPKCS11-Provider")
		.build();
```

### SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html).

#### How to create a SSLContext with the SSLContextBuilder
To create a SSLContext with the [SSLContextBuilder](src/main/java/ssl/builder/SSLContextBuilder.java), you have to provide a KeyStore to authenticate yourself and an optional list of [TrustManager](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/TrustManager.html) (default: trust all peers). The examples below show some use cases.

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

##### to trust all peers that also trusted by the internet explorer
the trustManagers property must be configured with the TrustManagers of Windows-ROOT.
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustManagers(TrustManagerHelper.createAllowAllTrustManagers())
		.build();
```

##### to choose an specific key - when there more than one - from the KeyStore
the aliasSelectionStrategy property must be configured.
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setAliasSelectionStrategy(new StaticAliasSelectionStrategy("ENV")
		.build();
```
This configuration always chooses the alias 'ENV'.

To control the behavior more specific, you have to implement your own AliasSelectionStrategy. The following example returns the first alias of the key store with the key usage DIGITAL_SIGNATURE ...
```java
...
public class MyAliasSelectionStrategy implements AliasSelectionStrategy
{
    private KeyStore keyStore;

    public MyAliasSelectionStrategy(KeyStore keyStore)
    {
        this.keyStore = keyStore;
    }

    @Override
    public String getSelection()
    {
        return KeyStoreHelper.getAliases(keyStore, KeyUsage.DIGITAL_SIGNATURE)[0];
    }
}
```
