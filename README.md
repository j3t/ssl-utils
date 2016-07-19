# ssl-utils
ssl-utils is a library of utilities to assist with developing PublicKeyInfrastructure functionality in Java applications.

## KeyStoreBuilder
The [KeyStoreBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/KeyStoreBuilder.java) is a builder-pattern style factory to create a [KeyStore](http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html). The KeyStore hold

### How to create a KeyStore with the KeyStoreBuilder
To create a KeyStore with the KeyStoreBuilder, you have to provide the type and the provider of the store. The following examples show some use cases.

#### WindowsMy
To access the Windows KeyStore, the type must be set to 'Windows-MY' and provider to 'SunMSCAPI'.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.WINDOWS_MY)
		.setProvider(KeyUsage.SUNMSCAPI)
		.setFixAliases(true)
		.build();
```
The property 'fixAliases' eliminates duplicate aliases in the key store. This possibility is sometimes required for use with older version of Java 6 (see [details](http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6672015)).

#### PKCS #12 File
To access a PKCS #12 KeyStore provided by a file, the type must be set to 'PKCS12' and path must be the absolute path to the certificate file.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS12)
		.setPath("/path/to/cert.p12")
		.build();
```

#### PKCS #11 Provider
To access a PKCS #11 KeyStore provided by a provider, the type must be set to 'PKCS11' and name to the name of the provider.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setProvider("Some-SunPKCS11-Provider")
		.build();
```

#### PKCS #11 Library (e.g. card reader)
To access a PKCS #11 KeyStore provided by a library, the type must be set to 'PKCS11' and libraryPath must be the absolute path to the library. This feature requires version 7 of Java or above.
```java
KeyStore keyStore = KeyStoreBuilder.create()
		.setType(KeyStoreType.PKCS11)
		.setLibraryPath("/path/to/external/pkcs11.dll")
		.setPassword("123456") // optional, password or pin to access the store
		.build();
```

## SSLContextBuilder
The [SSLContextBuilder](https://github.com/j3t/ssl-utils/blob/master/src/main/java/ssl/builder/SSLContextBuilder.java) is a builder-pattern style factory to create a [SSLContext](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html).

### How to create a SSLContext with the SSLContextBuilder
To create a SSLContext with the [SSLContextBuilder](src/main/java/ssl/builder/SSLContextBuilder.java), you have to provide a KeyStore to authenticate yourself and an optional list of [TrustManager](http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/TrustManager.html) (default: trust all peers). The examples below show some use cases.

#### KeyStore
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.build();
```

#### password protected KeyStore
```java
SSLContext sslContext = SSLContextBuilder.create()
		.setKeyStore(keyStore)
		.setKeyStorePassword("123456".toCharArray())
		.build();
```

#### trust all peers that trusted by Windows
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setTrustManagers(TrustManagerHelper.createWindowsRootTrustManagers())
		.build();
```

#### choose an specific key - when there more than one - from the KeyStore for authentification
```java
SSLContext sslContext = SSLContextBuilder.create()
		...
		.setAliasSelectionStrategy(new StaticAliasSelectionStrategy("ENV")
		.build();
```
This configuration always chooses the alias 'ENV', regardless of the other aliases/keys in the KeyStore.

To control the behavior more specific, you have to implement your own AliasSelectionStrategy. The following example chooses the first alias found in the KeyStore, which has the KeyUsage DIGITAL_SIGNATURE.
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
