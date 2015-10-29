# ssl-utils
This library provides easy access to public key infrastructure in Java applications.

## Create an HTTP call with the PKI from the Windows KeyStore 

```java
KeyStore keyStore = KeyStoreBuilder.create()
        .setType(WINDOWS_MY)
        .setProvider(SUNMSCAPI)
        .setFixAliases(true)
        .build();
         
SSLContext sslContext = SSLContextBuilder.create()
        .setKeyStore(keyStore)
        .build();
         
HttpClient client = HttpClients.custom()
        .setSslcontext(sslContext)
        .build();
     
HttpResponse response = client.execute(new HttpGet(new URI("https://secure.server")));
         
assertEquals(200, response.getStatusLine().getStatusCode());
```