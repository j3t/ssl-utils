package com.github.j3t.ssl.utils.test;


import com.github.j3t.ssl.utils.KeyStoreBuilder;
import com.github.j3t.ssl.utils.SSLContextBuilderIT;

import java.security.KeyStore;

import static com.github.j3t.ssl.utils.types.KeyStoreType.JKS;
import static com.github.j3t.ssl.utils.types.KeyStoreType.PKCS12;

public interface Fixtures {
    String CLIENT_JKS = SSLContextBuilderIT.class.getResource("/certs/client.jks").getFile();
    String CLIENT_TRUST_JKS = SSLContextBuilderIT.class.getResource("/certs/client-trust.jks").getFile();
    String SERVER_JKS = SSLContextBuilderIT.class.getResource("/certs/server.jks").getFile();
    String SERVER_TRUST_JKS = SSLContextBuilderIT.class.getResource("/certs/server-trust.jks").getFile();
    String UNKNOWN_CLIENT_JKS = SSLContextBuilderIT.class.getResource("/certs/unknown-client.jks").getFile();
    String CLIENT_P12 = SSLContextBuilderIT.class.getResource("/certs/client.p12").getFile();
    String EMPTY_JKS = SSLContextBuilderIT.class.getResource("/certs/empty.jks").getFile();
    String MULTI_JKS = SSLContextBuilderIT.class.getResource("/certs/multi.jks").getFile();

    /**
     * The client JKS key store fixture (Password: 'PtUPmi#o').<br>
     * <br>
     * <code>
     * Keystore type: JKS<br>
     * Keystore provider: SUN<br>
     * <br>
     * Your keystore contains 1 entry<br>
     * <br>
     * Alias name: client<br>
     * Creation date: Jul 22, 2016<br>
     * Entry type: PrivateKeyEntry<br>
     * Certificate chain length: 1<br>
     * Certificate[1]:<br>
     * Owner: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 296faac0<br>
     * Valid from: Fri Jul 22 13:40:29 CEST 2016 until: Sun Jul 07 13:40:29 CEST 2019<br>
     * Certificate fingerprints:<br>
     * MD5:  A5:AF:47:6F:C0:D5:A6:EF:F3:18:9B:7B:67:67:DA:49<br>
     * SHA1: A3:F3:48:3E:F7:28:47:0E:F2:30:75:06:7C:E4:ED:2A:00:4A:47:97<br>
     * SHA256: BB:E9:24:E9:E6:A2:BC:13:52:46:6A:E1:F2:85:F5:2A:0B:41:1B:96:6F:<br>
     * D1:DE:63:4A:26:6C:65:A8:54:A2:64<br>
     * Signature algorithm name: SHA1withDSA<br>
     * Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     * DigitalSignature<br>
     * ]<br>
     * </code>
     */
    KeyStore KEYSTORE_CLIENT = KeyStoreBuilder.create().setType(JKS).setPath(CLIENT_JKS).buildUnsecure();

    /**
     * The server JKS key store fixture (Password: 'EC\sEOoY').<br>
     * <br>
     * <code>
     * Keystore type: JKS<br>
     * Keystore provider: SUN<br>
     * <br>
     * Your keystore contains 1 entry<br>
     * <br>
     * Alias name: server<br>
     * Creation date: Jul 22, 2016<br>
     * Entry type: PrivateKeyEntry<br>
     * Certificate chain length: 1<br>
     * Certificate[1]:<br>
     * Owner: CN=localhost, OU=ssl-utils, O=server, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=server, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 259901fe<br>
     * Valid from: Fri Jul 22 13:40:30 CEST 2016 until: Sun Jul 07 13:40:30 CEST 2019<br>
     * Certificate fingerprints:<br>
     * MD5:  D8:06:8A:06:FE:D6:79:5E:E6:BA:36:EB:A9:1D:D1:27<br>
     * SHA1: DB:69:C9:BF:C4:C0:7B:5D:C8:DB:67:37:1C:14:F6:AF:4A:94:93:1E<br>
     * SHA256: 59:32:F5:16:E5:99:9F:3E:A9:2E:B1:60:78:13:12:CC:F7:FF:1D:8A:1A:<br>
     * 12:23:85:79:47:25:8B:61:BD:E0:E9<br>
     * Signature algorithm name: SHA1withDSA<br>
     * Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     * Key_CertSign<br>
     * Crl_Sign<br>
     * ]<br>
     * </code>
     */
    KeyStore KEYSTORE_SERVER = KeyStoreBuilder.create().setType(JKS).setPath(SERVER_JKS).buildUnsecure();

    /**
     * The 'unknown client' JKS key store fixture (Password: 'changeit').<br>
     * <br>
     * <code>
     * Keystore type: JKS<br>
     * Keystore provider: SUN<br>
     * <br>
     * Your keystore contains 1 entry<br>
     * <br>
     * Alias name: client<br>
     * Creation date: Jul 22, 2016<br>
     * Entry type: PrivateKeyEntry<br>
     * Certificate chain length: 1<br>
     * Certificate[1]:<br>
     * Owner: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 2f0b8581<br>
     * Valid from: Fri Jul 22 10:40:43 CEST 2016 until: Sun Jul 07 10:40:43 CEST 2019<br>
     * Certificate fingerprints:<br>
     *          MD5:  3B:A1:74:F5:D5:ED:90:65:FC:9C:F2:35:DC:88:6F:A8<br>
     *          SHA1: 8A:DB:AE:1B:6B:FD:FE:B4:46:70:C7:57:BC:FA:7F:F7:1B:A6:37:EE<br>
     *          SHA256: 32:E0:E2:77:99:D6:AF:66:6C:BF:3D:17:B2:4E:7E:7C:28:2E:CA:50:B6:<br>
     * A1:DA:61:16:48:44:00:8D:BC:04:FA<br>
     *          Signature algorithm name: SHA1withDSA<br>
     *          Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     *   DigitalSignature<br>
     * ]<br>
     * </code>
     */
    KeyStore KEYSTORE_UNKNOWN_CLIENT = KeyStoreBuilder.create().setType(JKS).setPath(UNKNOWN_CLIENT_JKS).buildUnsecure();

    /**
     * The empty JKS key store fixture (Password: 'changeit').<br>
     * <br>
     * <code>
     * Keystore type: JKS<br>
     * Keystore provider: SUN<br>
     * <br>
     * Your keystore contains 0 entries<br>
     * </code>
     */
    KeyStore KEYSTORE_EMPTY = KeyStoreBuilder.create().setType(JKS).setPath(EMPTY_JKS).buildUnsecure();

    /**
     * The multi JKS key store fixture (Password: 'changeit').<br>
     * <br>
     * <code>
     * Keystore type: JKS<br>
     * Keystore provider: SUN<br>
     * <br>
     * Your keystore contains 2 entries<br>
     * <br>
     * Alias name: client<br>
     * Creation date: Jul 27, 2016<br>
     * Entry type: trustedCertEntry<br>
     * <br>
     * Owner: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 77ebc33a<br>
     * Valid from: Fri Jul 22 12:09:57 CEST 2016 until: Sun Jul 07 12:09:57 CEST 2019<br>
     * Certificate fingerprints:<br>
     * MD5:  5D:64:BF:D9:00:14:6F:9B:23:81:6F:B0:5D:5E:71:1C<br>
     * SHA1: 4B:AD:52:F5:B1:58:59:EE:FC:C1:5D:4B:E3:E2:80:B8:7B:CA:87:6D<br>
     * SHA256: 0B:8C:6B:F9:A0:DE:F4:E3:0D:12:C0:69:52:FA:98:55:B9:78:FA:12:7A:<br>
     * 92:7F:CC:93:E0:4F:19:77:72:20:05<br>
     * Signature algorithm name: SHA1withDSA<br>
     * Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     * DigitalSignature<br>
     * ]<br>
     * <br>
     * <br>
     * *******************************************<br>
     * *******************************************<br>
     * <br>
     * <br>
     * Alias name: server<br>
     * Creation date: Jul 27, 2016<br>
     * Entry type: trustedCertEntry<br>
     * <br>
     * Owner: CN=localhost, OU=ssl-utils, O=server, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=server, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 3c7050d0<br>
     * Valid from: Fri Jul 22 12:10:11 CEST 2016 until: Sun Jul 07 12:10:11 CEST 2019<br>
     * Certificate fingerprints:<br>
     * MD5:  B9:0C:C1:D7:12:27:FD:23:4C:AA:8E:EF:C4:43:B9:6C<br>
     * SHA1: E1:28:0E:A9:10:DC:09:0D:D7:44:59:7E:CA:8B:5A:23:42:0D:C2:11<br>
     * SHA256: B4:6C:78:7A:F7:B8:A4:01:4E:97:C4:8A:0E:44:48:43:7F:4C:B9:9D:68:<br>
     * 0B:D5:6F:E2:99:EE:81:5D:A8:A2:89<br>
     * Signature algorithm name: SHA1withDSA<br>
     * Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     * Key_CertSign<br>
     * Crl_Sign<br>
     * ]<br>
     * </code>
     */
    KeyStore KEYSTORE_MULTI = KeyStoreBuilder.create().setType(JKS).setPath(MULTI_JKS).buildUnsecure();

    /**
     * The client PKCS12 key store fixture (Password: 'PtUPmi#o').<br>
     * <br>
     * <code>
     * Keystore type: PKCS12<br>
     * Keystore provider: SunJSSE<br>
     * <br>
     * Your keystore contains 1 entry<br>
     * <br>
     * Alias name: client<br>
     * Creation date: Jul 22, 2016<br>
     * Entry type: PrivateKeyEntry<br>
     * Certificate chain length: 1<br>
     * Certificate[1]:<br>
     * Owner: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 296faac0<br>
     * Valid from: Fri Jul 22 13:40:29 CEST 2016 until: Sun Jul 07 13:40:29 CEST 2019<br>
     * Certificate fingerprints:<br>
     * MD5:  A5:AF:47:6F:C0:D5:A6:EF:F3:18:9B:7B:67:67:DA:49<br>
     * SHA1: A3:F3:48:3E:F7:28:47:0E:F2:30:75:06:7C:E4:ED:2A:00:4A:47:97<br>
     * SHA256: BB:E9:24:E9:E6:A2:BC:13:52:46:6A:E1:F2:85:F5:2A:0B:41:1B:96:6F:<br>
     * D1:DE:63:4A:26:6C:65:A8:54:A2:64<br>
     * Signature algorithm name: SHA1withDSA<br>
     * Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     * DigitalSignature<br>
     * ]<br>
     * </code>
     */
    KeyStore KEYSTORE_CLIENT_P12 = KeyStoreBuilder.create().setType(PKCS12).setPath(CLIENT_P12).setPassword("PtUPmi#o").buildUnsecure();

    /**
     * The client JKS trust store fixture (Password: 'PtUPmi#o').<br>
     * <br>
     * <code>
     * Keystore type: JKS<br>
     * Keystore provider: SUN<br>
     * <br>
     * Your keystore contains 1 entry<br>
     * <br>
     * Alias name: server<br>
     * Creation date: Jul 22, 2016<br>
     * Entry type: trustedCertEntry<br>
     * <br>
     * Owner: CN=localhost, OU=ssl-utils, O=server, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=server, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 259901fe<br>
     * Valid from: Fri Jul 22 13:40:30 CEST 2016 until: Sun Jul 07 13:40:30 CEST 2019<br>
     * Certificate fingerprints:<br>
     * MD5:  D8:06:8A:06:FE:D6:79:5E:E6:BA:36:EB:A9:1D:D1:27<br>
     * SHA1: DB:69:C9:BF:C4:C0:7B:5D:C8:DB:67:37:1C:14:F6:AF:4A:94:93:1E<br>
     * SHA256: 59:32:F5:16:E5:99:9F:3E:A9:2E:B1:60:78:13:12:CC:F7:FF:1D:8A:1A:12:23:85:79:47:25:8B:61:BD:E0:E9<br>
     * Signature algorithm name: SHA1withDSA<br>
     * Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     * Key_CertSign<br>
     * Crl_Sign<br>
     * ]<br>
     * </code>
     */
    KeyStore TRUSTSTORE_CLIENT = KeyStoreBuilder.create().setType(JKS).setPath(CLIENT_TRUST_JKS).buildUnsecure();

    /**
     * The server JKS trust store fixture (Password: 'EC\sEOoY').<br>
     * <br>
     * <code>
     * Keystore type: JKS<br>
     * Keystore provider: SUN<br>
     * <br>
     * Your keystore contains 1 entry<br>
     * <br>
     * Alias name: client<br>
     * Creation date: Jul 22, 2016<br>
     * Entry type: trustedCertEntry<br>
     * <br>
     * Owner: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * Issuer: CN=localhost, OU=ssl-utils, O=client, L=Brunswick, ST=Lower Saxony, C=DE<br>
     * <br>
     * Serial number: 296faac0<br>
     * Valid from: Fri Jul 22 13:40:29 CEST 2016 until: Sun Jul 07 13:40:29 CEST 2019<br>
     * Certificate fingerprints:<br>
     * MD5:  A5:AF:47:6F:C0:D5:A6:EF:F3:18:9B:7B:67:67:DA:49<br>
     * SHA1: A3:F3:48:3E:F7:28:47:0E:F2:30:75:06:7C:E4:ED:2A:00:4A:47:97<br>
     * SHA256: BB:E9:24:E9:E6:A2:BC:13:52:46:6A:E1:F2:85:F5:2A:0B:41:1B:96:6F:<br>
     * D1:DE:63:4A:26:6C:65:A8:54:A2:64<br>
     * Signature algorithm name: SHA1withDSA<br>
     * Version: 3<br>
     * <br>
     * Extensions:<br>
     * <br>
     * #1: ObjectId: 2.5.29.15 Criticality=false<br>
     * KeyUsage [<br>
     * DigitalSignature<br>
     * ]<br>
     * </code>
     */
    KeyStore TRUSTSTORE_SERVER = KeyStoreBuilder.create().setType(JKS).setPath(SERVER_TRUST_JKS).buildUnsecure();
}
