/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.management;

import org.junit.*;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author djm76
 */
public class KeyStoreWrapperTest {

    public KeyStoreWrapperTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        SysProperty.setupTrustStore(); // throws IllegalStateException if prob
        String trustStoreFile = SysProperty.getValue("ngsca.truststore.file");
        String trustStorePath = System.getProperty("user.home");
        trustStorePath = trustStorePath + System.getProperty("file.separator") + ".ca";
        trustStorePath = trustStorePath + System.getProperty("file.separator") + trustStoreFile;

        String password = SysProperty.getValue("ngsca.cert.truststore.password");
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", password);
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }


    @Test
    public void testit() throws Exception {


       /* ClientKeyStore clientKeyStore = ClientKeyStore.getClientkeyStore("daf1djm".toCharArray());
        // create new keypair entry under new meaningless alias and re-save file.
        // this bit looks dodgy to me, it creates a self signed cert and
        // specifies xw's email and STFC DL attributes - why????
        String alias = clientKeyStore.createNewKeyPair();
        assertNotNull(alias);
        PublicKey publicKey = clientKeyStore.getPublicKey(alias);
        assertNotNull(publicKey);
        PrivateKey privateKey = clientKeyStore.getPrivateKey(alias);
        assertNotNull(privateKey);*/
    }

    /**
     * Test of getInstance method, of class CSR_And_CertificateInfo.
     */
    /*@Test
    public void testGetInstance() throws Exception {
        System.out.println("getInstance");
        char[] passphrase = "daf1djm".toCharArray();
        KeyStoreWrapper instance = KeyStoreWrapper.getInstance(passphrase);
        assertNotNull(instance);
        instance.loadKeyStoreWithOnlineEntryUpdate();
 
        List<KeyStoreEntryWrapper> entries = instance.getKeyStoreEntries();
        for(Iterator<KeyStoreEntryWrapper> it = entries.iterator(); it.hasNext();){
            KeyStoreEntryWrapper kse = it.next();
            System.out.println(""+kse.getAlias() + kse.getCreationDate());
            if(kse.getServerCertificateCSRInfo() != null){
                System.out.println("owner: "+kse.getServerCertificateCSRInfo().getOwner());
                System.out.println("status: "+kse.getServerCertificateCSRInfo().getStatus());

            }
        }
    }*/

}