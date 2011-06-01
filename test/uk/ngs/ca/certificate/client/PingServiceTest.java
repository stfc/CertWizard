/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.client;

import java.io.File;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author djm76
 */
public class PingServiceTest {

    public PingServiceTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
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


    /**
     * Test of isPingService method, of class PingService.
     */
    @Test
    public void testIsPingService() {
        System.out.println("isPingService");
        
        String truststore = System.getProperty("user.home")+File.separator+".ca"+File.separator+"truststore.jks";
        File f = new File(truststore);
        assertTrue(f.exists());
        System.setProperty("javax.net.ssl.trustStore", truststore);
        System.setProperty("javax.net.ssl.trustStorePassword", "passwd");


        PingService ps  = PingService.getPingService();
        for(int i=0; i<10; i++){
          boolean alive = ps.isPingService();
          assertTrue(alive);
        }
        
    }

}