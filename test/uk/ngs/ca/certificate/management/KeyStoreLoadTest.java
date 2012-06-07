/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

import java.io.File;
import org.junit.*;
import static org.junit.Assert.*;

/**
 *
 * @author djm76
 */
public class KeyStoreLoadTest {
    
    public KeyStoreLoadTest() {
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
    // TODO add test methods here.
    // The methods must be annotated with annotation @Test. For example:
    //
    @Test
    public void hello() throws Exception {
      File f = new File("/home/djm76/.globus/david_meredith_UK_e-ScienceCert_Exp08Aug2012.p12"); 
      
    
    }
}
