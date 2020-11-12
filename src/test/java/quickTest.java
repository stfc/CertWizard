/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Pattern;
import javax.swing.*;
import net.sf.portecle.gui.error.DThrowable;
import org.junit.*;
import static org.junit.Assert.*;
import org.junit.Test;
import resources.TestUtil;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.common.GuiExecutor;
import uk.ngs.certwizard.gui.GeneralMessageDialog;

/**
 * Use this class to do quick testing. 
 * @author David Meredith
 */
public class quickTest {
    
    public quickTest() {
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
    public void testDave() throws Exception{
        String path = quickTest.class.getResource("/resources/sample.pem").toURI().getPath();
        String pemString = TestUtil.readFileAsString(path); 
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(pemString.getBytes("UTF-8"));
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(is);
        String pk64 = EncryptUtil.getEncodedPublicKey(certificate.getPublicKey()); 
        System.out.println(pk64);
        //  url = /resources/resource/publickey/<base64encodedpubkey>
        // https://cwiz-live.ca.ngs.ac.uk/resources/resource/publickey/MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh8cdAzrBmB9M+bDk5jdWeD8rNNcPaTrjX855DEMXeHv1oCE/pReaEOy6qlgSrJaREPftbu4VxUvnl/o7oZBgZj5PqmxVXQqTg/76JBF6CtQEefzA6W8LCmSn2saEUygmcxDrUp8u7EGD5g2fbZdek643zUxxr2GyqWDyGiI5ESgrMz8YGcCZwm6xfRrKLKsK4uHL5OyUtKqv7nZm8ANMevh7P0khw38F5SQG4NYpqmey2O8XC8GHRAiZP+hwHOQbmJE3jvUglg3xG4Q0UUEA0Uo01ywKk7rENk21Hg+pOMvq6ZVQOEOB3lYLFhreaVxjkOB7u09gJa8k4PgkkRJwTwIDAQAB
    }

    @Test 
    public void testTolerance(){
         Calendar dateThirtyDaysAgo = Calendar.getInstance(TimeZone.getTimeZone("UTC")); 
         dateThirtyDaysAgo.add(Calendar.DAY_OF_MONTH, -30);
         Date d = new Date(); 
         Calendar now = Calendar.getInstance(TimeZone.getTimeZone("UTC")); 
         now.setTime(d);
         
         if(dateThirtyDaysAgo.before(now)){
             System.out.println("yp");
         } else {
             System.out.println("np");
         }
    }
    
    @Test
    public void testNormalizier(){
      String s = "garçoné";
      String ss = Normalizer.normalize(s, Normalizer.Form.NFD);
      System.out.println(ss);
      String normal = stripAccents(s); 
      assertEquals("garcone", normal);
    }

    //http://blog.smartkey.co.uk/2009/10/how-to-strip-accents-from-strings-using-java-6/
    public static String stripAccents(String s) {
        s = Normalizer.normalize(s, Normalizer.Form.NFD);
        s = s.replaceAll("\\p{InCombiningDiacriticalMarks}+", "");
        return s;
    }
    
    @Test
    public void testAssciAlphaNumericOnly(){
        //Pattern alphaNumericOnly = Pattern.compile("[0-9A-Za-z\\s_\\.,]+"); 
        Pattern alphaNumericSpaceOnly = Pattern.compile("[0-9A-Za-z\\s]+");
        
        String illegalChar = "' adfa "; 
        assertFalse(alphaNumericSpaceOnly.matcher(illegalChar).matches());

        illegalChar = "davídó garçoné"; // extended 
        assertFalse(alphaNumericSpaceOnly.matcher(illegalChar).matches());
        
        String okSeq  = "DAVE this is theworld 111343 comc ad"; 
        assertTrue(alphaNumericSpaceOnly.matcher(okSeq).matches());
    }
    

    
    
    
    
    /*@Test
    public void hello() {
        //String text = "adfaasdfafaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        //        + "aaaaaaaaaaaaaaaaaaaaaaaa\n"
        //        + "asssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"; 
        //GeneralMessageDialog.showAndWait(null, text, "title", JOptionPane.ERROR_MESSAGE); 
        
        final JDialog dlg = new JDialog();
        dlg.setModal(true);
        dlg.setTitle("Please wait...");
        //JProgressBar dpb = new JProgressBar();
        //dpb.setIndeterminate(true);
        //dlg.add(BorderLayout.CENTER, dpb);
        dlg.add(BorderLayout.CENTER, new JLabel("Processing"));
        //dlg.add(BorderLayout.NORTH, new JLabel("Progress..."));
        dlg.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        dlg.setSize(300, 50);
        //dlg.setLocationRelativeTo(this);
        GuiExecutor.instance().execute(new Runnable() {

            public void run() {
                dlg.setVisible(true);
            }
        }); 
        

        try {
            Thread.sleep(3000);
            dlg.dispose();
        } catch (Exception ex) {
            dlg.dispose();
        }

    }*/

}
