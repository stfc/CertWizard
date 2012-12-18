/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.text.Normalizer;
import java.util.regex.Pattern;
import javax.swing.*;
import net.sf.portecle.gui.error.DThrowable;
import org.junit.*;
import static org.junit.Assert.*;
import org.junit.Test;
import uk.ngs.ca.common.GuiExecutor;
import uk.ngs.ca.common.MyPattern;
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
    
    @Test
    public void testMyPattern(){
        MyPattern mp = new MyPattern(); 
        //String cn = mp._getCN("davídó garçoné"); 
        //System.out.println(cn);
        boolean validCN = mp.isValidCN("davídó garçoné");
        //mp.getCN();
        assertFalse(validCN); 
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
