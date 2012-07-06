/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


import java.awt.Dimension;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import org.junit.*;
import static org.junit.Assert.*;
import org.junit.Test;
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
    public void hello() {
        String text = "adfaasdfafaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                + "aaaaaaaaaaaaaaaaaaaaaaaa\n"
                + "asssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss"; 
        GeneralMessageDialog.showAndWait(null, text, "title", JOptionPane.ERROR_MESSAGE); 

    }
}
