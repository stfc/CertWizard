/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package xmlparsing;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import java.io.StringWriter;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import resources.TestUtil;
import static org.junit.Assert.*;

/**
 * Test parsing of a sample error message. 
 * 
 * @author David Meredith
 */
public class TestParseXMLErrorDoc {
    
    public TestParseXMLErrorDoc() {
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


    @Test
    public void testParseErrorDoc() throws Exception {
        String path = TestParseXMLErrorDoc.class.getResource("/resources/errorSample1.xml").toURI().getPath();
        String xmlString = TestUtil.readFileAsString(path); 
     
        
        DocumentBuilderFactory factory =  DocumentBuilderFactory.newInstance();
        InputSource source = new InputSource(new StringReader(xmlString));
        Document doc = factory.newDocumentBuilder().parse(source);
        assertNotNull(doc);
        String xmlString2 = this.getStringFromDocument(doc);
        assertNotNull(xmlString2);
        //System.out.println(xmlString2);
        
        NodeList allTextNodes = doc.getElementsByTagName("text");
        assertEquals(2, allTextNodes.getLength());
        
        Node node_major_text = allTextNodes.item(0);
        assertEquals("text", node_major_text.getNodeName());
        assertEquals("Certificate error", node_major_text.getTextContent()); 
        
        
        Node node_minor_text = allTextNodes.item(1);
        assertEquals("text", node_minor_text.getNodeName());
        assertEquals("some detail", node_minor_text.getTextContent());  

        
    }
    
    
    //method to convert Document to String
    public String getStringFromDocument(Document doc) {
        try {
            DOMSource domSource = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            return writer.toString();
        } catch (TransformerException ex) {
            ex.printStackTrace();
            return null;
        }
    }
}