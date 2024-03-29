/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package xmlparsing;

import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import utils.TestUtil;

/**
 * Test parsing of a sample error message. 
 * 
 * @author David Meredith
 */
public class TestParseXMLErrorDoc {
    
    public TestParseXMLErrorDoc() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }


    
    @Test 
    public void quickTest() {
       
        String sample = " one   two three, four    five  "; 
        String[] vals = sample.trim().split("[,\\s]+"); 
        assertEquals("one", vals[0]); 
        assertEquals("two", vals[1]); 
        assertEquals("three", vals[2]); 
        assertEquals("four", vals[3]); 
        assertEquals("five", vals[4]); 
        

        assertTrue(Files.isWritable(Paths.get(System.getProperty("user.home")))); 
        //Path p = Files.createTempFile(Paths.get(System.getProperty("user.home")), "certwiz", ".tmp");
        //File.createTempFile(sample, sample, null)
        //AccessController.checkPermission(new FilePermission("C:/Users/pcinstall", "read,write"));
    }


    @Test
    public void testParseErrorDoc() throws Exception {
        String path = TestParseXMLErrorDoc.class.getResource("/errorSample1.xml").toURI().getPath();
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
