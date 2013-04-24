/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.info;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Form;
import org.restlet.data.Method;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Retrieves CA information when calling <tt>/CA</tt> Rest resource.
 *
 * @author xw75 (Xiao Wang) 
 * @author David Meredith (some small modification, javadoc, lots to refactor still)
 */
public class CAInfo {

    String CAURL = SysProperty.getValue("uk.ngs.ca.request.ca.url");
    private Document document;

    /**
     * Create a new CAInfo instance and call the CA server. 
     * @throws IOException If the remote call to fetch the RA list fails
     */
    public CAInfo() throws IOException {
        Client c = new Client(Protocol.HTTPS);
        c.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

        Request request = new Request(Method.GET, new Reference(CAURL));

        //by calling Form to add a customized header
        Form form = new Form();
        //it looks like server check pppk. but we need to change it.
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", uk.ngs.ca.common.ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);

        //by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();

        info.setAgent("NGS-CertWizard/1.0");

        request.setClientInfo(info);
        Response response = c.handle(request); 
        try {
            String responseValue = response.getEntity().getText();
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.xml.sax.InputSource is = new org.xml.sax.InputSource();
            is.setCharacterStream(new java.io.StringReader(responseValue));
            document = db.parse(is);
        } catch(ParserConfigurationException ex){
           throw new IllegalStateException(ex);  // coding error 
        } catch(SAXException ex){
           throw new IllegalStateException("Could not parse CAInfo response", ex); // coding error
        }
    }

    /*public String getVersion() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/certWizard/latestVersion[1]/text()");
            return (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }*/

    /*public String getMoTDMessage() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/motd/text[1]/text()");
            return (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }*/

    /**
     * @return the list of RAs fetched from the server. 
     */
    public String[] getRAs() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/RAlist/ra");
            NodeList raLists = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
            List<String> RAs = new ArrayList(); 
            for (int i = 0; i < raLists.getLength(); i++) {
                Element raElement = (Element) raLists.item(i);
                NodeList ouLists = raElement.getElementsByTagName("ou");
                Element ouElement = (Element) ouLists.item(0);
                String ou = ouElement.getFirstChild().getNodeValue();

                NodeList lLists = raElement.getElementsByTagName("l");
                Element lElement = (Element) lLists.item(0);
                String l = lElement.getFirstChild().getNodeValue();
                
                if(ou != null && l != null){
                    String RA = ou.trim() + " " + l.trim();
                    RAs.add(RA);
                }
            }
            //Arrays.sort(RAs); // do not sort, we need to preserve the order returned from server 
            return RAs.toArray(new String[0]);  
        } catch(XPathExpressionException ex){
            throw new IllegalStateException("Problem parsing RAList", ex); // coding error
        }
    }

    /*
     * public static String[] offLineRAs = {"Aberystwyth ComputerScience",
     * "Aston University ISA", "Authority CLRC", "BBSRC BITS", "BBSRC IGER",
     * "BBSRC Roslin", "Bangor SOI", "Bath BUCS", "Bath Chemistry", "Birmingham
     * ParticlePhysics", "Bristol IS", "Bristol Physics", "Brunel ECE", "CLRC
     * DL", "CLRC External", "CLRC RAL", "Cambridge UCS", "Cardiff WeSC",
     * "Cranfield CCC", "CranfieldShrivenham CS", "Culham IT", "DLS DAG",
     * "Durham eScience", "Edinburgh NeSC", "Glasgow Compserv", "Imperial LeSC",
     * "Imperial Physics", "Kingston Grid", "Lancaster LeSC", "Lancaster
     * Physics", "Leeds ISS", "Leicester Physics", "Liverpool CSD", "Liverpool
     * Physics", "Macaulay ITS", "Manchester HEP", "Manchester MC",
     * "ManchesterMet ISU", "NERC CEH", "NERC POL", "NERC SO", "Newcastle
     * NEReSC", "Nottingham IS", "Oxford OeSC", "PML DTG", "Portsmouth DSG",
     * "QUB BESC", "QueenMaryLondon Physics", "Reading ITS",
     * "RoyalHollowayLondon Physics", "SOAS Linguistics", "Sheffield CICS",
     * "Southampton NOC", "Southampton SOC", "Southampton SeSC", "Stirling IS",
     * "Swansea LIS", "Training RA", "UCL EISD", "UEA ITCS", "Unis ITS",
     * "Warwick UOW", "Westminster ComputerScience", "York ComputerScience"};
     */
}
