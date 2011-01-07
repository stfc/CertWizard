/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.info;

import org.restlet.Client;
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Protocol;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.data.Form;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.Arrays;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import uk.ngs.ca.tools.property.SysProperty;

/** this class will retrieve CA information when calling /CA service.
 *
 * @author xw75
 */
public class CAInfo {

    String CAURL = SysProperty.getValue("uk.ngs.ca.request.ca.url");
    private Document document;

    public CAInfo() {
        init();
    }

    private void init() {
        Client c = new Client(Protocol.HTTPS);
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
        } catch (Exception ep) {
            ep.printStackTrace();

        }

    }

    public String getVersion() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/certWizard/latestVersion[1]/text()");
            return (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public String getMoTDMessage() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/motd/text[1]/text()");
            return (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

   
    public String[] getRAs() {
        String[] RAs = null;

        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/RAlist/ra");
            NodeList raLists = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
            RAs = new String[raLists.getLength()];

            for (int i = 0; i < raLists.getLength(); i++) {
                Element raElement = (Element) raLists.item(i);
                NodeList ouLists = raElement.getElementsByTagName("ou");
                Element ouElement = (Element) ouLists.item(0);
                String ou = ouElement.getFirstChild().getNodeValue();

                NodeList lLists = raElement.getElementsByTagName("l");
                Element lElement = (Element) lLists.item(0);
                String l = lElement.getFirstChild().getNodeValue();

                String RA = ou + " " + l;
                RAs[i] = RA;
            }
            //sort the String array.
            Arrays.sort(RAs);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return RAs;
        }

    }

    public static String[] offLineRAs = {"Aberystwyth ComputerScience",
        "Aston University ISA",
        "Authority CLRC",
        "BBSRC BITS",
        "BBSRC IGER",
        "BBSRC Roslin",
        "Bangor SOI",
        "Bath BUCS",
        "Bath Chemistry",
        "Birmingham ParticlePhysics",
        "Bristol IS",
        "Bristol Physics",
        "Brunel ECE",
        "CLRC DL",
        "CLRC External",
        "CLRC RAL",
        "Cambridge UCS",
        "Cardiff WeSC",
        "Cranfield CCC",
        "CranfieldShrivenham CS",
        "Culham IT",
        "DLS DAG",
        "Durham eScience",
        "Edinburgh NeSC",
        "Glasgow Compserv",
        "Imperial LeSC",
        "Imperial Physics",
        "Kingston Grid",
        "Lancaster LeSC",
        "Lancaster Physics",
        "Leeds ISS",
        "Leicester Physics",
        "Liverpool CSD",
        "Liverpool Physics",
        "Macaulay ITS",
        "Manchester HEP",
        "Manchester MC",
        "ManchesterMet ISU",
        "NERC CEH",
        "NERC POL",
        "NERC SO",
        "Newcastle NEReSC",
        "Nottingham IS",
        "Oxford OeSC",
        "PML DTG",
        "Portsmouth DSG",
        "QUB BESC",
        "QueenMaryLondon Physics",
        "Reading ITS",
        "RoyalHollowayLondon Physics",
        "SOAS Linguistics",
        "Sheffield CICS",
        "Southampton NOC",
        "Southampton SOC",
        "Southampton SeSC",
        "Stirling IS",
        "Swansea LIS",
        "Training RA",
        "UCL EISD",
        "UEA ITCS",
        "Unis ITS",
        "Warwick UOW",
        "Westminster ComputerScience",
        "York ComputerScience"};

}
