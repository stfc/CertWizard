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
package uk.ngs.ca.info;

import java.io.IOException;
import java.util.ArrayList;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.ClientInfo;
import org.restlet.data.Header;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Retrieves CA information when calling <tt>/CA</tt> Rest resource.
 *
 * @author xw75 (Xiao Wang)
 * @author David Meredith (some small modification, javadoc, lots to refactor
 * still)
 */
public class CAInfo {

    String CAURL = SysProperty.getValue("uk.ngs.ca.request.ca.url");
    private Document document;

    /**
     * Create a new CAInfo instance and call the CA server.
     *
     * @throws IOException If the remote call to fetch the RA list fails
     */
    public CAInfo() throws IOException {
        Client c = RestletClient.getClient();

        Request request = new Request(Method.GET, new Reference(CAURL));

        Series<Header> headers = request.getHeaders();
        headers.set("PPPK", "this is pppk");
        headers.set("LocalHost", ClientHostName.getHostName());

        //by calling clientinfo to change standard header
        ClientInfo info = new ClientInfo();

        info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));

        request.setClientInfo(info);
        Response response = c.handle(request);
        try {
            String responseValue = response.getEntity().getText();
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.xml.sax.InputSource is = new org.xml.sax.InputSource();
            is.setCharacterStream(new java.io.StringReader(responseValue));
            document = db.parse(is);
        } catch (ParserConfigurationException ex) {
            throw new IllegalStateException(ex);  // coding error 
        } catch (SAXException ex) {
            throw new IllegalStateException("Could not parse CAInfo response", ex); // coding error
        }
    }

    /**
     * @return the list of RAs fetched from the server.
     */
    public String[] getRAs() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/RAlist/ra");
            NodeList raLists = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
            ArrayList<String> RAs = new ArrayList<>();
            for (int i = 0; i < raLists.getLength(); i++) {
                Element raElement = (Element) raLists.item(i);
                NodeList ouLists = raElement.getElementsByTagName("ou");
                Element ouElement = (Element) ouLists.item(0);
                String ou = ouElement.getFirstChild().getNodeValue();

                NodeList lLists = raElement.getElementsByTagName("l");
                Element lElement = (Element) lLists.item(0);
                String l = lElement.getFirstChild().getNodeValue();

                if (ou != null && l != null) {
                    String RA = ou.trim() + " " + l.trim();
                    RAs.add(RA);
                }
            }
            //Arrays.sort(RAs); // do not sort, we need to preserve the order returned from server 
            return RAs.toArray(new String[0]);
        } catch (XPathExpressionException ex) {
            throw new IllegalStateException("Problem parsing RAList", ex); // coding error
        }
    }
}
