/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;


import org.w3c.dom.Document;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.Response;
import org.restlet.Request;
import org.restlet.data.Method;
import org.restlet.data.Status;
import org.restlet.ext.xml.DomRepresentation;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class CAMotd {

    public CAMotd() {
    }

    public String getText() {
        String text = null;
        try {
            String csrURL = SysProperty.getValue("uk.ngs.ca.request.ca.motd.text.url");
            Client c = new Client(Protocol.HTTPS);
            c.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

            Request request = new Request(Method.GET, new Reference(csrURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            Document document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Motd/text");

            text = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return text;
        }
    }

    /**
     * Get the latest version of CertWizard supported by the server. 
     * @return The latest CertWizard version or null if no version info can be 
     * retrieved from the server. 
     */
    public String getLatestVersion() {
        String latestVersion = null;
        try {
            String csrURL = SysProperty.getValue("uk.ngs.ca.request.ca.url");
            Client c = new Client(Protocol.HTTPS);
            Request request = new Request(Method.GET, new Reference(csrURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            //response.getStatus().
            if(!response.getStatus().equals(Status.SUCCESS_OK)){
                return null; 
            }

            Document document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();
            // transform the Document into a String
            document.getDocumentElement().normalize();
            NodeList nodeLst = document.getElementsByTagName("certWizard");

            for (int s = 0; s < nodeLst.getLength(); s++) {

                Node fstNode = nodeLst.item(s);

                if (fstNode.getNodeType() == Node.ELEMENT_NODE) {

                      Element fstElmnt = (Element) fstNode;
                      NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("latestVersion");
                      Element fstNmElmnt = (Element) fstNmElmntLst.item(0);
                      NodeList fstNm = fstNmElmnt.getChildNodes();
//                      System.out.println("SERVER VERSION NO === : "  + ((Node) fstNm.item(0)).getNodeValue());
                      latestVersion = ((Node) fstNm.item(0)).getNodeValue();
                }
            }
//            Document document = response.getEntityAsDom().getDocument();
//            XPath xpath = XPathFactory.newInstance().newXPath();
//            XPathExpression expr = xpath.compile("/CA");
//
//            img = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return latestVersion;
        }
    }

    /*public String getImage() {
        String img = null;
        try {
            String csrURL = SysProperty.getValue("uk.ngs.ca.request.ca.motd.img.url");
            Client c = new Client(Protocol.HTTPS);
            Request request = new Request(Method.GET, new Reference(csrURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            Document document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Motd/img");

            img = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return img;
        }
    }*/
    
}
