/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Method;
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
            Request request = new Request(Method.GET, new Reference(csrURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            Document document = response.getEntityAsDom().getDocument();

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Motd/text");

            text = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return text;
        }
    }

    public String getLatestVersion() {
        String img = null;
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

            Document document = response.getEntityAsDom().getDocument();
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
                      img = ((Node) fstNm.item(0)).getNodeValue();
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
            return img;
        }
    }

    public String getImage() {
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
            Document document = response.getEntityAsDom().getDocument();

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Motd/img");

            img = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return img;
        }
    }
    
}
