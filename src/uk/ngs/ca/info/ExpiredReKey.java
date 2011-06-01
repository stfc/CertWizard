/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.info;

import org.restlet.Client;
import org.restlet.Response;
import org.restlet.Request;
import org.restlet.data.Protocol;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.data.Form;

import org.w3c.dom.Document;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ExpiredReKey {

    String CAURL = SysProperty.getValue("uk.ngs.ca.request.ca.maxexpiredrekey.url");
    private Document document;

    public ExpiredReKey() {
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

    public int getMaxReKeyTime() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Policy/MaxExpiredReKey[1]/text()");
            String result = (String) expr.evaluate(document, XPathConstants.STRING);
            return new Integer(result).intValue();
        } catch (Exception ep) {
            ep.printStackTrace();
            return -1;
        }

    }

}
