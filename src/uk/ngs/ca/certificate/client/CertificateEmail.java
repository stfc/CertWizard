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
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Method;

import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class CertificateEmail {

    Document document = null;

    public CertificateEmail(String certID) {
        try {
            String certURL = SysProperty.getValue("uk.ngs.ca.request.certificate.email.url");
            certURL = certURL + "/" + certID;
            certURL = certURL + "/" + "useremail";

            Client c = new Client(Protocol.HTTPS);

            Request request = new Request(Method.GET, new Reference(certURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);

            document = response.getEntityAsDom().getDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    public String getEmail() {
        String email = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/useremail");

            email = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return email;
        }
    }

}
