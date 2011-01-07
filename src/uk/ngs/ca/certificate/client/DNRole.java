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

import org.bouncycastle.util.encoders.Base64;

import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class DNRole {

    Document document = null;

    public DNRole(String dn) {
        try {
            byte[] b = Base64.encode(dn.getBytes());
            String encodedDN = new String(b);

            String roleURL = SysProperty.getValue("uk.ngs.ca.request.dn.role.url");
            roleURL = roleURL + "/" + encodedDN;
            roleURL = roleURL + "/" + "role";
            Client c = new Client(Protocol.HTTPS);

            Request request = new Request(Method.GET, new Reference(roleURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            document = response.getEntityAsDom().getDocument();

        }catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    public String getRole() {
        String role = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/dn/role");

            role = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return role;
        }
    }

}
