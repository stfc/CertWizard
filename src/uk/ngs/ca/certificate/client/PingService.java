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

import org.restlet.data.Status;
import org.restlet.resource.Representation;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class PingService {

    public PingService() {
    }

    public String getHost() {
        String host = null;
        try {
            String pingURL = SysProperty.getValue("uk.ngs.ca.request.pingservice.url");
            Client c = new Client(Protocol.HTTPS);
            Request request = new Request(Method.GET, new Reference(pingURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            if (response.getStatus().equals(Status.SUCCESS_OK)) {
                Document document = response.getEntityAsDom().getDocument();

                XPath xpath = XPathFactory.newInstance().newXPath();
                XPathExpression expr = xpath.compile("/pingservice/host");

                host = (String) expr.evaluate(document, XPathConstants.STRING);
            }
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return host;
        }
    }

    public boolean isPingService() {
        boolean isPing = false;
        try {
            String pingURL = SysProperty.getValue("uk.ngs.ca.request.pingservice.url");
            Client c = new Client(Protocol.HTTPS);
            Request request = new Request(Method.GET, new Reference(pingURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            //System.out.println("======== STATUS RECEIVED" + response.getStatus().toString() + " ===============================================");
            if (response.getStatus().equals(Status.SUCCESS_OK)) {
                isPing = true;
            }

            //Representation out = response.getEntity();
            //out.write(System.out);
            
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return isPing;
        }
    }
/* 
    public static void main(String[] args) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String message = SysProperty.setupTrustStore();
        if (message == null) {
            String trustStoreFile = SysProperty.getValue("ngsca.truststore.file");
            String trustStorePath = System.getProperty("user.home");
            trustStorePath = trustStorePath + System.getProperty("file.separator") + ".ca";
            trustStorePath = trustStorePath + System.getProperty("file.separator") + trustStoreFile;

            String password = SysProperty.getValue("ngsca.cert.truststore.password");
            System.setProperty("javax.net.ssl.trustStore", trustStorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", password);
//            System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        } else {
            javax.swing.JOptionPane.showMessageDialog(null, message, "Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }
        PingService s = new PingService();
        System.out.println("is Ping = " + s.isPingService());
//        System.out.println("ping host = " + s.getHost());

    }
 */
    
}
