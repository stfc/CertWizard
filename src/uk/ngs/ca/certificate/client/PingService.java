/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

//import java.io.File;
//import org.w3c.dom.Document;
//import javax.xml.xpath.XPath;
//import javax.xml.xpath.XPathFactory;
//import javax.xml.xpath.XPathExpression;
//import javax.xml.xpath.XPathConstants;

import org.restlet.Client;
import org.restlet.Context;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.Response;
import org.restlet.Request;
import org.restlet.data.Method;

import org.restlet.data.Status;
//import org.restlet.ext.xml.DomRepresentation;
//import org.restlet.resource.ClientResource;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Ping the server.
 * @author xw75 
 */
public final class PingService {

  
    private PingService() {  // force non-instantiation with private constructor.
    }

    /**
     * Get the shared, thread safe PingService instance.
     * @return
     */
    public static PingService getPingService() {
        return PingServiceHolder.pingService;
    }

   /**
    * PingServiceHolder is loaded on the first execution of PingService.getInstance()
    * or the first access to PingServiceHolder.pingService, not before.
    */
    private static class PingServiceHolder {
         public static final PingService pingService = new PingService();
    }

    /*public synchronized String getHost() {
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
                Document document = new DomRepresentation(response.getEntity()).getDocument();
                //Document document = response.getEntityAsDom().getDocument();

                XPath xpath = XPathFactory.newInstance().newXPath();
                XPathExpression expr = xpath.compile("/pingservice/host");

                host = (String) expr.evaluate(document, XPathConstants.STRING);
            }
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return host;
        }
    }*/

    /**
     * Ping the CA server with a ping request.
     *
     * @return true if successful ping otherwise false.
     */
    public boolean isPingService() {
        boolean isPing = false;
        Response response = null;
        try {
            // lets check to see that the trust is set
            //System.setProperty("javax.net.ssl.trustStore", "C:/Documents and Settings/djm76/.ca/truststore.jks");
            //System.setProperty("javax.net.ssl.trustStorePassword", "passwd");
            //String trustStoreFile = System.getProperty("javax.net.ssl.trustStore");
            //String trustStorePW = System.getProperty("javax.net.ssl.trustStorePassword");
            //System.out.println("trustStore: "+trustStoreFile);
            //System.out.println("password: "+trustStorePW);
//            File trustStore = new File(trustStoreFile);
//            if(!trustStore.exists() || !trustStore.canRead()){
//                throw new IllegalStateException("Error, unable to read truststore file");
//            }


            String pingURL = SysProperty.getValue("uk.ngs.ca.request.pingservice.url");
            Client client = new Client(new Context(), Protocol.HTTPS);
            
            //client.setConnectTimeout(20000);

            Request request = new Request(Method.GET, new Reference(pingURL));

            System.out.println("TIMEOUT SUPPOSED TO BE SET TO: " +client.getConnectTimeout());
            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);
            System.out.println("pinging URL [" + pingURL+"]");

            response = client.handle(request);
            //System.out.println("==============after response====================");
            //System.out.println("======== STATUS RECEIVED" + response.getStatus().toString() + " ===============================================");
            if (response.getStatus().equals(Status.SUCCESS_OK)) {
                isPing = true;
            }
            //System.out.println("==============isPing true====================");

            //Representation out = response.getEntity();
            //out.write(System.out);

            // change the systems online status and update any observers. 
            SystemStatus.getInstance().setIsOnline(isPing);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            // ensure that the response is fully read. 
            try{ response.getEntity().getStream().close();} catch (Exception ex){}
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
