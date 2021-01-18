/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import java.io.StringReader;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.restlet.Response;
import org.restlet.data.Status;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * Common utility methods for processing CSR new and renew requests.
 *
 * @author David Meredith
 */
public class OnlineCertUtil {

    private static final Logger logger = LogManager.getLogger(OnlineCertUtil.class);

    /**
     * Try and parse the server error response XML doc (if any) and return a
     * message.
     */
    public static String getServerErrorMessage(Response response) {
        if (response.getStatus().equals(Status.SUCCESS_ACCEPTED)) {
            // 202 - This means that the server understood the request, but 
            // there were errors/problems. In this scenario, the server sends 
            // back an XML document that wraps the cause. 
            try {
                String xmlResponse = response.getEntityAsText();
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                InputSource source = new InputSource(new StringReader(xmlResponse));
                Document responseDoc = factory.newDocumentBuilder().parse(source);
                if (responseDoc != null) {
                    NodeList allTextNodes = responseDoc.getElementsByTagName("text");
                    if (allTextNodes != null) {
                        Node node_minor_text = allTextNodes.item(1);
                        if (node_minor_text != null) {
                            return node_minor_text.getTextContent();
                        }
                    }
                }
            } catch (Exception ex) {
                logger.warn("Could not parse server error response XML doc", ex);
            }
        } else if (response.getStatus().equals(Status.CLIENT_ERROR_NOT_FOUND)) {
            //404
            return "There is no such service. Please check system configure file.";
        } else if (response.getStatus().equals(Status.CLIENT_ERROR_FORBIDDEN)) {
            //403
            return "Failed authentication. Please contact the helpdesk";
        } else if (response.getStatus().equals(Status.CLIENT_ERROR_METHOD_NOT_ALLOWED)) {
            //405
            return "Server does not support POST.";
        } else {
            return "A problem occurred submitting the request. Please contact the helpdesk.";
        }
        return "";
    }
}