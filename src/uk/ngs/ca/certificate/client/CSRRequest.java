/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.Response;
import org.restlet.Request;
import org.restlet.data.Method;

//import javax.xml.transform.dom.DOMSource;
//import javax.xml.transform.Transformer;
//import javax.xml.transform.TransformerFactory;
//import javax.xml.transform.OutputKeys;
//import javax.xml.transform.stream.StreamResult;

import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75 (Xiao Wang) 
 */
public class CSRRequest {

    private String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    private String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private String MESSAGE = "";
    private boolean isCSRRequestSuccess = false;

    public CSRRequest(String csrString, String pin, String email) {
        Client c = new Client(Protocol.HTTPS);
        c.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

        Request request = new Request(Method.POST, new Reference(CSRURL), getRepresentation(csrString, pin, email));

        Form form = new Form();
        form.add("LocalHost", ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);

//by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);

        Response response = c.handle(request);

        if (response.getStatus().equals(response.getStatus().SUCCESS_CREATED)) {
            MESSAGE = "Your CSR has been submitted to the CA server successfully. \nIt is waiting for the approval and signing by an RA and CA operator.";
            isCSRRequestSuccess = true;
        } else if (response.getStatus().equals(response.getStatus().SUCCESS_ACCEPTED)) {
            try {
                MESSAGE = _getFormattedMessage(response);
                isCSRRequestSuccess = false;
            } catch (Exception ep) {
                ep.printStackTrace();
            }
        } else {

            MESSAGE = "A problem occurred during the submission process. This could be due to a Server side problem.\n"
                    + "Please try again later. If the problem persists, please contact the helpdesk support at \n"
                    + "support@grid-support.ac.uk";
            isCSRRequestSuccess = false;
        }
    }

    private String _getFormattedMessage(Response response) {
        String message = "";

        try {
            Document document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();
//            // transform the Document into a String
//            DOMSource domSource = new DOMSource(document);
//            TransformerFactory tf = TransformerFactory.newInstance();
//            Transformer transformer = tf.newTransformer();
//            //transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
//            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
//            transformer.setOutputProperty(OutputKeys.ENCODING, "ISO-8859-1");
//            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
//            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
//            java.io.StringWriter sw = new java.io.StringWriter();
//            StreamResult sr = new StreamResult(sw);
//            transformer.transform(domSource, sr);
//            String xml = sw.toString();
            document.getDocumentElement().normalize();
            NodeList nodeLst = document.getElementsByTagName("minor");

            for (int s = 0; s < nodeLst.getLength(); s++) {

                Node fstNode = nodeLst.item(s);

                if (fstNode.getNodeType() == Node.ELEMENT_NODE) {

                    Element fstElmnt = (Element) fstNode;
                    NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("text");


                    Element fstNmElmnt = (Element) fstNmElmntLst.item(0);
                    NodeList fstNm = fstNmElmnt.getChildNodes();

                    message = (((Node) fstNm.item(0)).getNodeValue());
//                      System.out.println("SERVER VERSION NO === : "  + ((Node) fstNm.item(0)).getNodeValue());
                    //img = ((Node) fstNm.item(0)).getNodeValue();
                }
            }

            return message;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }

    }

    public String getMessage() {
        return MESSAGE;
    }

    public boolean isCSRREquestSuccess() {
        return isCSRRequestSuccess;
    }

    private Representation getRepresentation(String csrString, String pin, String email) {
        DomRepresentation representation;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("CSR");
            d.appendChild(rootElement);

            Element eltName = d.createElement("Request");
            eltName.appendChild(d.createTextNode(csrString));
            rootElement.appendChild(eltName);

            eltName = d.createElement("PIN");
            eltName.appendChild(d.createTextNode(pin));
            rootElement.appendChild(eltName);

            eltName = d.createElement("Email");
            eltName.appendChild(d.createTextNode(email));
            rootElement.appendChild(eltName);

            String _version = SysProperty.getValue("ngsca.certwizard.version");
            eltName = d.createElement("Version");
            eltName.appendChild(d.createTextNode(_version));
            rootElement.appendChild(eltName);

            d.normalizeDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
        return representation;
    }
}
