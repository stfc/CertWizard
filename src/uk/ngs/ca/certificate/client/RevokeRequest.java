/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Method;
import org.restlet.data.Status;
import org.restlet.data.Parameter;
import org.restlet.resource.DomRepresentation;
import org.restlet.resource.Representation;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;

import java.security.PrivateKey;
import java.math.BigInteger;

import java.util.Date;

import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class RevokeRequest {

    private String REVOKEURL = SysProperty.getValue("uk.ngs.ca.request.revoke.url");
    private String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private long cert_id = -1;
    private String reason = null;
    private String MESSAGE = null;
    private PrivateKey privateKey;

    public RevokeRequest(PrivateKey privateKey, long cert_id, String reason) {
        this.privateKey = privateKey;
        this.cert_id = cert_id;
        this.reason = reason;
    }

    public String getMessage() {
        return this.MESSAGE;
    }

    private String asciiToHex(String ascii) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < ascii.length(); i++) {
            hex.append(Integer.toHexString(ascii.charAt(i)));
        }
        return hex.toString();
    }

    private String getPrivateExponent(PrivateKey _privateKey) {
        int index = _privateKey.toString().indexOf("private exponent:");
        index = index + 17;
        String subString = _privateKey.toString().substring(index);
        index = subString.indexOf("\n");
        subString = subString.substring(0, index);
        subString = subString.trim();
        return subString;
    }

    
    public boolean doPosts() {
        Client client = new Client(Protocol.HTTPS);
        Request request = new Request(Method.POST, new Reference(REVOKEURL), getRepresentation());
        Form form = new Form();
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);
//by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);

        Response response = client.handle(request);

        Status _status = response.getStatus();
        //we will do second post
        if (_status.equals(Status.CLIENT_ERROR_UNAUTHORIZED)) {
            org.restlet.util.Series<org.restlet.data.Parameter> headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
            Parameter _realmP = headers.getFirst("realm");
            Parameter _nonceP = headers.getFirst("nonce");
            Parameter _keyidP = headers.getFirst("keyid");
            Parameter _opaqueP = headers.getFirst("opaque");

            //we will do the response action from here.
            if (_opaqueP == null) {

                String _keyid = _keyidP.getValue();
                int index = _keyid.indexOf(".");
                String m = _keyid.substring(0, index).toUpperCase();
                String q = getPrivateExponent(privateKey);

                String _nonce = _nonceP.getValue() + ":" + new Date().getTime();
                _nonce = _nonce.toLowerCase();
                String c = asciiToHex(_nonce);
                c = c.toUpperCase();

                BigInteger b_c = new BigInteger(c, 16);
                BigInteger b_q = new BigInteger(q, 16);
                BigInteger b_m = new BigInteger(m, 16);
                BigInteger b_response = b_c.modPow(b_q, b_m);
                String _response = b_response.toString(16);

                Form _form = new Form();
                _form.add("PPPK", "this is pppk");
                _form.add("LocalHost", ClientHostName.getHostName());
                _form.add("keyid", _keyid);
                _form.add("realm", _realmP.getValue());
                _form.add("response", _response);

                client = new Client(Protocol.HTTPS);
                request = new Request(Method.POST, new Reference(REVOKEURL), getRepresentation());
                request.getAttributes().put("org.restlet.http.headers", _form);
                org.restlet.data.ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

            } else {
                //we will do cookie thing from here
                Form _form = new Form();
                _form.add("PPPK", "this is pppk");
                _form.add("LocalHost", ClientHostName.getHostName());
                _form.add("opaque", _opaqueP.getValue());
                /* */
                client = new Client(Protocol.HTTPS);
//please note you have to call getRepresentation() again, otherwise it will be null. Why???
                request = new Request(Method.POST, new Reference(REVOKEURL), getRepresentation());
                request.getAttributes().put("org.restlet.http.headers", _form);
                org.restlet.data.ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

                org.restlet.util.Series<org.restlet.data.Parameter> _headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
            }

            if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
                //201
                this.MESSAGE = "The certificate has been revoked successfully.";
                return true;

            } else if (response.getStatus().equals(Status.SUCCESS_ACCEPTED)) {
                //202
                try {
                    this.MESSAGE = "Error message received from the Server. Please contact the helpdesk";
                } catch (Exception ep) {
                    ep.printStackTrace();
                } finally {
                    return false;
                }

            } else if (response.getStatus().equals(Status.CLIENT_ERROR_NOT_FOUND)) {
                //404
                this.MESSAGE = "there is no such service. Please check system configure file.";
                return false;
            } else if (response.getStatus().equals(Status.CLIENT_ERROR_FORBIDDEN)) {
                //403
                this.MESSAGE = "failed authentication. Please check out PPPK";
                return false;
            } else if (response.getStatus().equals(Status.CLIENT_ERROR_METHOD_NOT_ALLOWED)) {
                //405
                this.MESSAGE = "Server does not support POST.";
                return false;
            } else {
                this.MESSAGE = "There appears to be a problem with submitting the revocation request.\n"
                        + "This could be either due to networking problems you are having or \n"
                        + "problem in the e-Science CA Server. If your connection is already up but still \n"
                        + "unable to complete the revocation submission, please contact the helpdesk.";
                return false;
            }

        } else {
            this.MESSAGE = "There appears to be a problem with submitting the revocation request.\n"
                    + "This could be either due to networking problems you are having or \n"
                    + "problem in the e-Science CA Server. If your connection is already up but still \n"
                    + "unable to complete the revocation submission, please contact the helpdesk.";
            return false;
        }
    }

    private String _getFormattedMessage(Response response) {

        try {
            Document _document = response.getEntityAsDom().getDocument();
            // transform the Document into a String
            DOMSource domSource = new DOMSource(_document);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            //transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "ISO-8859-1");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            java.io.StringWriter sw = new java.io.StringWriter();
            StreamResult sr = new StreamResult(sw);
            transformer.transform(domSource, sr);
            String xml = sw.toString();

            return xml;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }

    }

    private Representation getRepresentation() {
        DomRepresentation representation = null;
        try {
            String id = new Long(cert_id).toString();
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("Revoke");
            d.appendChild(rootElement);

            Element idElement = d.createElement("id");
            Element reasonElement = d.createElement("reason");
            idElement.appendChild(d.createTextNode(id));
            reasonElement.appendChild(d.createTextNode(this.reason));

            rootElement.appendChild(idElement);
            rootElement.appendChild(reasonElement);

            d.normalizeDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return representation;
        }
    }
    
}
