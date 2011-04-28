/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.client;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import java.util.Properties;
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
import org.restlet.Client;
import org.restlet.data.Protocol;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.EncryptUtil;

/**
 *
 * @author xw75
 */
public class RAContact {

    private String encodedPublicKey = null;

    private String CONTACTURL = SysProperty.getValue("uk.ngs.ca.ra.contact.url");
    private String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private PrivateKey privateKey;
    
    private String from = null;
    private String to = null;
    private String subject = null;
    private String content = null;

    private String MESSAGE = null;

    public RAContact(PrivateKey privateKey, String encodedPublicKeyString, String from, String to, String subject, String content) {
        this.privateKey = privateKey;
        this.encodedPublicKey = encodedPublicKeyString;
        this.from = from;
        this.to = to;
        this.subject = subject;
        this.content = content;
    }

    public String getMessage(){
        return this.MESSAGE;
    }

    private Representation getRepresentation() {
        DomRepresentation representation = null;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("CA");
            d.appendChild(rootElement);

            Element raElement = d.createElement("RA");
            Element fromElement = d.createElement("from");
            Element toElement = d.createElement("to");
            Element subjectElement = d.createElement("subject");
            Element contentElement = d.createElement("content");

            fromElement.appendChild(d.createTextNode(this.from));
            toElement.appendChild(d.createTextNode(this.to));
            subjectElement.appendChild(d.createTextNode(this.subject));
            contentElement.appendChild(d.createTextNode(this.content));

            raElement.appendChild(fromElement);
            raElement.appendChild(toElement);
            raElement.appendChild(subjectElement);
            raElement.appendChild(contentElement);
            rootElement.appendChild(raElement);

            d.normalizeDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return representation;
        }
    }

    public boolean isSuccessContact() {
        String contactURL = this.CONTACTURL;
        String keyid = EncryptUtil.getKeyid( this.encodedPublicKey );
        Client client = new Client(Protocol.HTTPS);
        Request request = new Request(Method.POST, new Reference(contactURL), getRepresentation() );
        Form form = new Form();
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", ClientHostName.getHostName());
        form.add("keyid", keyid);
        request.getAttributes().put("org.restlet.http.headers", form);
//by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(this.USERAGENT);
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
                String q = getPrivateExponent(this.privateKey);

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
                request = new Request(Method.POST, new Reference(contactURL), getRepresentation());
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
                request = new Request(Method.POST, new Reference(contactURL), getRepresentation());
                request.getAttributes().put("org.restlet.http.headers", _form);
                org.restlet.data.ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(this.USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

                org.restlet.util.Series<org.restlet.data.Parameter> _headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
            }
            if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
                //200
                this.MESSAGE = "The email has been send out successfully.";
                return true;
            }else if (response.getStatus().equals(Status.SUCCESS_ACCEPTED)) {
                //202
                this.MESSAGE = "Server failed to send the email. Please contact the helpdesk";
                return false;
            } else if (response.getStatus().equals(Status.CLIENT_ERROR_NOT_FOUND)) {
                //404
                this.MESSAGE = "there is no such service. Please contact the helpdesk";
                return false;
            } else if (response.getStatus().equals(Status.CLIENT_ERROR_FORBIDDEN)) {
                //403
                this.MESSAGE = "failed authentication. Please contact the helpdesk";
                return false;
            } else if (response.getStatus().equals(Status.CLIENT_ERROR_METHOD_NOT_ALLOWED)) {
                //405
                this.MESSAGE = "Server does not support POST. ";
                return false;
            } else {
                this.MESSAGE = "There appears to be a problem with sending out the email.\n"
                        + "This could be either due to networking problems you are having or \n"
                        + "problem in the e-Science CA Server. If your connection is already up but still \n"
                        + "unable to send the email to the user, please contact the helpdesk.";
                return false;
            }
        } else {
            this.MESSAGE = "There appears to be a problem with sending out the email.\n"
                    + "This could be either due to networking problems you are having or \n"
                    + "problem in the e-Science CA Server. If your connection is already up but still \n"
                    + "unable to send the email to the user, please contact the helpdesk.";
            return false;
        }
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

    private String asciiToHex(String ascii) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < ascii.length(); i++) {
            hex.append(Integer.toHexString(ascii.charAt(i)));
        }
        return hex.toString();
    }

}
