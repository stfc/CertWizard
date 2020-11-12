/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.ClientInfo;
import org.restlet.data.Header;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.data.Status;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75 (Xiao Wang)
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
        Client client = RestletClient.getClient();

        Request request = new Request(Method.POST, new Reference(REVOKEURL), getRepresentation());

        Series<Header> headerz = request.getHeaders();
        headerz.set("LocalHost", ClientHostName.getHostName());
        headerz.set("PPPK", "this is pppk");

        ClientInfo info = new ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);

        Response response = client.handle(request);

        Status _status = response.getStatus();
        //we will do second post
        if (_status.equals(Status.CLIENT_ERROR_UNAUTHORIZED)) {
            Series<Header> headers = response.getHeaders();
            Header _realmP = headers.getFirst("realm");
            Header _nonceP = headers.getFirst("nonce");
            Header _keyidP = headers.getFirst("keyid");
            Header _opaqueP = headers.getFirst("opaque");

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

                client = RestletClient.getClient();
                request = new Request(Method.POST, new Reference(REVOKEURL), getRepresentation());
                Series<Header> _headers = request.getHeaders();
                _headers.set("PPPK", "this is pppk");
                _headers.set("LocalHost", ClientHostName.getHostName());
                _headers.set("keyid", _keyid);
                _headers.set("realm", _realmP.getValue());
                _headers.set("response", _response);
                ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

            } else {
                //we will do cookie thing from here

                client = RestletClient.getClient();
                //please note you have to call getRepresentation() again, otherwise it will be null. Why???
                request = new Request(Method.POST, new Reference(REVOKEURL), getRepresentation());
                Series _headers = request.getHeaders();
                _headers.set("PPPK", "this is pppk");
                _headers.set("LocalHost", ClientHostName.getHostName());
                _headers.set("opaque", _opaqueP.getValue());
                ClientInfo _info = new ClientInfo();
                _info.setAgent(USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

                //Series<Header> _headers = response.getHeaders();
            }

            if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
                //201
                this.MESSAGE = "The certificate revocation request has been submitted.";
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

    private Representation getRepresentation() {
        DomRepresentation representation = null;
        try {
            String id = Long.toString(cert_id);
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
