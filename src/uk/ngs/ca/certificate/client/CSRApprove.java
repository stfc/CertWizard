/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.client;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

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

/**
 *
 * @author xw75
 */
public class CSRApprove {

    private long cert_id = -1;
    private long req_id = -1;
    private String APPROVEURL = SysProperty.getValue("uk.ngs.ca.request.csr.status.url");
    private String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private PrivateKey privateKey;
    
    public CSRApprove(PrivateKey privateKey, long cert_id, long req_id) {
        this.privateKey = privateKey;
        this.cert_id = cert_id;
        this.req_id = req_id;
    }
    
    public boolean isSuccessApprove() {
        String approveURL = this.APPROVEURL + "/" + this.req_id + "/status";

        Client client = new Client(Protocol.HTTPS);
        Request request = new Request(Method.PUT, new Reference(approveURL), getRepresentation());
        Form form = new Form();
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", ClientHostName.getHostName());
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
                request = new Request(Method.PUT, new Reference(approveURL), getRepresentation());
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
                request = new Request(Method.PUT, new Reference(approveURL), getRepresentation());
                request.getAttributes().put("org.restlet.http.headers", _form);
                org.restlet.data.ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(this.USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

                org.restlet.util.Series<org.restlet.data.Parameter> _headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
            }

            if (response.getStatus().equals(Status.SUCCESS_NO_CONTENT)) {
                //200
                return true;
            } else {
                return false;
            }
        } else {
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
            
    private Representation getRepresentation() {
        DomRepresentation representation = null;
        try {
            String id = new Long(this.cert_id).toString();
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("CSR");
            d.appendChild(rootElement);

            Element raElement = d.createElement("RA");                        
            Element idElement = d.createElement("id");
            idElement.appendChild(d.createTextNode(id));
            
            raElement.appendChild(idElement);
            rootElement.appendChild(raElement);

            d.normalizeDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return representation;
        }
    }

}
