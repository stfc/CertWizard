/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.certificate.client;

import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.*;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.ngs.ca.certificate.OnlineCertUtil;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import static uk.ngs.ca.common.CertUtil.asciiToHex;
import static uk.ngs.ca.common.CertUtil.getPrivateExponent;

/**
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
                BigInteger q = getPrivateExponent(privateKey);

                String _nonce = _nonceP.getValue() + ":" + new Date().getTime();
                _nonce = _nonce.toLowerCase();
                String c = asciiToHex(_nonce);
                c = c.toUpperCase();

                BigInteger b_c = new BigInteger(c, 16);
                BigInteger b_m = new BigInteger(m, 16);
                BigInteger b_response = b_c.modPow(q, b_m);
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

            } else {
                //we will do cookie thing from here

                client = RestletClient.getClient();
                //please note you have to call getRepresentation() again, otherwise it will be null. Why???
                request = new Request(Method.POST, new Reference(REVOKEURL), getRepresentation());
                Series<Header> _headers = request.getHeaders();
                _headers.set("PPPK", "this is pppk");
                _headers.set("LocalHost", ClientHostName.getHostName());
                _headers.set("opaque", _opaqueP.getValue());
                ClientInfo _info = new ClientInfo();
                _info.setAgent(USERAGENT);
                request.setClientInfo(_info);
            }
            response = client.handle(request);

            if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
                return true;   // 201
            } else {
                this.MESSAGE = OnlineCertUtil.getServerErrorMessage(response);
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
