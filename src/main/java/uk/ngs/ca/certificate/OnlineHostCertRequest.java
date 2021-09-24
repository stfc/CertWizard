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
package uk.ngs.ca.certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.*;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import static uk.ngs.ca.common.CertUtil.asciiToHex;
import static uk.ngs.ca.common.CertUtil.getPrivateExponent;

/**
 * Performs a new host certificate request with the server. An X509 certificate
 * and its corresponding private key must be provided in order to authenticate
 * the request with the PPPK protocol.
 *
 * @author David Meredith
 */
public class OnlineHostCertRequest {

    private static final Logger logger = LogManager.getLogger(OnlineHostCertRequest.class);
    private final String request_URL = SysProperty.getValue("uk.ngs.ca.request.bulkhost.reqid.url");
    private final String userAgent = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private final X509Certificate authCert;
    private final BigInteger exponent;
    private final String pkcs10;
    private final String pinHash;
    private final String email;

    /**
     * Create a new instance. After creation call {@link #doHostCSR() } when
     * ready to perform the CSR request with the server.
     *
     * @param authCert   Used to authenticate the CSR request with the server.
     * @param privateKey This must be the corresponding private key to
     *                   <tt>authCert</tt>.
     * @param pkcs10     A string encoded PKCS#10 certificate signing request.
     * @param pinHash    Hash of the pin number. To be manually checked by the RA.
     * @param email      Contact Email address that will be associated with this host
     *                   cert (e.g. the server administrator).
     */
    public OnlineHostCertRequest(X509Certificate authCert, PrivateKey privateKey, String pkcs10, String pinHash, String email) {
        this.pkcs10 = pkcs10;
        this.pinHash = pinHash;
        this.email = email;
        this.authCert = authCert;
        this.exponent = getPrivateExponent(privateKey);
    }

    /**
     * Call the server with the new Host CSR.
     *
     * @return A Pair object where <tt>Pair.first</tt> indicates if the CSR
     * request was successfully processed by the server (true for success
     * otherwise false). <tt>Pair.second</tt> provides a message returned by the
     * server (if any).
     */
    public Pair<Boolean, String> doHostCSR() {
        Response response = this.doInitialRequest();
        Pair<Boolean, String> result = this.respondToPPPKChallenge(response);
        return result;
    }

    /**
     * Send the initial request to the PPPK protected <tt>/CSRs</tt> resource.
     *
     * @return The response
     */
    private Response doInitialRequest() {
        Client client = RestletClient.getClient();

        Representation representation = this.getDomRepresentation();
        Request request = new Request(Method.POST, new Reference(request_URL), representation);

        Series<Header> headers = request.getHeaders();
        ;
        // Setup initial request headers: Add the 'PPPK' header and serial
        headers.set("PPPK", "this is pppk");
        // Send the required auth cert serial number header 
        headers.set("serial", this.authCert.getSerialNumber().toString());
        headers.set("LocalHost", ClientHostName.getHostName());

        // call clientinfo to change standard header
        ClientInfo info = new ClientInfo();
        info.setAgent(this.userAgent);
        request.setClientInfo(info);
        // Send reqeust to server 
        return client.handle(request);
    }

    /**
     * Process the initial response and complete the PPPK 401 challenge.
     *
     * @param response
     * @return A Pair object where <tt>Pair.first</tt> indicates if the CSR
     * request was processed by the server (true for success otherwise false).
     * <tt>Pair.second</tt> provides a message returned by the server (if any).
     */
    private Pair<Boolean, String> respondToPPPKChallenge(Response response) {
        Status status = response.getStatus();
        // We expect CLIENT_ERROR_UNAUTHORIZED as the response from the intial request. 
        if (!status.equals(Status.CLIENT_ERROR_UNAUTHORIZED)) {
            return Pair.create(false, "UNAUTHORIZED");
        }
        Series<Header> headers = response.getHeaders();
        Header realmP = headers.getFirst("realm");
        Header nonceP = headers.getFirst("nonce");
        Header keyidP = headers.getFirst("keyid");
        //Parameter opaqueP = headers.getFirst("opaque"); // TODO don't support yet 

        // Check that nonceP and keyidP are returned from the server, if not we can throw 
        // an unchecked exe as this is a coding error (albeit on the server). 
        if (nonceP == null || keyidP == null) {
            throw new IllegalStateException("Expected nonceP and keyidP headers from server");
        }

        String keyid = keyidP.getValue();
        int index = keyid.indexOf(".");
        String m = keyid.substring(0, index).toUpperCase();

        String nonce = nonceP.getValue() + ":" + new Date().getTime();
        nonce = nonce.toLowerCase();
        String c = asciiToHex(nonce);
        c = c.toUpperCase();
        BigInteger b_c = new BigInteger(c, 16);
        BigInteger b_m = new BigInteger(m, 16);
        BigInteger b_response = b_c.modPow(this.exponent, b_m);
        String _response = b_response.toString(16);

        Client client = RestletClient.getClient();

        Representation representation = this.getDomRepresentation();
        Request request = new Request(Method.POST, new Reference(request_URL), representation);

        Series<Header> newHeaders = request.getHeaders();
        newHeaders.set("PPPK", "this is pppk");
        newHeaders.set("LocalHost", ClientHostName.getHostName());
        newHeaders.set("keyid", keyid);
        newHeaders.set("realm", realmP.getValue());
        newHeaders.set("response", _response);
        newHeaders.set("serial", this.authCert.getSerialNumber().toString());

        ClientInfo info = new ClientInfo();
        info.setAgent(this.userAgent);
        request.setClientInfo(info);
        response = client.handle(request);

        if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
            return Pair.create(true, "SUCCESS_CREATED");   // 201 

        } else {
            String detailError = OnlineCertUtil.getServerErrorMessage(response);
            return Pair.create(false, detailError + " [" + response.getStatus() + "]");
        }
    }

    private Representation getDomRepresentation() {
        DomRepresentation representation;
        Document d;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            d = representation.getDocument();
        } catch (IOException ex) {
            throw new IllegalStateException("Coding error - can't create empty dom doc", ex);
        }

        Element rootElement = d.createElement("Bulk");
        d.appendChild(rootElement);

        Element csrElt = d.createElement("CSR");
        rootElement.appendChild(csrElt);

        Element eltName = d.createElement("Request");
        eltName.appendChild(d.createTextNode(this.pkcs10));
        csrElt.appendChild(eltName);

        eltName = d.createElement("PIN");
        eltName.appendChild(d.createTextNode(this.pinHash));
        csrElt.appendChild(eltName);

        eltName = d.createElement("Email");
        eltName.appendChild(d.createTextNode(this.email));
        csrElt.appendChild(eltName);

        String version = SysProperty.getValue("ngsca.certwizard.version");
        eltName = d.createElement("Version");
        eltName.appendChild(d.createTextNode(version));
        csrElt.appendChild(eltName);

        d.normalizeDocument();
        return representation;
    }
}
