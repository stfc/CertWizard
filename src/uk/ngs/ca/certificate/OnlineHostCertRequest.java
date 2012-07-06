package uk.ngs.ca.certificate;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.log4j.Logger;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.*;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.HashUtil;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Performs a new host certificate request with the server. An X509 certificate
 * and its corresponding private key must be provided in order to authenticate
 * the request with the PPPK protocol.
 *
 * @author David Meredith
 */
public class OnlineHostCertRequest {

    private static final Logger logger = Logger.getLogger(OnlineHostCertRequest.class);
    private final String request_URL = SysProperty.getValue("uk.ngs.ca.request.bulkhost.reqid.url");
    private final String userAgent = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private final X509Certificate authCert;
    private final String exponent;
    private final String pkcs10;
    private final String pin;
    private final String email;

    /**
     * Create a new instance. After creation call {@link #doHostCSR() } when
     * ready.
     *
     * @param authCert Used to authenticate the CSR request with the server.
     * @param privateKey This must be the corresponding private key to
     * <tt>authCert</tt>.
     * @param pin To be manually checked by the RA.
     * @param email Contact Email address that will be associated with this host
     * cert (e.g. the server administrator).
     * @param pkcs10 A string encoded PKCS#10 certificate signing request.
     */
    public OnlineHostCertRequest(X509Certificate authCert, PrivateKey privateKey, String pin, String email, String pkcs10) {
        this.pkcs10 = pkcs10;
        this.pin = pin;
        this.email = email;
        this.authCert = authCert;
        this.exponent = this.getPrivateExponent(privateKey);
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
        Client client = new Client(Protocol.HTTPS);
        // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 
        client.setConnectTimeout(SysProperty.getTimeoutMilliSecs());
        Representation representation = this.getDomRepresentation();
        Request request = new Request(Method.POST, new Reference(request_URL), representation);

        // Setup initial request headers: Add the 'PPPK' header and serial
        Form form = new Form();
        // Send the required PPPK header, its value is not signficant
        form.add("PPPK", "this is pppk");
        // Send the required auth cert serial number header 
        form.add("serial", this.authCert.getSerialNumber().toString());
        form.add("LocalHost", ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);
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
        if (!status.equals(Status.CLIENT_ERROR_UNAUTHORIZED)) {
            return Pair.create(false, "CLIENT_ERROR_UNAUTHORIZED");
        }
        Series<Parameter> headers = (Series) response.getAttributes().get("org.restlet.http.headers");
        Parameter realmP = headers.getFirst("realm");
        Parameter nonceP = headers.getFirst("nonce");
        Parameter keyidP = headers.getFirst("keyid");
        //Parameter opaqueP = headers.getFirst("opaque"); // TODO don't support yet 

        // Check that nonceP and keyidP are returned from the server, if not we can throw 
        // an unchecked exe as this is a coding error (albeit on the server). 
        if (nonceP == null || keyidP == null) {
            throw new IllegalStateException("Expected nonceP and keyidP headers from server");
        }

        String keyid = keyidP.getValue();
        int index = keyid.indexOf(".");
        String m = keyid.substring(0, index).toUpperCase();
        String q = this.exponent;

        String nonce = nonceP.getValue() + ":" + new Date().getTime();
        nonce = nonce.toLowerCase();
        String c = asciiToHex(nonce);
        c = c.toUpperCase();
        BigInteger b_c = new BigInteger(c, 16);
        BigInteger b_q = new BigInteger(q, 16);
        BigInteger b_m = new BigInteger(m, 16);
        BigInteger b_response = b_c.modPow(b_q, b_m);
        String _response = b_response.toString(16);

        Form form = new Form();
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", ClientHostName.getHostName());
        form.add("keyid", keyid);
        form.add("realm", realmP.getValue());
        form.add("response", _response);
        form.add("serial", this.authCert.getSerialNumber().toString());
        Client client = new Client(Protocol.HTTPS);
        client.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

        Representation representation = this.getDomRepresentation();
        Request request = new Request(Method.POST, new Reference(request_URL), representation);
        request.getAttributes().put("org.restlet.http.headers", form);
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(this.userAgent);
        request.setClientInfo(info);
        response = client.handle(request);

        if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
            return Pair.create(true, "SUCCESS_CREATED");   // 201 

        } else {
            String detailError = this.getServerErrorMessage(response);
            return Pair.create(false, detailError+" ["+response.getStatus()+"]");
        }
    }

    /**
     * Try and parse the server error response XML doc (if any) and return a
     * message.
     */
    private String getServerErrorMessage(Response response) {
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
                logger.warn("Could not parse server error response XML doc");
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

    private Representation getDomRepresentation() {
        DomRepresentation representation;
        Document d;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            d = representation.getDocument();
        } catch (IOException ex) {
            throw new IllegalStateException("Coding error - can't create empty dom doc");
        }

        Element rootElement = d.createElement("Bulk");
        d.appendChild(rootElement);

        Element csrElt = d.createElement("CSR");
        rootElement.appendChild(csrElt);

        Element eltName = d.createElement("Request");
        eltName.appendChild(d.createTextNode(this.pkcs10));
        csrElt.appendChild(eltName);

        eltName = d.createElement("PIN");
        eltName.appendChild(d.createTextNode(HashUtil.getHash(this.pin)));
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

    private String asciiToHex(String ascii) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < ascii.length(); i++) {
            hex.append(Integer.toHexString(ascii.charAt(i)));
        }
        return hex.toString();
    }

    private String getPrivateExponent(PrivateKey _privateKey) {
        // this seems hacky, there must be a way to to retrieve the value via API
        int index = _privateKey.toString().indexOf("private exponent:");
        index = index + 17;
        String subString = _privateKey.toString().substring(index);
        index = subString.indexOf("\n");
        subString = subString.substring(0, index);
        subString = subString.trim();
        return subString;
    }
}
