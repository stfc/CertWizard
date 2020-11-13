package uk.ngs.ca.certificate;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Locale;
import java.util.Random;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.*;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.ngs.ca.common.CertUtil;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.HashUtil;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Create a PKCS#10 CSR renewal for the given Host or User cert and send it to
 * the server. Both the renewal cert and its corresponding private key must be
 * provided in order to authenticate the request using the PPPK protocol. The
 * renewal cert is not modified.
 *
 * @author Xiao Wang
 * @author David Meredith (some modifications)
 */
public class OnlineCertRenewRequest {

    public static final String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    public static final String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    //private static final String SIG_ALG = SysProperty.getValue("ngsca.cert.signature.algorithm");

    private final String email;
    private final X509Certificate authAndRenewCert;
    private final PrivateKey authPrivateKey;
    private final String pkcs10String;
    private final String attrOU, attrL, attrCN;

    /**
     * Create a new instance. After creation call {@link #doRenewal() }. No
     * validity checks are performed on the given certificate, it is up to the
     * calling client to test for expiry and yet to be valid.
     *
     * @param authAndRenewCertP The certificate that is to be renewed and used
     * for PPPK authentication. The DN of this certificate is extracted and used
     * to build the PKCS#10 DN.
     * @param authPrivateKeyP Certificate private key (used for PPPK
     * authentication).
     * @param csrKeyPair The key pair used to create the PKCS#10 request.
     * @param emailAddressP Used to specify the email element in the CSR XML
     * document and is the email value that will be associated with the renewed
     * certificate.
     */
    public OnlineCertRenewRequest(X509Certificate authAndRenewCertP, PrivateKey authPrivateKeyP,
            KeyPair csrKeyPair, String emailAddressP) {

        this.authAndRenewCert = authAndRenewCertP;
        this.email = emailAddressP;
        this.authPrivateKey = authPrivateKeyP;
        if (this.authPrivateKey == null) {
            throw new NullPointerException("toRenewPrivateKey is null");
        }

        // Get the DN string from the X509Certificate. 
        // Use authCert.getSubjectX500Principal().toString() to ensure EMAILADDRESS is listed in DN string 
        // (this is not portable: authCert.getSubjectDN().getName() - is denigrated)
        // (this does not provide email attribute in x500: authCert.getSubjectX500Principal().getName()) 
        String dn = this.authAndRenewCert.getSubjectX500Principal().toString();
        dn = CertUtil.prepareDNforOpenCA(dn, true);  // will want to ask the user here.....
        this.attrCN = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.CN);
        this.attrOU = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.OU);
        this.attrL = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.L);

        // Create the PKCS#10 string. 
        CertificateRequestCreator csrCreator = new CertificateRequestCreator(dn, this.email);
        this.pkcs10String = csrCreator.createCertificateRequest(csrKeyPair.getPrivate(), csrKeyPair.getPublic());
    }

    public String getOU() {
        return this.attrOU;
    }

    public String getL() {
        return this.attrL;
    }

    public String getCN() {
        return this.attrCN;
    }

    /**
     * Call the server with the renewal request.
     *
     * @return A Pair object where <tt>Pair.first</tt> indicates if the CSR
     * renew request was successfully processed by the server (true for success
     * otherwise false). <tt>Pair.second</tt> provides a message returned by the
     * server (if any).
     */
    public Pair<Boolean, String> doRenewal() {
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

        // First attempt to connect. Add the 'PPPK' header and provide the encoded 
        // public keyid in the request message payload/body. 
        // We subsequently expect a 401 response challenge. 
        Representation representation = getDomRepresentation();

        Request request = new Request(Method.POST, new Reference(CSRURL), representation);

        Series<Header> headers = request.getHeaders();
        headers.set("PPPK", "this is pppk");
        headers.set("LocalHost", ClientHostName.getHostName());

        //by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);
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
        Header _realmP = headers.getFirst("realm");
        Header _nonceP = headers.getFirst("nonce");
        Header _keyidP = headers.getFirst("keyid");
        Header _opaqueP = headers.getFirst("opaque");
        //we will do the response action from here.
        if (_opaqueP == null) {
            String _keyid = _keyidP.getValue();
            int index = _keyid.indexOf(".");
            String m = _keyid.substring(0, index).toUpperCase(Locale.ENGLISH);
            String q = getPrivateExponent(this.authPrivateKey);

            String _nonce = _nonceP.getValue() + ":" + new Date().getTime();
            _nonce = _nonce.toLowerCase(Locale.ENGLISH);
            String c = asciiToHex(_nonce);
            c = c.toUpperCase(Locale.ENGLISH);
            BigInteger b_c = new BigInteger(c, 16);
            BigInteger b_q = new BigInteger(q, 16);
            BigInteger b_m = new BigInteger(m, 16);
            BigInteger b_response = b_c.modPow(b_q, b_m);
            String _response = b_response.toString(16);

            Client client = RestletClient.getClient();

            //please note you have to call getRepresentation() again, otherwise 
            // it will be null. Why? - maybe restlet nullifies it after the first post?
            Representation representation = getDomRepresentation();
            Request request = new Request(Method.POST, new Reference(CSRURL), representation);
            Series<Header> newHeaders = request.getHeaders();
            newHeaders.set("PPPK", "this is pppk");
            newHeaders.set("LocalHost", ClientHostName.getHostName());
            newHeaders.set("keyid", _keyid);
            newHeaders.set("realm", _realmP.getValue());
            newHeaders.set("response", _response);

            ClientInfo info = new ClientInfo();
            info.setAgent(USERAGENT);
            request.setClientInfo(info);
            response = client.handle(request);

        } else {
            //we will do cookie thing from here

            Client client = RestletClient.getClient();
            //please note you have to call getRepresentation() again, otherwise 
            // it will be null. Why? - maybe restlet nullifies it after the first post?
            Representation representation = getDomRepresentation();
            Request request = new Request(Method.POST, new Reference(CSRURL), representation);
            Series<Header> newHeaders = request.getHeaders();
            newHeaders.set("PPPK", "this is pppk");
            newHeaders.set("LocalHost", ClientHostName.getHostName());
            newHeaders.set("opaque", _opaqueP.getValue());

            ClientInfo info = new ClientInfo();
            info.setAgent(USERAGENT);
            request.setClientInfo(info);
            response = client.handle(request);
            //org.restlet.util.Series<org.restlet.data.Parameter> _headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
        }

        if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
            return Pair.create(true, "SUCCESS_CREATED");   // 201 

        } else {
            String detailError = OnlineCertUtil.getServerErrorMessage(response);
            return Pair.create(false, detailError + " [" + response.getStatus() + "]");
        }
    }

    private String asciiToHex(String ascii) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < ascii.length(); i++) {
            hex.append(Integer.toHexString(ascii.charAt(i)));
        }
        return hex.toString();
    }

    // hmm, this looks hacky 
    private String getPrivateExponent(PrivateKey _privateKey) {
        int index = _privateKey.toString().indexOf("private exponent:");
        index = index + 17;
        String subString = _privateKey.toString().substring(index);
        index = subString.indexOf("\n");
        subString = subString.substring(0, index);
        subString = subString.trim();
        return subString;
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
        Element rootElement = d.createElement("CSR");
        d.appendChild(rootElement);

        Element eltName = d.createElement("Request");
        eltName.appendChild(d.createTextNode(this.pkcs10String));
        rootElement.appendChild(eltName);

        eltName = d.createElement("PIN");
        Random random = new Random();
        String pin = Long.toString(Math.abs(random.nextLong()), 36);
        eltName.appendChild(d.createTextNode(HashUtil.getHash(pin)));
        rootElement.appendChild(eltName);

        eltName = d.createElement("Email");
        eltName.appendChild(d.createTextNode(this.email)); // was getEmail()
        rootElement.appendChild(eltName);

        // We include the keyid string as the <PublicKey> element so that 
        // the server can then issue a 401 response challenge for this pubkey. 
        RSAPublicKey authRSAPublicKey = (RSAPublicKey) this.authAndRenewCert.getPublicKey();
        String modulusString = authRSAPublicKey.getModulus().toString(16);
        String exponentString = authRSAPublicKey.getPublicExponent().toString(16);
        String keyString = modulusString + "." + exponentString;
        eltName = d.createElement("PublicKey");
        eltName.appendChild(d.createTextNode(keyString));
        rootElement.appendChild(eltName);

        String _version = SysProperty.getValue("ngsca.certwizard.version");
        eltName = d.createElement("Version");
        eltName.appendChild(d.createTextNode(_version));
        rootElement.appendChild(eltName);

        d.normalizeDocument();

        /*
         * TransformerFactory transFactory = TransformerFactory.newInstance();
         * Transformer transformer = transFactory.newTransformer(); StringWriter
         * buffer = new StringWriter();
         * transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
         * "yes"); transformer.transform(new DOMSource(d), new
         * StreamResult(buffer)); String str = buffer.toString();
         * System.out.println(str);
         */
        return representation;
    }
}
