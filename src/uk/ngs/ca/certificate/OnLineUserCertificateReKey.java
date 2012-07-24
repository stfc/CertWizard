/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.*;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import uk.ngs.ca.certificate.management.ClientKeyStore;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.HashUtil;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * This class renews certificate under online.
 * @author xw75 (Xiao Wang)
 */
public class OnLineUserCertificateReKey {

    public static String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    public static String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    public String SIG_ALG = SysProperty.getValue("ngsca.cert.signature.algorithm");
    X509Certificate renewalCert = null;
    private final ClientKeyStore clientKeyStore;
    //private final ClientKeyStoreCaServiceWrapper caKeyStoreModel; 
    String ERRORMESSAGE = "";
    String DETAILERRORMESSAGE = "";
    private Document DOCUMENT = null;
    //private PKCS10CertificationRequest PKCS10REQUEST = null;
    private String newCsrAlias = null;

    public OnLineUserCertificateReKey(ClientKeyStoreCaServiceWrapper caKeyStoreModel, 
            String newCsrAlias, X509Certificate renewalCert)  {
        //this.caKeyStoreModel = caKeyStoreModel; 
        this.clientKeyStore = caKeyStoreModel.getClientKeyStore(); 
        this.newCsrAlias = newCsrAlias;
        this.renewalCert = renewalCert;
    }


    /**
     * Checks if selected certificate is valid. Only valid certificate can be renewed.
     * @return true if valid, otherwise false.
     */
    public boolean isValidReKey() {
        if ((!SystemStatus.getInstance().getIsOnline()) || (this.renewalCert == null)) {
            return false;
        }
        try {
            this.renewalCert.checkValidity();
            PublicKey publicKey = this.renewalCert.getPublicKey();
            PrivateKey privateKey = this.clientKeyStore.getPrivateKey(publicKey);
            if (!this.clientKeyStore.isExistPublicKey(publicKey)) {
                return false;
            } else if (privateKey == null) {
                return false;
            } else {
                return true;
            }
        } catch(KeyStoreException ex){
            this.ERRORMESSAGE = "A problem has occurred reading the keyStore: "+ex.getMessage();
            return false; 
        } 
        catch (CertificateExpiredException ce) {
            this.ERRORMESSAGE = "Selected certificate has expired.";
            return false;
        } catch (CertificateNotYetValidException cve) {
            this.ERRORMESSAGE = "Selected certificate is not a valid certificate.";
            return false;
        }
    }

    /**
     * Gets error message. It is null if isValidReKey is true.
     * @return error message.
     */
    public String getErrorMessage() {
        return this.ERRORMESSAGE;
    }

    /**
     * Gets error message in detail information.
     * @return detailed error message.
     */
    public String getDetailErrorMessage() {
        /*if (this.DOCUMENT == null) {
            return "";
        }
        try {
            // transform the Document into a String
            DOMSource domSource = new DOMSource(this.DOCUMENT);
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
            return ep.getMessage();
        }*/
        return this.DETAILERRORMESSAGE; 
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

    /*private BigInteger hex2BigInteger(String s) {
        String digits = "0123456789ABCDEF";
        s = s.toUpperCase();
        BigInteger b = new BigInteger("0");
        BigInteger my_b = new BigInteger(new Integer(16).toString());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = digits.indexOf(c);
            BigInteger _b = new BigInteger(new Integer(d).toString());
            b = b.multiply(my_b);
            b = b.add(_b);
        }
        return b;
    }*/

    public boolean doPosts() {
        Client client = new Client(Protocol.HTTPS);
        client.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

        // First attempt to connect. Add the 'PPPK' header and provide the encoded 
        // public keyid in the request message payload/body. 
        // We subsequently expect a 401 response challenge. 
        Representation representation = getRepresentation();
        
        Request request = new Request(Method.POST, new Reference(CSRURL), representation);
        request = setupHeaders(request);
        Response response = client.handle(request);
        Status _status = response.getStatus();

        // 401 response challenge was issued by the server - we will do a 
        // second post and this time include the required PPPK headers to authenticate.
        if (_status.equals(Status.CLIENT_ERROR_UNAUTHORIZED)) {
            org.restlet.util.Series<org.restlet.data.Parameter> headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
            Parameter _realmP = headers.getFirst("realm");
            Parameter _nonceP = headers.getFirst("nonce");
            Parameter _keyidP = headers.getFirst("keyid");
            Parameter _opaqueP = headers.getFirst("opaque");
            //we will do the response action from here.
            if (_opaqueP == null) {

                PrivateKey _privateKey = this.clientKeyStore.getPrivateKey(this.renewalCert.getPublicKey());

                String _keyid = _keyidP.getValue();
                int index = _keyid.indexOf(".");
                String m = _keyid.substring(0, index).toUpperCase();
                String q = getPrivateExponent(_privateKey);

                String _nonce = _nonceP.getValue() + ":" + new Date().getTime();
                _nonce = _nonce.toLowerCase();
                String c = asciiToHex(_nonce);
                c = c.toUpperCase();
                BigInteger b_c = new BigInteger(c, 16);
                BigInteger b_q = new BigInteger(q, 16);
                BigInteger b_m = new BigInteger(m, 16);
                BigInteger b_response = b_c.modPow(b_q, b_m);
                String _response = b_response.toString(16);

                Form form = new Form();
                form.add("PPPK", "this is pppk");
                form.add("LocalHost", ClientHostName.getHostName());
                form.add("keyid", _keyid);
                form.add("realm", _realmP.getValue());
                form.add("response", _response);
                client = new Client(Protocol.HTTPS);
                client.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

                //please note you have to call getRepresentation() again, otherwise 
                // it will be null. Why? - maybe restlet nullifies it after the first post?
                representation = getRepresentation();
                request = new Request(Method.POST, new Reference(CSRURL), representation);
                request.getAttributes().put("org.restlet.http.headers", form);
                org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
                info.setAgent(USERAGENT);
                request.setClientInfo(info);
                response = client.handle(request);

            } else {
                //we will do cookie thing from here
                Form form = new Form();
                form.add("PPPK", "this is pppk");
                form.add("LocalHost", ClientHostName.getHostName());
                form.add("opaque", _opaqueP.getValue());

                client = new Client(Protocol.HTTPS);
                //please note you have to call getRepresentation() again, otherwise 
                // it will be null. Why? - maybe restlet nullifies it after the first post?
                representation = getRepresentation();
                request = new Request(Method.POST, new Reference(CSRURL), representation);
                request.getAttributes().put("org.restlet.http.headers", form);
                org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
                info.setAgent(USERAGENT);
                request.setClientInfo(info);
                response = client.handle(request);
                org.restlet.util.Series<org.restlet.data.Parameter> _headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");

            }

            if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
                //201
                return true;

            } else {
                // Set defaults 
                this.ERRORMESSAGE = "Error";
                this.DETAILERRORMESSAGE = "Unknown Error";
                
                // try and parse the server response XML 
                try {
                    String xmlResponse = response.getEntityAsText();
                    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                    InputSource source = new InputSource(new StringReader(xmlResponse));
                    this.DOCUMENT = factory.newDocumentBuilder().parse(source);
                } catch (ParserConfigurationException ex) {
                    ex.printStackTrace();
                } catch(SAXException ex){
                    ex.printStackTrace();
                } catch(IOException ex){
                    ex.printStackTrace();
                }

                if (response.getStatus().equals(Status.SUCCESS_ACCEPTED)) {
                    //202
                    if (this.DOCUMENT != null) {
                        NodeList allTextNodes = this.DOCUMENT.getElementsByTagName("text");
                        if (allTextNodes != null) {
                            Node node_minor_text = allTextNodes.item(1);
                            if (node_minor_text != null) {
                                this.DETAILERRORMESSAGE = node_minor_text.getTextContent();
                            }
                        }
                    }
                    return false;

                } else if (response.getStatus().equals(Status.CLIENT_ERROR_NOT_FOUND)) {
                    //404
                    this.DETAILERRORMESSAGE = "There is no such service. Please check system configure file.";
                    return false;
                } else if (response.getStatus().equals(Status.CLIENT_ERROR_FORBIDDEN)) {
                    //403
                    this.DETAILERRORMESSAGE = "Failed authentication. Please contact the helpdesk";
                    return false;
                } else if (response.getStatus().equals(Status.CLIENT_ERROR_METHOD_NOT_ALLOWED)) {
                    //405
                    this.DETAILERRORMESSAGE = "Server does not support POST.";
                    return false;
                } else {
                    this.DETAILERRORMESSAGE = "There appears to be a problem with submitting the renewal request.\n"
                            + "This could be either due to networking problems you are having or \n"
                            + "problem in the e-Science CA Server. If your connection is already up but still \n"
                            + "unable to complete the renewal submission, please contact the helpdesk.";
                    return false;
                }
            }
        } else {
            this.DETAILERRORMESSAGE = "There appears to be a problem with submitting the renewal request.\n"
                    + "This could be either due to networking problems you are having or \n"
                    + "problem in the e-Science CA Server. If your connection is already up but still \n"
                    + "unable to complete the renewal submission, please contact the helpdesk.";
            return false;
        }

    }

  
    /**
     * setup header. CSRResource will check if there is PPPK. if there is PPPK,
     * then the CSR is the rekey request, otherwise the CSR is the new certificate request.
     *
     * @param request restlet request
     * @return restlrt request
     */
    private Request setupHeaders(Request request) {
        Form form = new Form();
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);

//by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);
        return request;
    }

    private Representation getRepresentation() {
        DomRepresentation representation;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("CSR");
            d.appendChild(rootElement);

            Element eltName = d.createElement("Request");
            eltName.appendChild(d.createTextNode(getCSR_AddToKeyStoreNoRestore()));
            rootElement.appendChild(eltName);

            eltName = d.createElement("PIN");
            eltName.appendChild(d.createTextNode(HashUtil.getHash(getRandomString())));
            rootElement.appendChild(eltName);

            eltName = d.createElement("Email");
            eltName.appendChild(d.createTextNode(getEmail()));
            rootElement.appendChild(eltName);

            // We include the keyid string as the <PublicKey> element so that 
            // the server can then issue a 401 response challenge for this pubkey. 
            RSAPublicKey _publicKey = (RSAPublicKey) this.renewalCert.getPublicKey();
            String modulusString = _publicKey.getModulus().toString(16);
            String exponentString = _publicKey.getPublicExponent().toString(16);
            String keyString = modulusString + "." + exponentString;
            eltName = d.createElement("PublicKey");
            eltName.appendChild(d.createTextNode(keyString));
            rootElement.appendChild(eltName);

            String _version = SysProperty.getValue("ngsca.certwizard.version");
            eltName = d.createElement("Version");
            eltName.appendChild(d.createTextNode(_version));
            rootElement.appendChild(eltName);

            d.normalizeDocument();           
            
            /*TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();
            StringWriter buffer = new StringWriter();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.transform(new DOMSource(d),
            new StreamResult(buffer));
            String str = buffer.toString();
            System.out.println(str);*/
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
        return representation;
    }

    private String _retrieveDataFromDN(String dn, String data) {
        int index = dn.indexOf(data);
        index = index + data.length();
        String result = dn.substring(index);
        int _index = result.indexOf(",");
        if (_index != -1) {
            result = result.substring(0, _index);
        }
        result = result.trim();

        return result;
    }

    private X509Name getDN() {
        String dn = this.renewalCert.getSubjectDN().getName();

        String C = _retrieveDataFromDN(dn, "C=");
        String O = _retrieveDataFromDN(dn, "O=");
        String OU = _retrieveDataFromDN(dn, "OU=");
        String L = _retrieveDataFromDN(dn, "L=");
        String CN = _retrieveDataFromDN(dn, "CN=");

//        String name = "C=" + C + ", O=" + O + ", OU=" + OU + ", L=" + L + ", CN=" + CN;
        String name = "CN=" + CN + ", L=" + L + ", OU=" + OU + ", O=" + O + ", C=" + C;
        return new X509Name(name);
        //we need to reverse back, otherwise renew doesn't work. It is strange.
        //       return new X509Name(renewalCert.getSubjectDN().getName());
    }

//    public String getAlias(){
//        return this.newCsrAlias;
//    }

    private String getCSR_AddToKeyStoreNoRestore() {
        try {
            PKCS10CertificationRequest PKCS10REQUEST;
            String dn = this.renewalCert.getSubjectDN().getName();
            String OU = _retrieveDataFromDN(dn, "OU=");
            String L = _retrieveDataFromDN(dn, "L=");
            String CN = _retrieveDataFromDN(dn, "CN=");
            String alias = this.clientKeyStore.createNewSelfSignedCert(newCsrAlias, OU, L, CN);
            //this.clientKeyStore.reStore();
            PublicKey _publicKey = this.clientKeyStore.getPublicKey(alias);
            PrivateKey _privateKey = this.clientKeyStore.getPrivateKey(alias);
            PKCS10REQUEST = new PKCS10CertificationRequest(this.SIG_ALG, new X500Principal(getDN().toString()), _publicKey, new DERSet(), _privateKey);

            StringWriter writer = new StringWriter();
            PEMWriter pemWrite = new PEMWriter(writer);
            pemWrite.writeObject(PKCS10REQUEST);
            pemWrite.close();
            return writer.toString();

        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }

    }

    private String getEmail() {
        try {
            //but in here we are retrieveing email from Extension....
            Collection col = this.renewalCert.getSubjectAlternativeNames();
            if (!(col == null)) {
                Iterator iterator = col.iterator();
                while (iterator.hasNext()) {
                    java.util.List list = (java.util.List) iterator.next();
                    return (String) list.get(1);
                }
                return null;
            } else {
                return null;
            }
        } catch (CertificateParsingException ce) {
            ce.printStackTrace();
            return null;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    private String getRandomString() {
        Random random = new Random();
        return Long.toString(Math.abs(random.nextLong()), 36);
    }

    
    
      /**
     * Calls CA server to renew the certificate
     * @return true if successful, otherwise false.
     */
    /*public boolean doLaunchneedtomove() {
        String requestID = null;

        Client c = new Client(Protocol.HTTPS);
        c.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

        Request request = new Request(Method.POST, new Reference(CSRURL), getRepresentation());

        request = setupHeaders(request);

        Response _response = c.handle(request);

        if (_response.getStatus().equals(_response.getStatus().SUCCESS_CREATED)) {
            //201
            return true;

        } else if (_response.getStatus().equals(_response.getStatus().SUCCESS_ACCEPTED)) {
            //202
            try {
                DETAILERRORMESSAGE = _response.getEntityAsText();
                DOCUMENT = new DomRepresentation(_response.getEntity()).getDocument();//_response.getEntityAsDom().getDocument();
                ERRORMESSAGE = "Server sends back error message. Please check it out.";
            } catch (Exception ep) {
                ep.printStackTrace();
            } finally {
                return false;
            }

        } else if (_response.getStatus().equals(_response.getStatus().CLIENT_ERROR_NOT_FOUND)) {
            //404

            ERRORMESSAGE = "there is no such service. Please check system configure file.";
            try {
                DETAILERRORMESSAGE = _response.getEntityAsText();
                DOCUMENT = new DomRepresentation(_response.getEntity()).getDocument();//_response.getEntityAsDom().getDocument();
            } catch (Exception ep) {
                ep.printStackTrace();
            } finally {
                return false;
            }
        } else if (_response.getStatus().equals(_response.getStatus().CLIENT_ERROR_FORBIDDEN)) {
            //403
            ERRORMESSAGE = "failed authentication. Please check out PPPK";
            try {
                DETAILERRORMESSAGE = _response.getEntityAsText();
                DOCUMENT = new DomRepresentation(_response.getEntity()).getDocument();//_response.getEntityAsDom().getDocument();
            } catch (Exception ep) {
                ep.printStackTrace();
            } finally {
                return false;
            }
        } else if (_response.getStatus().equals(_response.getStatus().CLIENT_ERROR_METHOD_NOT_ALLOWED)) {
            //405
            ERRORMESSAGE = "Server does not support POST.";
            try {
                DETAILERRORMESSAGE = _response.getEntityAsText();
                DOCUMENT = new DomRepresentation(_response.getEntity()).getDocument();//_response.getEntityAsDom().getDocument();
            } catch (Exception ep) {
                ep.printStackTrace();
            } finally {
                return false;
            }
        } else {
            ERRORMESSAGE = "There appears to be a problem with processing the Certficate request.\n"
                    + "This could be either due to networking problems you are having or \n"
                    + "problem in the e-Science CA Server. If your connection is already up but still \n"
                    + "unable to complete the revocation submission, please contact the helpdesk.";
            return false;
        }

    }*/

}
