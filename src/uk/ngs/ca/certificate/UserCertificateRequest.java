/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.Response;
import org.restlet.Request;
import org.restlet.data.Method;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.IOException;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;

import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.certificate.management.CertificateRequestManager;
import uk.ngs.ca.common.HashUtil;
import uk.ngs.ca.common.ClientKeyStore;

/**
 *
 * @author xw75
 */
public class UserCertificateRequest {

    public static String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    public static String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private CertificateRequestManager certRequestManager;
    private CertificateRequestCreator certRequestCreator;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String CSRSTRING;
    private String REQUESTID;
    private String CN = "testme four--";
    private String OU = "CLRC";
    private String L = "DL";
    private String EMAIL = "xiao.wang@stfc.ac.uk";
    private String PIN1 = "123456789";
    private String PIN2 = "123456789";

    private char[] PASSPHRASE;

    private String ERRORMESSAGE = null;


    public UserCertificateRequest( char[] passphrase ) {
        PASSPHRASE = passphrase;

        certRequestManager = new CertificateRequestManager(PASSPHRASE);

        ClientKeyStore my_keyStore = ClientKeyStore.getClientkeyStore(passphrase);
        String a = my_keyStore.createNewKeyPair();
        privateKey = my_keyStore.getPrivateKey(a);
        publicKey = my_keyStore.getPublicKey(a);

    }

    public void setCN( String cn ){
        CN = cn;
    }

    public void setOU( String ou ){
        OU = ou;
    }

    public void setL( String l ){
        L = l;
    }

    public void setEmail( String email ){
        EMAIL = email;
    }

    public void setPIN1( String pin1 ){
        PIN1 = pin1;
    }

    public void setPIN2( String pin2 ){
        PIN2 = pin2;
    }

    public void upDateXMLStore( ) {
        certRequestManager = new CertificateRequestManager(PASSPHRASE);
        String dn = certRequestCreator.getDN().toString();

        certRequestManager.addReqID(dn, REQUESTID);
        certRequestManager.addCSR(dn, CSRSTRING);

        certRequestManager.addStatus(dn, "Submitted");

        certRequestManager.addEmail(dn, EMAIL);
        certRequestManager.addPIN(dn, HashUtil.getHash(PIN1));

        certRequestManager.saveFile();

    }

    public String getRequestID() {

        return REQUESTID;
    }

    public String getErrorMessage(){
        return ERRORMESSAGE;
    }

    public boolean doLaunch() {

        Client c = new Client(Protocol.HTTPS);
        Request request = new Request(Method.POST, new Reference(CSRURL), getRepresentation());

        request = setupHeaders(request);

        Response _response = c.handle(request);

        if (_response.getStatus().equals(_response.getStatus().SUCCESS_CREATED)) {

            try {

                //retrieve request id from response header.
                REQUESTID = _response.getLocationRef().getLastSegment();

                org.restlet.util.Series<org.restlet.data.Parameter> headers =
                        (org.restlet.util.Series) _response.getAttributes().get("org.restlet.http.headers");

                } catch (Exception ep) {
                ep.printStackTrace();
                return false;
            }

        }else if(_response.getStatus().equals(_response.getStatus().SUCCESS_ACCEPTED)){
            try{
                ERRORMESSAGE = _response.getEntityAsText();
                return false;
            }catch(Exception ep){
                ep.printStackTrace();
            }

        }
        return true;

    }

    // retrieve value of request ID from XML style response. XPath may be called here.
    private String _getRequestID(String value) {
        String result = null;
        try {
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.xml.sax.InputSource is = new org.xml.sax.InputSource();
            is.setCharacterStream(new java.io.StringReader(value));

            Document doc = db.parse(is);

            javax.xml.xpath.XPath xpath = javax.xml.xpath.XPathFactory.newInstance().newXPath();
            javax.xml.xpath.XPathExpression expr = xpath.compile("/CSR/ID[1]/text()");
            result = (String) expr.evaluate(doc, javax.xml.xpath.XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        }
        return result;
    }

    private Request setupHeaders(Request request) {
        Form form = new Form();

        form.add("LocalHost", uk.ngs.ca.common.ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);

//by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);
        return request;
    }

    private String getCSR() {
        certRequestCreator = new CertificateRequestCreator();
        certRequestCreator.setCN(CN);
        certRequestCreator.setEmail(EMAIL);
        certRequestCreator.setRA(OU, L);
        String hashPIN1 = HashUtil.getHash(PIN1);
        String hashPIN2 = HashUtil.getHash(PIN2);
        certRequestCreator.setPIN1(hashPIN1);
        certRequestCreator.setPIN2(hashPIN2);
        certRequestCreator.createDN(false);
        CSRSTRING = certRequestCreator.createCertificateRequest(privateKey, publicKey);

        return CSRSTRING;
    }

    private Representation getRepresentation() {
        DomRepresentation representation;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("CSR");
            d.appendChild(rootElement);

            Element eltName = d.createElement("Request");
            eltName.appendChild(d.createTextNode(getCSR()));
            rootElement.appendChild(eltName);

            eltName = d.createElement("PIN");
            eltName.appendChild(d.createTextNode(HashUtil.getHash(PIN1)));
            rootElement.appendChild(eltName);

            eltName = d.createElement("Email");
            eltName.appendChild(d.createTextNode(EMAIL));
            rootElement.appendChild(eltName);

            d.normalizeDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
        return representation;
    }

}

