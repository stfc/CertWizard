/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.management;

import java.security.PublicKey;
import java.security.PrivateKey;

import java.io.FileNotFoundException;

import java.io.FileWriter;
import java.io.BufferedWriter;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import javax.xml.parsers.DocumentBuilder;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Method;
import org.restlet.resource.DomRepresentation;
import org.restlet.resource.Representation;


import javax.xml.parsers.DocumentBuilderFactory;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import java.security.cert.X509Certificate;

import java.io.FileOutputStream;

import java.util.Enumeration;
import java.util.Vector;

import java.util.Date;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.stream.StreamResult;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;


import org.apache.log4j.Logger;

import java.util.Properties;

import java.util.Observable;

import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.CertificateOwner;
import uk.ngs.ca.certificate.client.CertificateEndDate;
import uk.ngs.ca.certificate.client.CertificateStartDate;
import uk.ngs.ca.certificate.client.CertificateStatus;
import uk.ngs.ca.certificate.client.CertificateEmail;
import uk.ngs.ca.certificate.client.CSREmail;
import uk.ngs.ca.certificate.client.CSRStatus;
import uk.ngs.ca.certificate.client.CSROwner;
import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.info.ExpiredReKey;
import uk.ngs.ca.common.ClientCertKeyStore;
import uk.ngs.ca.common.ClientKeyStore;

import uk.ngs.ca.certificate.OnLineUserCertificateReKey;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;

/**
 *
 * @author xw75
 */
public class OnLineCertificateInfoBak extends Observable {


    public static String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    public static String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private char[] PASSPHRASE = null;
    static final Logger myLogger = Logger.getLogger(OffLineCertificateInfo.class);
    static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private Properties properties = new Properties();
    private String keyStoreFile = null;
    private KeyStore keyStore = null;
    private KeyStore certKeyStore = null;
    private String CERTIFICATE = "Certificate";
    private String DN = "DN";
    private String ERRORMESSAGE = "";
    private String[] certificateIDs = null;
    private String[] requestIDs = null;
    private String NotAppliable = "N/A";
private Document DOCUMENT = null;
private String[] AllDNs = null;

    public OnLineCertificateInfoBak(char[] passphrase) {
        PASSPHRASE = passphrase;
        ClientKeyStore _keyStore = new ClientKeyStore(passphrase);
        ClientCertKeyStore _certKeyStore = new ClientCertKeyStore(passphrase);
        init(passphrase);
        if (isExistKeyStore()) {
            if (!isExistKeyPair(passphrase)) {
                removeCertKeyStore();
                removeCSRFile();
            } else {
                isExistCertKeyStore();
                submitRequest();
//System.out.println("before setupcertandcsr......");
                setupCertandCSR( passphrase );
//System.out.println("before updatecertkeystore.....");
                updateCertKeyStore();
//System.out.println("certID length = " + certificateIDs.length + ", csrID length = " + requestIDs.length);
            }
        } else {
            removeCertKeyStore();
            removeCSRFile();
        }
    }

    public void notifyObserver(){
            //notify MainWindow
            setChanged();
            notifyObservers( this );
    }

    public OnLineUserCertificateReKey getOnLineUserCertificateReKey(){
        return new OnLineUserCertificateReKey( PASSPHRASE );
    }

    public ClientKeyStore getClientKeyStore(){
        return new ClientKeyStore( PASSPHRASE );
    }

    public String[] getAllDNs() {
        if( AllDNs != null ){
            return AllDNs;
        }
        String[] allDNs = null;
        if (certificateIDs == null) {
            if (requestIDs == null) {
                return null;
            } else {
                allDNs = new String[requestIDs.length];
                for (int i = 0; i < requestIDs.length; i++) {
                    CSROwner csrOwner = new CSROwner(requestIDs[i]);
                    allDNs[i] = csrOwner.getOwner();
                }
            }
        } else {
            if (requestIDs == null) {
                allDNs = new String[certificateIDs.length];
                for (int i = 0; i < certificateIDs.length; i++) {
                    CertificateOwner certOwner = new CertificateOwner(certificateIDs[i]);
                    allDNs[i] = certOwner.getOwner();
                }
            } else {
                int length = certificateIDs.length + requestIDs.length;
                allDNs = new String[length];
                for (int i = 0; i < certificateIDs.length; i++) {
                    CertificateOwner certOwner = new CertificateOwner(certificateIDs[i]);
                    allDNs[i] = certOwner.getOwner();
                }
                for (int i = 0; i < requestIDs.length; i++) {
                    CSROwner csrOwner = new CSROwner(requestIDs[i]);
                    allDNs[i + certificateIDs.length] = csrOwner.getOwner();
                }
            }
        }
        AllDNs = allDNs;
        return allDNs;
    }

    public boolean remove( int index ){
        int _index = index + 1;

        if (_index <= certificateIDs.length) {
            X509Certificate _certificate = getCertificate( index );
            PublicKey _publicKey = _certificate.getPublicKey();
            String _status = getStatus( index );
            ClientKeyStore _keyStore = new ClientKeyStore(PASSPHRASE);

            PrivateKey _privateKey = _keyStore.getPrivateKey(_publicKey);
            boolean b1 = _keyStore.removeKey(_privateKey);
            boolean b2 = true;
            if( _status.equals("VALID")){
                ClientCertKeyStore _certKeyStore = new ClientCertKeyStore(PASSPHRASE);
                String _alias = _certKeyStore.getAlias(_publicKey);
                b2 = _certKeyStore.removeEntry(_alias);
            }

            if( b1 & b2 ){
                return true;
            }else{
                return false;
            }
        } else if ((_index > certificateIDs.length) && (_index <= (certificateIDs.length + requestIDs.length))) {
            String id = requestIDs[index - certificateIDs.length];
            uk.ngs.ca.certificate.client.CSRCSR csrCSR = new uk.ngs.ca.certificate.client.CSRCSR( id );
            PublicKey _publicKey = csrCSR.getPublicKey();
            String _status = getStatus( index );
            ClientKeyStore _keyStore = new ClientKeyStore(PASSPHRASE);
//            ClientCertKeyStore _certKeyStore = new ClientCertKeyStore(PASSPHRASE);

            PrivateKey _privateKey = _keyStore.getPrivateKey(_publicKey);
            boolean b1 = _keyStore.removeKey(_privateKey);

            boolean b2 = true;
            if( _status.equals("VALID")){
                ClientCertKeyStore _certKeyStore = new ClientCertKeyStore(PASSPHRASE);
                String _alias = _certKeyStore.getAlias(_publicKey);
                b2 = _certKeyStore.removeEntry(_alias);
            }

//            String _alias = _certKeyStore.getAlias(_publicKey);
//            boolean b2 = _certKeyStore.removeEntry(_alias);
            if( b1 & b2 ){
                return true;
            }else{
                return false;
            }

 //System.out.println("csr ID pub key = " + _publicKey);
        }else{
            return false;
        }

//        return false;
    }

    public String getDN(int index) {
        if (AllDNs == null) {
            return null;
        } else {
            return AllDNs[index];
        }
    }

    public String getDNtoDisplay(int index) {
        String dn = getDN(index);
        String status = getStatus(index);
        String endDate = getFormatEndDate(index);
        int _index = dn.indexOf("CN=");
        int length = dn.length();
        dn = dn.substring(_index, length);
        _index = dn.indexOf(",");
        if (_index != -1) {
            dn = dn.substring(0, _index);
        }
//        dn = dn.substring(0, _index);
        dn = dn.trim();
        dn = dn + "-" + endDate + "(" + status + ")";
        return dn;
    }

    public String getEmail(int index) {
        int _index = index + 1;
        if (_index <= certificateIDs.length) {
            CertificateEmail certEmail = new CertificateEmail(certificateIDs[index]);
            return certEmail.getEmail();
        } else if ((_index > certificateIDs.length) && (_index <= (certificateIDs.length + requestIDs.length))) {
            String id = requestIDs[index - certificateIDs.length];
            CSREmail csrEmail = new CSREmail(id);
            return csrEmail.getEmail();
        } else {
            return NotAppliable;
        }

    }

    public String getStatus(int index) {
//System.out.println("begimn top status....");
        int _index = index + 1;
        if (_index <= certificateIDs.length) {
            CertificateStatus certStatus = new CertificateStatus(certificateIDs[index]);
            return certStatus.getStatus();
        } else if ((_index > certificateIDs.length) && (_index <= (certificateIDs.length + requestIDs.length))) {
            String id = requestIDs[index - certificateIDs.length];
            CSRStatus csrStatus = new CSRStatus(id);
            String status = csrStatus.getStatus();
            if (status.equals("NEW")) {
//                return "CSR: waiting for the approval.";
                return "NEW";
            } else if (status.equals("RENEW")) {
//                return "CSR: waiting for the renewal approval.";
                return "RENEW";
            } else if (status.equals("APPROVED")) {
//                return "CSR: approved  by RA, waiting for the signing.";
                return "APPROVED";
            } else if (status.equals("ARCHIVED")) {
//                return "CSR: signed.";
                return "ARCHIVED";
            } else if (status.equals("DELETED")) {
//                return "CSR: deleted.";
                return "DELETED";
            } else if (status.equals("VALID")) {
//                return "Certificate: valid.";
                return "VALID";
            } else if (status.equals("REVOKED")) {
//                return "Certificate: revoked";
                return "REVOKED";
            } else if (status.equals("SUSPENDED")) {
//                return "Certificate: suspending";
                return "SUSPENDED";
            } else {
                return "Unknown.";
            }
//            return csrStatus.getStatus();
        } else {
            return NotAppliable;
        }
    }

    public String getFormatStartDate(int index) {
        Date startDate = getStartDate(index);
        if (startDate == null) {
            return NotAppliable;
        } else {
            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String result = formatter.format(startDate);
            return result;
        }
    }

    public Date getStartDate(int index) {
        int _index = index + 1;
        if (_index <= certificateIDs.length) {
            CertificateStartDate certStartDate = new CertificateStartDate(certificateIDs[index]);
            return certStartDate.getStartDate();
        } else {
            return null;
        }
    }

    public String getFormatEndDate(int index) {
        Date endDate = getEndDate(index);
        if (endDate == null) {
            return NotAppliable;
        } else {
            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String result = formatter.format(endDate);
            return result;
        }
    }

    public Date getEndDate(int index) {
        int _index = index + 1;
        if (_index <= certificateIDs.length) {
            CertificateEndDate certEndDate = new CertificateEndDate(certificateIDs[index]);
            return certEndDate.getEndDate();
        } else {
            return null;
        }
    }

    public String getLifeDays(int index) {
        int _index = index + 1;
        if (_index <= certificateIDs.length) {
            CertificateDownload certDownload = new CertificateDownload(certificateIDs[index]);
            X509Certificate cert = certDownload.getCertificate();
/*
            long startMillis = cert.getNotBefore().getTime();
            long endMillis = cert.getNotAfter().getTime();
            if (endMillis < startMillis) {
                return NotAppliable;
            }
            long diffDays = (endMillis - startMillis) / (24 * 60 * 60 * 1000);
*/
            long currentMillis = new Date().getTime();
            long endMillis = cert.getNotAfter().getTime();
            if (endMillis < currentMillis) {
                return NotAppliable;
            }
            long diffDays = (endMillis - currentMillis) / (24 * 60 * 60 * 1000);
            //the live days would include the extra rekey days.
            ExpiredReKey reKey = new ExpiredReKey();
            int reKeyDays = reKey.getMaxReKeyTime();

            diffDays = diffDays + reKeyDays;

            return new Long(diffDays).toString();

        } else {
            return NotAppliable;
        }

    }

    public String getRenewDate(int index) {

        Date endDate = getEndDate(index);
        if (endDate == null) {
            return NotAppliable;
        } else {
            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String result = formatter.format(endDate);
            return result;
        }
    }

    public X509Certificate getCertificate(int index) {
        int _index = index + 1;
        if (_index <= certificateIDs.length) {
            CertificateDownload certDownload = new CertificateDownload(certificateIDs[index]);
            X509Certificate cert = certDownload.getCertificate();
            return cert;
        } else {
            return null;
        }
    }

    public void updateCertKeyStore() {
        String[] certIDs = certificateIDs;

        // delete all entries from certkeystore.
        try{
            Enumeration aliases = certKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                certKeyStore.deleteEntry(alias);
            }
        }catch( Exception ep ){
            ep.printStackTrace();
        }

//System.out.println("length of certIDs = " + certIDs.length);
        for (int i = 0; i < certIDs.length; i++) {
            CertificateDownload certDownload = new CertificateDownload(certIDs[i]);
            X509Certificate cert = certDownload.getCertificate();
            CertificateStatus my_status = new CertificateStatus( certIDs[i]);
            String _status = my_status.getStatus();
//System.out.println( "_status = " + _status + ", certID length = " + certIDs.length );
            if (cert == null) {
//System.out.println("length of certIDs = " + certIDs.length + ", but there is no cert in the CA server");
//System.out.println("i = " + i + ", but cert == null");
                break;
            } else if( !_status.equals("VALID") ) {
//System.out.println("status = VALID......");
//System.out.println("i = " + i + ", but cert != VALID");
                continue;
            } else {
//System.out.println("else, status = " + _status);
//System.out.println("i = " + i + ", but cert == VALID");
                PublicKey publicKey = cert.getPublicKey();
                Vector _vector = _getCertFromKeyStore();
                for (int j = 0; j < _vector.size(); j++) {
                   X509Certificate _cert = (X509Certificate) _vector.elementAt(j);
                   PublicKey _publicKey = _cert.getPublicKey();
                   if (publicKey.equals(_publicKey)) {
                       try{
                           PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStore.getCertificateAlias(_cert), PASSPHRASE);
                           X509Certificate[] chain = new X509Certificate[1];
                           chain[ 0 ] = cert;
                           long _alias = new Date().getTime();
                           String my_alias = new Long(_alias).toString();
                           certKeyStore.setKeyEntry(my_alias, privateKey, PASSPHRASE, chain);
                       }catch( Exception ep ){
                           ep.printStackTrace();
                       }
//                      _restoreCertKeyStore();
                   }
                }
                _restoreNewCertKeyStore();

/*
                try {
                    Vector vector = _getCertFromCertKeyStore();
                    boolean _isExist = false;
                    if ( (vector != null) && (vector.size() != 0) ) {
                        for (int j = 0; j < vector.size(); j++) {
                            X509Certificate _cert = (X509Certificate) vector.elementAt(j);
                            if (cert.equals(_cert)) {
                                _isExist = true;
                            }
                        }
                    }else{
                        _isExist = false;
                    }
                    //add up a new entry if the cert is not existed in the cacertkeystore.pkcs12
                        if (!_isExist) {
                            Vector _vector = _getCertFromKeyStore();
                            for (int j = 0; j < _vector.size(); j++) {
                                X509Certificate _cert = (X509Certificate) _vector.elementAt(j);
                                PublicKey _publicKey = _cert.getPublicKey();
                                if (publicKey.equals(_publicKey)) {
                                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStore.getCertificateAlias(_cert), PASSPHRASE);
                                    X509Certificate[] chain = new X509Certificate[1];
                                    chain[ 0 ] = cert;
                                    long _alias = new Date().getTime();
                                    String my_alias = new Long(_alias).toString();
                                    certKeyStore.setKeyEntry(my_alias, privateKey, PASSPHRASE, chain);
                                    _restoreCertKeyStore();
                                }
                            }
                        }
                } catch (Exception ep) {
                    ep.printStackTrace();
                }
*/
            }
        }

    }


        private boolean _restoreNewCertKeyStore() {
        try {
String fileName = SysProperty.getValue("ngsca.cert.keystore.file");
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + fileName;

            File f = new File(homePath);
            //delete old one and create a new one.
            f.delete();

            FileOutputStream fos = new FileOutputStream(f);
            certKeyStore.store(fos, PASSPHRASE);
            fos.close();
            return true;
        } catch (FileNotFoundException fe) {
            fe.printStackTrace();
            myLogger.error("[OnLineCertificateInfo] failed to get pkcs file: " + fe.getMessage());
            return false;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnLineCertificateInfo] failed to get keystore file: " + ke.getMessage());
            return false;
        } catch (IOException ie) {
            ie.printStackTrace();
            myLogger.error("[OnLineCertificateInfo] failed to access pkcs file: " + ie.getMessage());
            return false;
        } catch (NoSuchAlgorithmException ne) {
            ne.printStackTrace();
            myLogger.error("[OnLineCertificateInfo] no such algorithm: " + ne.getMessage());
            return false;
        } catch (CertificateException ce) {
            ce.printStackTrace();
            myLogger.error("[OnLineCertificateInfo] certificate error: " + ce.getMessage());
            return false;
        }

    }

    private Vector _getCertFromKeyStore() {
        try {
            Enumeration aliases = keyStore.aliases();
            Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    vector.addElement(keyStore.getCertificate(alias));
                }
            }
            return vector;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    private Vector _getCertFromCertKeyStore() {
        try {
            Enumeration aliases = certKeyStore.aliases();
            Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (certKeyStore.isKeyEntry(alias)) {
                    vector.addElement(certKeyStore.getCertificate(alias));
                }
            }
            return vector;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    private void setupCertandCSR( char[] passphrase ){
        String[] certIDs = null;
        String[] reqIDs = null;

        Vector certVector = new Vector();
        Vector reqVector = new Vector();
boolean uselessKey = true;
        try {
            Enumeration aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();

                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                PublicKey publicKey = cert.getPublicKey();

                ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey( publicKey );
                boolean isExist = resourcesPublicKey.isExist();
                Document doc = resourcesPublicKey.getDocument();

//                String encodedPubKey = EncryptUtil.getEncodedPublicKey(publicKey);
//                Document doc = _getPubKeyResource(encodedPubKey);
//System.out.println("doc = " + doc.toString());
                XPath xpath = XPathFactory.newInstance().newXPath();
                XPathExpression expr = xpath.compile("/resources/resource/certificates/certificate/id");
//System.out.println("alias = " + alias + ", subject = " + cert.getSubjectDN().getName());
                Object result = expr.evaluate(doc, XPathConstants.NODESET);
                NodeList nodeList = (NodeList) result;
/*
                if( nodeList.getLength() == 0 ){
                    uselessKey = true;
                }
                for (int i = 0; i < nodeList.getLength(); i++) {
                    certVector.addElement( nodeList.item(i).getTextContent() );
                }
*/
                if( nodeList.getLength() == 0 ){
//System.out.println("no length of nodelist");
                    uselessKey = true;
                }else{
                    for (int i = 0; i < nodeList.getLength(); i++) {
//System.out.println("length = " + nodeList.getLength());
                        certVector.addElement( nodeList.item(i).getTextContent() );
                    }
                }

                XPath _xpath = XPathFactory.newInstance().newXPath();
                XPathExpression _expr = _xpath.compile("/resources/resource/CSRs/CSR");
                Object _result = _expr.evaluate(doc, XPathConstants.NODESET);
                NodeList _nodeList = (NodeList) _result;
/*
                if( ( _nodeList.getLength() == 0 ) && ( uselessKey ) ){
System.out.println("running _updateKeyStore to remove cert.");
                   _updateKeyStore( alias );
                }
                for (int i = 0; i < _nodeList.getLength(); i++) {
                    Node _csrNode = _nodeList.item(i);
                    if (_csrNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element _csrElement = (Element) _csrNode;
                        NodeList _idList = _csrElement.getElementsByTagName("id");
                        Element _idElement = (Element) _idList.item(0);
                        String _id = _idElement.getChildNodes().item(0).getTextContent();

                        NodeList _statusList = _csrElement.getElementsByTagName("status");
                        Element _statusElement = (Element) _statusList.item(0);
                        String _status = _statusElement.getChildNodes().item(0).getTextContent();
                        if (_status.equals("NEW") || _status.equals("RENEW") || _status.equals("APPROVED")) {

                            reqVector.addElement(_id);
                        }
                    }
                }
 */
                if( ( _nodeList.getLength() == 0 ) && ( uselessKey ) ){
//System.out.println("running _updateKeyStore to remove cert.");
                   _updateKeyStore( alias );
                }else{
                   for (int i = 0; i < _nodeList.getLength(); i++) {
                    Node _csrNode = _nodeList.item(i);
                    if (_csrNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element _csrElement = (Element) _csrNode;
                        NodeList _idList = _csrElement.getElementsByTagName("id");
                        Element _idElement = (Element) _idList.item(0);
                        String _id = _idElement.getChildNodes().item(0).getTextContent();

                        NodeList _statusList = _csrElement.getElementsByTagName("status");
                        Element _statusElement = (Element) _statusList.item(0);
                        String _status = _statusElement.getChildNodes().item(0).getTextContent();
                        if (_status.equals("NEW") || _status.equals("RENEW") || _status.equals("APPROVED")) {

                            reqVector.addElement(_id);
                        }
                    }
                   }
                }


                reqIDs = new String[reqVector.size()];
                for (int i = 0; i < reqVector.size(); i++) {
                    reqIDs[i] = (String) reqVector.elementAt(i);
                }
            }
            certIDs = new String[certVector.size()];
            for( int i = 0; i < certIDs.length; i++ ){
                certIDs[ i ] = (String)certVector.elementAt(i);
            }

certificateIDs = certIDs;
                requestIDs = reqIDs;
        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    private boolean _updateKeyStore( String alias ){
        try{
        keyStore.deleteEntry(alias);
        File f = new File(keyStoreFile);
            FileOutputStream fos = new FileOutputStream(f);
            keyStore.store(fos, PASSPHRASE);
            fos.close();
        return true;
        }catch( Exception kse ){
            kse.printStackTrace();
            return false;
        }
    }

/*
    private Document _getPubKeyResource(String publicKey) {
        Document _document = null;
        try {
            String resourceURL = SysProperty.getValue("uk.ngs.ca.request.resource.publickey");
            resourceURL = resourceURL + "/" + publicKey;
//            Client c = new Client(Protocol.HTTP);
            Client c = new Client(Protocol.HTTPS);

            Request request = new Request(Method.GET, new Reference(resourceURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
//            form.add("PPPK", "this is pppk");
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
//System.out.println("response = " + response.getEntity().getText());
            _document = response.getEntityAsDom().getDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return _document;
        }
    }
*/

    private String submitRequest() {
        String fileName = SysProperty.getValue("ngsca.cert.xml.file");
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + fileName;

        try {
            File file = new File(homePath);
            if (!file.exists()) {
                return "";
            }
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(file);
            doc.getDocumentElement().normalize();
            NodeList nodeList = doc.getElementsByTagName(CERTIFICATE);
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node certNode = nodeList.item(i);

                if (certNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element certElement = (Element) certNode;
                    NodeList csrList = certElement.getElementsByTagName("CSR");
                    Element csrElement = (Element) csrList.item(0);
                    String csr = csrElement.getChildNodes().item(0).getNodeValue();

                    NodeList emailList = certElement.getElementsByTagName("Email");
                    Element emailElement = (Element) emailList.item(0);
                    String email = emailElement.getChildNodes().item(0).getNodeValue();

                    NodeList pinList = certElement.getElementsByTagName("PIN");
                    Element pinElement = (Element) pinList.item(0);
                    String pin = pinElement.getChildNodes().item(0).getNodeValue();

                    Representation representation = getRepresentation(csr, email, pin);

                    Response response = doCSRRequest(representation);
//DOCUMENT = response.getEntityAsDom().getDocument();
                    if (response.getStatus().equals(response.getStatus().SUCCESS_CREATED)) {
                        updateCSRFile( csr, doc );
//                        removeCSRFromCSRFile(csr, doc);
                    } else if (response.getStatus().equals(response.getStatus().SUCCESS_ACCEPTED)) {
DOCUMENT = response.getEntityAsDom().getDocument();
//update csr xml file once there is any error from server.
updateCSRFile( csr, doc );
                        ERRORMESSAGE = response.getEntityAsDom().getText();
                    }
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            ERRORMESSAGE = ep.getMessage();
        } finally {
            return ERRORMESSAGE;
        }
    }

    public String getErrorMessage(){

        if( DOCUMENT == null ){
            return "";
        }
        try {
            // transform the Document into a String
            DOMSource domSource = new DOMSource(DOCUMENT);
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
            myLogger.error("[OnLineCertificateInfo] failed to save xml file: " + ep.toString());
            return ep.getMessage();
        }

    }

    private Response doCSRRequest(Representation representation) {
//        Client c = new Client(Protocol.HTTP);
        Client c = new Client(Protocol.HTTPS);
        Request request = new Request(Method.POST, new Reference(CSRURL), representation);

        Form form = new Form();
//        form.add("PPPK", "this is pppk");
//        form.add("LocalHost", getHostName());
        form.add("LocalHost", uk.ngs.ca.common.ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);

//by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);

        Response _response = c.handle(request);
        return _response;
    }

    private Document removeCSRFromCSRFile(String csr, Document doc) {

        NodeList list = doc.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);
                NodeList list1 = e1.getElementsByTagName("CSR");
                Element e2 = (Element) list1.item(0);
                if (list1.item(0).getFirstChild().getNodeValue().equals(csr)) {
                    Element certElement = (Element) e2.getParentNode();
                    certElement.getParentNode().removeChild(certElement);

                    doc.normalize();
                }
            }
        }
        return doc;
    }

    private boolean updateCSRFile( String csr, Document doc ) {
        //to save the updated document in xml file.
        try {

            Document _doc = removeCSRFromCSRFile( csr, doc );
             // transform the Document into a String
            DOMSource domSource = new DOMSource(_doc);
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

            String fileName = SysProperty.getValue("ngsca.cert.xml.file");
        String xmlFileName = System.getProperty("user.home");
        xmlFileName = xmlFileName + System.getProperty("file.separator") + ".ca";
        xmlFileName = xmlFileName + System.getProperty("file.separator") + fileName;

            FileWriter fstream = new FileWriter(xmlFileName);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(xml);
            out.close();

//document.normalizeDocument();

myLogger.debug("[OnLineCertificateInfo] save xml file successfully");
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OnLineCertificateInfo] failed to save xml file: " + ep.toString());
            return false;
        }
    }

    private Representation getRepresentation(String csr, String email, String pin) {
        DomRepresentation representation;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("CSR");
            d.appendChild(rootElement);

            Element eltName = d.createElement("Request");
            eltName.appendChild(d.createTextNode(csr));
            rootElement.appendChild(eltName);

            eltName = d.createElement("PIN");
            eltName.appendChild(d.createTextNode(pin));
            rootElement.appendChild(eltName);

            eltName = d.createElement("Email");
            eltName.appendChild(d.createTextNode(email));
            rootElement.appendChild(eltName);

            d.normalizeDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
        return representation;
    }

    private boolean removeCertKeyStore() {
        if (!isExistCertKeyStore()) {
            return true;
        } else {
            String fileName = SysProperty.getValue("ngsca.cert.keystore.file");
            String homePath = System.getProperty("user.home");
            homePath = homePath + System.getProperty("file.separator") + ".ca";
            homePath = homePath + System.getProperty("file.separator") + fileName;
            return (new File(homePath).delete());
        }
    }

    private boolean removeCSRFile() {
        if (!isExistCSRFile()) {
            return true;
        } else {
            String fileName = SysProperty.getValue("ngsca.cert.xml.file");
            String homePath = System.getProperty("user.home");
            homePath = homePath + System.getProperty("file.separator") + ".ca";
            homePath = homePath + System.getProperty("file.separator") + fileName;
            return (new File(homePath).delete());
        }
    }

    private boolean isExistKeyStore() {
        String fileName = SysProperty.getValue("ngsca.key.keystore.file");
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
            return false;
        } else {
            homePath = homePath + System.getProperty("file.separator") + fileName;
            if (!new File(homePath).exists()) {
                return false;
            } else {
                if (new File(homePath).length() == 0) {
                    return false;
                }
                return true;
            }
        }
    }

    private boolean isExistKeyPair(char[] passphrase) {
        boolean isExist = false;
//        myLogger.debug("[OnlineCertificateManager] get keystore ...");
        String key = "ngsca.key.keystore.file";
        String value = properties.getProperty(key);
        if (value == null) {
            myLogger.error("[OnlineCertificateInfo] could not find out the value of " + key + " in your property file.");
        }
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + value;
        keyStoreFile = homePath;
        try {
            FileInputStream fis = new FileInputStream(keyStoreFile);
            keyStore.load(fis, passphrase);
            fis.close();
            int size = keyStore.size();
            if (size > 0) {
                isExist = true;
            }
        } catch (IOException iep) {
            iep.printStackTrace();
            myLogger.error("[OnlineCertificateInfo] failed to read keystore file from: " + keyStoreFile + ". with the message: " + iep.getMessage());
        } catch (NoSuchAlgorithmException nae) {
            nae.printStackTrace();
            myLogger.error("[OnlineCertificateInfo] algorithm error: " + nae.getMessage());
        } catch (CertificateException ce) {
            ce.printStackTrace();
            myLogger.error("[OnlineCertificateInfo] certificate error: " + ce.getMessage());
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateInfo] keyStore error: " + ke.getMessage());
        } finally {
            return isExist;
        }
    }

    private boolean isExistCertKeyStore() {
        String fileName = SysProperty.getValue("ngsca.cert.keystore.file");
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
            return false;
        } else {
            homePath = homePath + System.getProperty("file.separator") + fileName;
            if (!new File(homePath).exists()) {
                return false;
            } else {
                if (new File(homePath).length() == 0) {
                    return false;
                } else {
                    try {
                        FileInputStream fis = new FileInputStream(homePath);
                        certKeyStore.load(fis, PASSPHRASE);
                        fis.close();
                        return true;
                    } catch (Exception ep) {
                        ep.printStackTrace();
                        return false;
                    }
                }

            }
        }
    }

    private boolean isExistCSRFile() {
        String fileName = SysProperty.getValue("ngsca.cert.xml.file");
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
            return false;
        } else {
            homePath = homePath + System.getProperty("file.separator") + fileName;
            if (!new File(homePath).exists()) {
                return false;
            } else {
                if (new File(homePath).length() == 0) {
                    return false;
                }
                return true;
            }
        }
    }

    private void init(char[] passphrase) {
        myLogger.debug("[OnlineCertificateInfo] init...");
        try {
//            keyStore = KeyStore.getInstance("PKCS12", "BC");
            keyStore = PKCS12KeyStoreUnlimited.getInstance();
//            certKeyStore = KeyStore.getInstance("PKCS12", "BC");
            certKeyStore = PKCS12KeyStoreUnlimited.getInstance();
            InputStream input = SysProperty.class.getResourceAsStream(PROP_FILE);
            properties.load(input);
            input.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] Property file is failed to load.");
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] failed to create a keyStore: " + ke.getMessage());
        } catch (NoSuchProviderException ne) {
            ne.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] failed to create a keystore without suitable provider: " + ne.getMessage());
        }
    }

/*
    public static void main(String[] args) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        OnLineCertificateInfo t = new OnLineCertificateInfo("mypassword".toCharArray());
        String[] dns = t.getAllDNs();
        System.out.println("dns = " + dns.length);
        System.out.println("certID length = " + t.certificateIDs.length + ", error message = " + t.getErrorMessage());
//for( int i = 0; i <t.certificateIDs.length; i++ ){
//    System.out.println("IDs = " + t.certificateIDs[i]);
//}

//        for (int i = 0; i < dns.length; i++) {
//        System.out.println("dn [ " + i + " ] = " + t.getDN(i));
//        System.out.println("dn to display [ " + i + " ] = " + t.getDNtoDisplay(i));
//        System.out.println("email [ " + i + " ] = " + t.getEmail(i));
//        System.out.println("formated end date [ " + i + " ] = " + t.getFormatEndDate(i));
//        System.out.println("formatted start date [ " + i + " ] = " + t.getFormatStartDate(i));
//        System.out.println("life days [ " + i + " ] = " + t.getLifeDays(i));
//        System.out.println("renew date [ " + i + " ] = " + t.getRenewDate(i));
//        System.out.println("status [ " + i + " ] = " + t.getStatus(i));
//        }

//        t.updateCertKeyStore();
//ClientCertKeyStore _certKeyStore = new ClientCertKeyStore( "mypassword".toCharArray() );
    }
 */



}
