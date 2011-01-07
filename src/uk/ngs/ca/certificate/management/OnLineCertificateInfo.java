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
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.common.ClientCertKeyStore;
import uk.ngs.ca.common.ClientKeyStore;

import uk.ngs.ca.certificate.OnLineUserCertificateReKey;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
/**
 *
 * @author xw75
 */
public class OnLineCertificateInfo extends Observable{

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

    private Vector CertCSRVector = null;


    public OnLineCertificateInfo(char[] passphrase) {
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
                setupCertandCSR( passphrase );
                updateCertKeyStore();
            }
        } else {
            removeCertKeyStore();
            removeCSRFile();
        }
    }

    public void notifyObserver( String _notifyMessage ){
        setChanged();
        notifyObservers( _notifyMessage );
    }

    public OnLineUserCertificateReKey getOnLineUserCertificateReKey(){
        return new OnLineUserCertificateReKey( PASSPHRASE );
    }

    public ClientKeyStore getClientKeyStore(){
        return new ClientKeyStore( PASSPHRASE );
    }
/*
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
*/

    public boolean remove( int index ){

        CertificateCSRInfo _info = getCertCSRInfos()[ index ];
        String _status = _info.getStatus();
        String _encodedPublicKey = _info.getPublickey();
        PublicKey _publicKey = EncryptUtil.getPublicKey(_encodedPublicKey);
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

    }

    public void updateCertKeyStore() {
        String[] certIDs = certificateIDs;
        
        Vector _updateVector = new Vector();
        if( this.CertCSRVector == null ){
            return;
        }else{
            for( int i = 0; i < this.CertCSRVector.size(); i++ ){
                CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                String _status = _info.getStatus();
                if( _status.equals("VALID") ){
                    _updateVector.addElement(_info);
                }
            }
        }
        

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


        for( int i = 0; i < _updateVector.size(); i++ ){
            CertificateCSRInfo _info = (CertificateCSRInfo)_updateVector.elementAt(i);
            String _id = _info.getId();
            CertificateDownload certDownload = new CertificateDownload(_id);
            X509Certificate cert = certDownload.getCertificate();
            if( cert == null ){
                break;
            }else{
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
                   }
                }
                _restoreNewCertKeyStore();
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

    public CertificateCSRInfo[] getCertCSRInfos(){
        if( this.CertCSRVector == null ){
            return null;
        }else{
            int size = this.CertCSRVector.size();
            CertificateCSRInfo[] infos = new CertificateCSRInfo[ size ];
            for( int i = 0; i < size; i ++ ){
                infos[ i ] = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
            }
            return infos;
        }
    }

    public void refresh(){
        _reloadKeyStore();
        if( this.CertCSRVector == null ){
            this.CertCSRVector = new Vector();
        }
    }

    public void deleteCertificateCSRInfo( int _index ){
        Vector _certCSRVector = new Vector();
        int size = this.CertCSRVector.size();
        for( int i = 0; i < size; i ++ ){
            if( i != _index ){
                _certCSRVector.addElement( (CertificateCSRInfo)this.CertCSRVector.elementAt(i) );
            }
        }
        this.CertCSRVector = _certCSRVector;
    }

    public void addCertificateCSRInfo( CertificateCSRInfo _certCSRInfo ){
        this.CertCSRVector.addElement(_certCSRInfo);
    }

    private void setupCertandCSR( char[] passphrase ){
        String[] certIDs = null;
        String[] reqIDs = null;

        Vector certVector = new Vector();
        Vector reqVector = new Vector();

        boolean uselessKey = true;

        this.CertCSRVector = new Vector();

        try {
            Enumeration aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                PublicKey publicKey = cert.getPublicKey();
                ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey( publicKey );
                boolean isExist = resourcesPublicKey.isExist();
//System.out.println("isExist = " + isExist);
                Document doc = resourcesPublicKey.getDocument();
                XPath xpath = XPathFactory.newInstance().newXPath();
                XPathExpression expr = xpath.compile("/resources/resource/certificates/certificate");
                Object result = expr.evaluate(doc, XPathConstants.NODESET);
                NodeList nodeList = (NodeList) result;
                if( nodeList.getLength() == 0 ){
                    uselessKey = true;
                }else{
                   for (int i = 0; i < nodeList.getLength(); i++) {
                    Node _certNode = nodeList.item(i);
                    if (_certNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element _certElement = (Element) _certNode;
                        NodeList _idList = _certElement.getElementsByTagName("id");
                        Element _idElement = (Element) _idList.item(0);
                        String _id = _idElement.getChildNodes().item(0).getTextContent();

                        NodeList _statusList = _certElement.getElementsByTagName("status");
                        Element _statusElement = (Element) _statusList.item(0);
                        String _status = _statusElement.getChildNodes().item(0).getTextContent();

                        NodeList _ownerList = _certElement.getElementsByTagName("owner");
                        Element _ownerElement = (Element) _ownerList.item(0);
                        String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                        NodeList _roleList = _certElement.getElementsByTagName("role");
                        Element _roleElement = (Element) _roleList.item(0);
                        String _role = _roleElement.getChildNodes().item(0).getTextContent();

                        NodeList _useremailList = _certElement.getElementsByTagName("useremail");
                        Element _useremailElement = (Element) _useremailList.item(0);
                        String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                        NodeList _startdateList = _certElement.getElementsByTagName("startdate");
                        Element _startdateElement = (Element) _startdateList.item(0);
                        String _startdate = _startdateElement.getChildNodes().item(0).getTextContent();

                        NodeList _enddateList = _certElement.getElementsByTagName("enddate");
                        Element _enddateElement = (Element) _enddateList.item(0);
                        String _enddate = _enddateElement.getChildNodes().item(0).getTextContent();

                        NodeList _lifedaysList = _certElement.getElementsByTagName("lifedays");
                        Element _lifedaysElement = (Element) _lifedaysList.item(0);
                        String _lifedays = _lifedaysElement.getChildNodes().item(0).getTextContent();

                        NodeList _renewList = _certElement.getElementsByTagName("renew");
                        Element _renewElement = (Element) _renewList.item(0);
                        String _renew = _renewElement.getChildNodes().item(0).getTextContent();
                        
                        CertificateCSRInfo certCSRInfo = new CertificateCSRInfo();
                        certCSRInfo.setIsCSR(false);
                        certCSRInfo.setOwner(_owner);
                        certCSRInfo.setStatus(_status);
                        certCSRInfo.setRole( _role );
                        certCSRInfo.setUserEmail(_useremail);
                        certCSRInfo.setId(_id);
                        certCSRInfo.setStartDate(_startdate);
                        certCSRInfo.setEndDate(_enddate);
                        certCSRInfo.setLifeDays(_lifedays);
                        certCSRInfo.setRenew(_renew);
                        certCSRInfo.setPublickey(EncryptUtil.getEncodedPublicKey(publicKey));
                        this.CertCSRVector.addElement(certCSRInfo);

                        certVector.addElement( _id );
                    }
                   }
                }

                XPath _xpath = XPathFactory.newInstance().newXPath();
                XPathExpression _expr = _xpath.compile("/resources/resource/CSRs/CSR");
                Object _result = _expr.evaluate(doc, XPathConstants.NODESET);
                NodeList _nodeList = (NodeList) _result;

                if( ( _nodeList.getLength() == 0 ) && ( uselessKey ) ){
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

                        NodeList _ownerList = _csrElement.getElementsByTagName("owner");
                        Element _ownerElement = (Element) _ownerList.item(0);
                        String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                        NodeList _roleList = _csrElement.getElementsByTagName("role");
                        Element _roleElement = (Element) _roleList.item(0);
                        String _role = _roleElement.getChildNodes().item(0).getTextContent();

                        NodeList _useremailList = _csrElement.getElementsByTagName("useremail");
                        Element _useremailElement = (Element) _useremailList.item(0);
                        String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                        CertificateCSRInfo certCSRInfo = new CertificateCSRInfo();
                        certCSRInfo.setPublickey(EncryptUtil.getEncodedPublicKey(publicKey));
                        certCSRInfo.setIsCSR(true);
                        certCSRInfo.setOwner(_owner);
                        certCSRInfo.setRole( _role );

                        certCSRInfo.setUserEmail(_useremail);
                        certCSRInfo.setId(_id);
                        if( _status.equals("NEW") ){
                            String description = "Your certificate has been submitted and is waiting for the approve.";
                            certCSRInfo.setDescription(description);
                            certCSRInfo.setStatus(_status);
                            this.CertCSRVector.addElement(certCSRInfo);

                        }
                        if( _status.equals("RENEW") ){
                            String description = "Your renewal certificate has been submitted and is waiting for the approve.";
                            certCSRInfo.setDescription(description);
                            certCSRInfo.setStatus(_status);
                            this.CertCSRVector.addElement(certCSRInfo);
                        }
                        if( _status.equals("APPROVED") ){
                            String description = "Your certificate has been approved and is waiting for CA operator to sign.";
                            certCSRInfo.setDescription(description);
                            certCSRInfo.setStatus(_status);
                            this.CertCSRVector.addElement(certCSRInfo);
                        }
                        // we need to think about deleted/archived
                        if( _status.equals("DELETED")){
                            //at here, any deleted item would be removed from cakeystore.pkcs12
                            _updateKeyStore( alias );

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
/* */
                //reorganized the list
                Vector _vector = new Vector();
                int _index = this.CertCSRVector.size();
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("VALID") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("SUSPENDED") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("REVOKED") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("NEW") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("RENEW") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("APPROVED") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("ARCHIVED") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( _info.getStatus().equals("DELETED") ){
                        _vector.addElement(_info);
                    }
                }
                for( int i = 0; i < _index; i ++ ){
                    CertificateCSRInfo _info = (CertificateCSRInfo)this.CertCSRVector.elementAt(i);
                    if( ( ! _info.getStatus().equals("VALID") )
                            && ( ! _info.getStatus().equals("SUSPENDED") )
                            && ( ! _info.getStatus().equals("REVOKED") )
                            && ( ! _info.getStatus().equals("NEW") )
                            && ( ! _info.getStatus().equals("RENEW") )
                            && ( ! _info.getStatus().equals("APPROVED") )
                            && ( ! _info.getStatus().equals("ARCHIVED") )
                            && ( ! _info.getStatus().equals("DELETED") ) ){
                        _vector.addElement(_info);
                    }
                }
                
                this.CertCSRVector = _vector;
/*  */
        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    private boolean _reloadKeyStore( ){
        try {
            FileInputStream fis = new FileInputStream(keyStoreFile);
            keyStore.load(fis, this.PASSPHRASE);
            fis.close();
            return true;
        }catch( Exception kse ){
            kse.printStackTrace();
            return false;
        }
    }

    private boolean _updateKeyStore( String alias ){
//System.out.println("2222222222222222222222222222222222222222222222222222222222");
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
                    if (response.getStatus().equals(response.getStatus().SUCCESS_CREATED)) {
                        updateCSRFile( csr, doc );
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
        Client c = new Client(Protocol.HTTPS);
        Request request = new Request(Method.POST, new Reference(CSRURL), representation);

        Form form = new Form();
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
            keyStore = PKCS12KeyStoreUnlimited.getInstance();
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
    
}
