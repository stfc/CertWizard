package uk.ngs.ca.certificate.management;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.io.FileWriter;
import java.io.BufferedWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;
import javax.xml.parsers.DocumentBuilder;
import org.restlet.data.Status;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.Response;
import org.restlet.Request;
import org.restlet.data.Method;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.io.FileOutputStream;
import java.util.Enumeration;
import java.util.Date;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import org.apache.log4j.Logger;
import java.util.Observable;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.common.ClientCertKeyStore;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.certificate.OnLineUserCertificateReKey;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;

/**
 * If online, the class creates an in-memory cache of <code>CertificateCSRInfo</code>
 * objects that represent either CSRs or valid certificates that are recognised
 * by the online CA. The cacertkeystore.pkcs12 file is also updated so that
 * it contains only valid certificates for subsequent offline usage.
 * <p>
 * On class creation, the following actions occur;
 * <ol>
 * <li> Pending CSRs stored in the localcertificate.xml file are submitted to the CA server.</li>
 * <li> The cakeystore.pkcs12 file is read and for each CSR/cert entry,
 *    its status is checked with the online CA.</li>
 * <li> The cacertkeystore.pkcs12 file is re-initialised to contain only VALID certs
 *    (done for subsequent offline usage)</li>
 * </ol>
 * <p>
 * Note, during class creation, the cakeystore.pkcs12 file is read-only while the
 * cacertkeystore.pkcs12 file is <b>updated</b>. This class
 * needs lots of attention or maybe even depreciate this class and create a
 * CertificateCSRInfo class that can be used online or offline.
 *
 * @author xw75
 */
public class OnLineCertificateInfo extends Observable {
    private static final Logger myLogger = Logger.getLogger(OnLineCertificateInfo.class);
   
    // important class vars
    private String key_KeyStoreFilePath = null;  // '$HOME/.ca/cakeystore.pkcs12'
    private KeyStore key_keyStore = null;
    private String cert_KeyStoreFilePath = null; // '$HOME/.ca/cacertkeystore.pkcs12'
    private KeyStore cert_KeyStore = null;
    private String csr_xmlFilePath = null;      // '$HOME/.ca/localcertificate.xml'
    private ArrayList<CertificateCSRInfo> certCSRInfos = null;
    private char[] PASSPHRASE = null;

    /**
     * What does construction of this class do ? - what are the repercussions ?
     * in terms of creating/deleting cacertkeystore.pkcs12 and cakeystore.pkcs12
     * @param passphrase
     */
    public OnLineCertificateInfo(char[] passphrase) {
        this.PASSPHRASE = passphrase;

        String caDir = System.getProperty("user.home") + File.separator + ".ca" + File.separator;
        this.key_KeyStoreFilePath = caDir + SysProperty.getValue("ngsca.key.keystore.file");
        this.cert_KeyStoreFilePath = caDir + SysProperty.getValue("ngsca.cert.keystore.file");
        this.csr_xmlFilePath = caDir + SysProperty.getValue("ngsca.cert.xml.file");

        this.touchAndInitKeyStoreFromFile(); // Init this.keyStore from '$HOME/.ca/cakeystore.pkcs12'
        this.touchAndInitCertKeyStoreFromFile(); // Init this.certKeyStore from '$HOME/.ca/cacertkeystore.pkcs12'

        boolean key_KeyStoreEmpty = false;
        try { if (this.key_keyStore.size() == 0) key_KeyStoreEmpty = true;
        } catch (KeyStoreException ex) {
            throw new IllegalStateException("key_keyStore has not be initialized", ex);
        }

        if ( key_KeyStoreEmpty ) {
            // explicitly delete the 'cacertkeystore.pkcs12' and 'localcertificate.xml' files - why?
            (new File(this.cert_KeyStoreFilePath)).delete();
            (new File(this.csr_xmlFilePath)).delete();
        } else {

            // Submit pending CSR requests from the cert_xmlFile.
            this.submitPendingCSRRequests();

            // Online init certCSRInfos.
            // For each key_keyStore entry, get the PublicKey and
            // query to see if our CA has a record of that PubKey.
            // If recognised, create a new CSR or Certificate certCSRInfos
            // object from the PubKey and the server reponse info.
            this.initCertCSRInfos_From_KeyStoreCertsWithOnlineCheck();

            // Online init cert_keyStore with VALID and recognized certificates.
            // For every VALID certificate certCSRInfos object, download the cert from the CA server and
            // compare its PubKey to the PubKey of the certs in this.key_keyStore. For each match,
            // add the DOWNLOADED CERT and the keystore key as a pair to cert_keyStore
            // and Write to cert_KeyStoreFilePath.
            // This is done for subsequent offline usage.
            this.updateSaveCertKeyStoreForOfflineUse_From_ValidCertCSRInfosWithOnlineCheck();
        }
    }

    /**
     * Init <code>this.keyStore</code> from '$HOME/.ca/cakeystore.pkcs12'.
     * Create the file if it does not already exist and create empty keyStore.
     */
    private void touchAndInitKeyStoreFromFile() {
        // create or read '$HOME/.ca/cakeystore.pkcs12'
        ClientKeyStore.getClientkeyStore(this.PASSPHRASE);
        try {
            this.key_keyStore = PKCS12KeyStoreUnlimited.getInstance();
            FileInputStream fis = new FileInputStream(key_KeyStoreFilePath);
            key_keyStore.load(fis, this.PASSPHRASE);
            fis.close();
        } catch (Exception iep) {
            iep.printStackTrace();
        }
    }

    /**
     * Init <code>this.certKeyStore</code> from '$HOME/.ca/cacertkeystore.pkcs12'
     * Create the file if it does not already exist and create empty certKeyStore.
     */
    private void touchAndInitCertKeyStoreFromFile() {
         // create or read '$HOME/.ca/cacertkeystore.pkcs12'
        ClientCertKeyStore.getClientCertKeyStore(this.PASSPHRASE);
        try {
            this.cert_KeyStore = PKCS12KeyStoreUnlimited.getInstance();
            FileInputStream fis = new FileInputStream(this.cert_KeyStoreFilePath);
            this.cert_KeyStore.load(fis, PASSPHRASE);
            fis.close();
        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    /**
     * Notify the <code>MainWindowPanel</code> which is an observer of this class.
     * @param _notifyMessage
     */
    public void notifyObserver(String _notifyMessage) {
        this.setChanged();
        this.notifyObservers(_notifyMessage); // any indication of who are the observers ?
    }

    public OnLineUserCertificateReKey getOnLineUserCertificateReKey() {
        return new OnLineUserCertificateReKey(PASSPHRASE);
    }

    public ClientKeyStore getClientKeyStore() {
        return ClientKeyStore.getClientkeyStore(PASSPHRASE);
    }

    public CertificateCSRInfo[] getCertCSRInfos() {
        if (this.certCSRInfos == null) {
            return null;
        } else {
           return this.certCSRInfos.toArray( new CertificateCSRInfo[this.certCSRInfos.size()] );
        }
    }

    public void refresh() {
        try {
            FileInputStream fis = new FileInputStream(this.key_KeyStoreFilePath);
            key_keyStore.load(fis, this.PASSPHRASE);
            fis.close();
        } catch (Exception kse) {
            kse.printStackTrace();
        }
        if (this.certCSRInfos == null) {
            this.certCSRInfos = new ArrayList<CertificateCSRInfo>();
        }
    }

    public void deleteCertificateCSRInfo(int index) {
        this.certCSRInfos.remove(index);
    }

    public void addCertificateCSRInfo(CertificateCSRInfo certCSRInfo) {
        this.certCSRInfos.add(certCSRInfo);
    }

    /**
     * For each key_keyStore entry, get the PublicKey and
     * query to see if our CA has a record of that PubKey.
     * If recognised, create a new certCSRInfos from the PubKey and
     * server response (an XML doc).
     * <p>
     * For each <pre><certificate/> or <CSR/></pre> node in the
     * returned XML, create a new <code>CertificateCSRInfo</code> object
     * populated from the returned XML info and the key_keyStore PK, and
     * add it to <code>this.certCSRInfos</code> collection
     * (note, for certificate nodes, <code>CertificateCSRInfo.isCSR</code> is set to false).
     */
    private void initCertCSRInfos_From_KeyStoreCertsWithOnlineCheck() {
        this.certCSRInfos = new ArrayList<CertificateCSRInfo>();
        try {
            // prob can compile both expressions agains a single XPath object.
            XPath certXpath = XPathFactory.newInstance().newXPath();
            XPathExpression extractCertificateExpr = certXpath.compile("/resources/resource/certificates/certificate");
            XPath csrXpath = XPathFactory.newInstance().newXPath();
            XPathExpression exptractCSR_Expr = csrXpath.compile("/resources/resource/CSRs/CSR");

            Enumeration<String> keystoreAliases = key_keyStore.aliases();
            while (keystoreAliases.hasMoreElements()) {
                String keyStoreAlias = keystoreAliases.nextElement();
                X509Certificate cert = (X509Certificate) key_keyStore.getCertificate(keyStoreAlias);
                PublicKey keystorePublicKey = cert.getPublicKey();
                // Query CA server and determine if it has a record of this public key
                System.out.println("calling resources......................");
                ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey( keystorePublicKey );
                if( !resourcesPublicKey.isExist() ){
                    continue;  // move onto the next keystore entry if not.
                }
                // doc would be null if not recognized by CA
                Document doc = resourcesPublicKey.getDocument();
                boolean uselessPublicKey = false;

                // Create CERTIFICATE CertificateCSRInfo entries
                // =============================================
                NodeList certNodes = (NodeList) extractCertificateExpr.evaluate(doc, XPathConstants.NODESET);
                if (certNodes.getLength() == 0) {
                    uselessPublicKey = true;
                } else {
                    // iterate all the <certificate> XML nodes
                    for (int i = 0; i < certNodes.getLength(); i++) {
                        Node _certNode = certNodes.item(i);
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

                            //***Add a new Certificate CertificateCSRInfo to certCSRInfos***
                            CertificateCSRInfo certCSRInfo = new CertificateCSRInfo();
                            certCSRInfo.setIsCSR(false); // note !
                            certCSRInfo.setOwner(_owner);
                            certCSRInfo.setStatus(_status);
                            certCSRInfo.setRole(_role);
                            certCSRInfo.setUserEmail(_useremail);
                            certCSRInfo.setId(_id);
                            certCSRInfo.setStartDate(_startdate);
                            certCSRInfo.setEndDate(_enddate);
                            certCSRInfo.setLifeDays(_lifedays);
                            certCSRInfo.setRenew(_renew);
                            certCSRInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                            this.certCSRInfos.add(certCSRInfo);
                        }
                    }
                }

                // Create CSR CertificateCSRInfo entries
                // =====================================
                NodeList csrNodes = (NodeList)exptractCSR_Expr.evaluate(doc, XPathConstants.NODESET);
                if ((csrNodes.getLength() == 0) && uselessPublicKey ) {
                    deleteKeyStoreFileEntry(keyStoreAlias);  // should we really delete?
                } else {
                    // iterate all the <CSR> nodes
                    for (int i = 0; i < csrNodes.getLength(); i++) {
                        Node csrNode = csrNodes.item(i);
                        if (csrNode.getNodeType() == Node.ELEMENT_NODE) {
                            Element _csrElement = (Element) csrNode;
                            NodeList _idList = _csrElement.getElementsByTagName("id");
                            Element _idElement = (Element) _idList.item(0);
                            String _id = _idElement.getChildNodes().item(0).getTextContent();

                            NodeList _statusList = _csrElement.getElementsByTagName("status");
                            Element _statusElement = (Element) _statusList.item(0);
                            String _status = _statusElement.getChildNodes().item(0).getTextContent();
                            //if ("NEW".equals(_status) || "RENEW".equals(_status) || "APPROVED".equals(_status) ) reqList.add(_id);

                            NodeList _ownerList = _csrElement.getElementsByTagName("owner");
                            Element _ownerElement = (Element) _ownerList.item(0);
                            String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                            NodeList _roleList = _csrElement.getElementsByTagName("role");
                            Element _roleElement = (Element) _roleList.item(0);
                            String _role = _roleElement.getChildNodes().item(0).getTextContent();

                            NodeList _useremailList = _csrElement.getElementsByTagName("useremail");
                            Element _useremailElement = (Element) _useremailList.item(0);
                            String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                            if ("DELETED".equals(_status)) {
                                deleteKeyStoreFileEntry(keyStoreAlias); // remove from cakeystore.pkcs12 (need to think about deleted/archived)
                                continue; // force next loop iteration
                            }

                            String description = "Your certificate has an unrecognized status";
                            if ("NEW".equals(_status))
                                description = "Your certificate has been submitted and is awaiting approval.";
                            if ("RENEW".equals(_status))
                                description = "Your renewal certificate has been submitted and is awaiting approval.";
                            if ("APPROVED".equals(_status))
                                description = "Your certificate has been approved and is waiting for CA operator signing.";

                            //***Add a new CSR CertificateCSRInfo to certCSRInfos***
                            CertificateCSRInfo certCSRInfo = new CertificateCSRInfo();
                            certCSRInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                            certCSRInfo.setIsCSR(true); // note !
                            certCSRInfo.setOwner(_owner);
                            certCSRInfo.setRole(_role);
                            certCSRInfo.setUserEmail(_useremail);
                            certCSRInfo.setId(_id);
                            certCSRInfo.setDescription(description);
                            certCSRInfo.setStatus(_status);
                            this.certCSRInfos.add(certCSRInfo);
                        }
                    }
                }
            } // end of while

            //Simply sort this.certCSRInfos (are better ways to do this)
            ArrayList<CertificateCSRInfo> orderedCertCSRInfos = new ArrayList<CertificateCSRInfo>();
            int _index = this.certCSRInfos.size();
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("VALID".equals(_info.getStatus()))  orderedCertCSRInfos.add(_info);
            }
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("SUSPENDED".equals(_info.getStatus()))  orderedCertCSRInfos.add(_info);
            }
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("REVOKED".equals(_info.getStatus()))  orderedCertCSRInfos.add(_info);
            }
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("NEW".equals(_info.getStatus())) orderedCertCSRInfos.add(_info);
            }
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("RENEW".equals(_info.getStatus())) orderedCertCSRInfos.add(_info);
            }
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("APPROVED".equals(_info.getStatus())) orderedCertCSRInfos.add(_info);
            }
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("ARCHIVED".equals(_info.getStatus())) orderedCertCSRInfos.add(_info);
            }
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo _info = this.certCSRInfos.get(i);
                if ("DELETED".equals(_info.getStatus())) orderedCertCSRInfos.add(_info);
            }
            // add all others with differebt status to the end.
            for (int i = 0; i < _index; i++) {
                CertificateCSRInfo csrInfo = this.certCSRInfos.get(i);
                if ((!"VALID".equals(csrInfo.getStatus()))
                        && (!"SUSPENDED".equals(csrInfo.getStatus()))
                        && (!"REVOKED".equals(csrInfo.getStatus()))
                        && (!"NEW".equals(csrInfo.getStatus()))
                        && (!"RENEW".equals(csrInfo.getStatus()))
                        && (!"APPROVED".equals(csrInfo.getStatus()))
                        && (!"ARCHIVED".equals(csrInfo.getStatus()))
                        && (!"DELETED".equals(csrInfo.getStatus()))) {
                    orderedCertCSRInfos.add(csrInfo);
                }
            }
            this.certCSRInfos = orderedCertCSRInfos;
        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    private boolean deleteKeyStoreFileEntry(String alias) {
        try {
            this.key_keyStore.deleteEntry(alias);
            File f = new File(key_KeyStoreFilePath);
            FileOutputStream fos = new FileOutputStream(f);
            key_keyStore.store(fos, PASSPHRASE);
            fos.close();
            return true;
        } catch (Exception kse) {
            kse.printStackTrace();
            return false;
        }
    }

    /**
     * Populate cert_KeyStore for subsequent offline usage (maybe the network is lost).
     * For every VALID certCSRInfos (certificate), download the PubKey cert from the CA server and
     * compare to the certs' PubKeys in this.key_keyStore. For each match,
     * create new cert_KeyStore keyentry under a new meaningless alias from:
     * a) the downloaded cert and b) the corresponding private key residing in key_keyStore
     * Then, write cert_KeyStore.
     */
    private void updateSaveCertKeyStoreForOfflineUse_From_ValidCertCSRInfosWithOnlineCheck() {
        if (this.certCSRInfos == null || this.certCSRInfos.isEmpty()) {
            return;
        }
        // Iterate certCSRInfos and add only VALID [Certificate] certCSRInfo's to validCertCSRInfos
        ArrayList<CertificateCSRInfo> validCertCSRInfos = new ArrayList<CertificateCSRInfo>();
        for (int i = 0; i < this.certCSRInfos.size(); i++) {
            CertificateCSRInfo info = this.certCSRInfos.get(i);
            if ("VALID".equals(info.getStatus()))
                validCertCSRInfos.add(info);
        }
        // Delete all entries from cert_KeyStore.
        try {
            Enumeration<String> aliases = cert_KeyStore.aliases();
            while (aliases.hasMoreElements()) {
                cert_KeyStore.deleteEntry( aliases.nextElement() );
            }
        } catch (Exception ep) {
            ep.printStackTrace();
        }
        // Iterate certCSRInfos and add VALID cert/key pairs to cert_keyStore
        // (provided the PK can also be downloaded from CA server)
        for (int i = 0; i < validCertCSRInfos.size(); i++) {
            X509Certificate downloadedCert = (new CertificateDownload(validCertCSRInfos.get(i).getId())).getCertificate();
            if (downloadedCert == null) {
                return; // why return? what about other CSRInfos ? shouldn't we continue?
            } else {
                PublicKey downloadedPublicKey = downloadedCert.getPublicKey();
                // iterate all certs in this.key_keyStore and compare with
                // the downloadedPublicKey.
                ArrayList<X509Certificate> keyStoreCerts = getCertsFromKeyStore();
                for (int j = 0; j < keyStoreCerts.size(); j++) {
                    X509Certificate keyStoreCert = keyStoreCerts.get(j);
                    if (downloadedPublicKey.equals( keyStoreCert.getPublicKey() )) {
                        try {
                            // ok, we have a match,
                            // create new cert_KeyStore keyentry under a new meaninglness alias from: 
                            // a) the downloaded cert and b) the corresponding private key residing in key_keyStore
                            String keyStoreAlias = key_keyStore.getCertificateAlias(keyStoreCert);
                            PrivateKey privateKey = (PrivateKey) key_keyStore.getKey(keyStoreAlias, PASSPHRASE);
                            X509Certificate[] chain = {downloadedCert};
                            String my_alias = new Long((new Date().getTime())).toString();
                            // if we were using a single keystore, here we should replace our self-signed
                            // cert (that was used to do the CSR) with the new downloaded cert and key.
                            // According to javadoc, "If the given alias already exists, the keystore information
                            // associated with it is overridden by the given key (and possibly certificate chain)".
                            cert_KeyStore.setKeyEntry(my_alias, privateKey, PASSPHRASE, chain);
                        } catch (Exception ep) {
                            ep.printStackTrace();
                        }
                    }
                }
            }
        }
        // write the cert_Keystore to file
        try {
            File f = new File(this.cert_KeyStoreFilePath);
            if (f.exists()) f.delete(); //delete old one and create a new one.
            FileOutputStream fos = new FileOutputStream(f);
            this.cert_KeyStore.store(fos, PASSPHRASE);
            fos.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Get all the x509Certificate entries from <code>this.key_keyStore</code>
     */
    private ArrayList<X509Certificate> getCertsFromKeyStore() {
        ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
        try {
            Enumeration aliases = key_keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (key_keyStore.isKeyEntry(alias)) {
                    certs.add((X509Certificate) key_keyStore.getCertificate(alias));
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
        }
        return certs;
    }




    /**
     * Delete the cert/key pair with the given index from the cacertkeystore.pkcs12
     * and the cakeystore.pkcs12.
     * @param index (zero offset)
     * @return true if successfully deleted otherwise false.
     */
    public boolean remove(int index) {
        CertificateCSRInfo info = getCertCSRInfos()[index];
        String encodedPublicKey = info.getPublickey();
        PublicKey publicKey = EncryptUtil.getPublicKey(encodedPublicKey);
        ClientKeyStore keyStore = ClientKeyStore.getClientkeyStore(PASSPHRASE);
        // get the alias of the key, and delete the entry with that alias (will
        // also remove associated cert) and write change to cakeystore.pkcs12
        boolean deleted = keyStore.removeKey( keyStore.getPrivateKey(publicKey) );
        // also remove the corresponding entry from cacertkeystore.pkcs12 if
        // recognized as a VALID certificate entry.
        if ("VALID".equals(info.getStatus())) {
            ClientCertKeyStore certKeyStore = ClientCertKeyStore.getClientCertKeyStore(PASSPHRASE);
            deleted = certKeyStore.removeEntry( certKeyStore.getAlias(publicKey) );
        }
        return deleted;
    }

    /**
     * For all the CERTIFICATE elements in 'localcertificate.xml' file,
     * do a server CSR request and update 'localcertificate.xml' by
     * removing the successfully submitted csr from this file.
     */
    private void submitPendingCSRRequests() {
        try {
            File file = new File(this.csr_xmlFilePath);
            if (!file.exists()) {
                return;
            }

            // get Doc representation of 'localcertificate.xml'
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(file);
            doc.getDocumentElement().normalize();

            NodeList nodeList = doc.getElementsByTagName("Certificate");
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

                    // create the XML of the CSR and submit to CA server
                    Representation representation = getRepresentation(csr, email, pin);
                    Response response = doCSRRequest(representation);

                    if (response.getStatus().equals(Status.SUCCESS_CREATED)) {
                        removeCSR_WriteCSRFile(csr, doc);
                    } else if (response.getStatus().equals(Status.SUCCESS_ACCEPTED)) {
                        removeCSR_WriteCSRFile(csr, doc);
                    }
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
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

    private Response doCSRRequest(Representation representation) {
        Client c = new Client(Protocol.HTTPS);
        Request request = new Request(Method.POST, new Reference(SysProperty.getValue("uk.ngs.ca.request.csr.url")), representation);
        Form form = new Form();
        form.add("LocalHost", uk.ngs.ca.common.ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);
        //by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
        request.setClientInfo(info);
        Response _response = c.handle(request);
        return _response;
    }

    /**
     * Remove the given csr from the given doc and write the doc to
     * 'localcertificate.xml'. Return true if success otherwise return false.
     */
    private boolean removeCSR_WriteCSRFile(String csr, Document doc) {
        try {
            // remove the given csr from the doc
            Document _doc = removeCSRFromDoc(csr, doc);
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
            // overwrite the 'localcertificate.xml' file with the updated doc
            FileWriter fstream = new FileWriter(this.csr_xmlFilePath);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(sw.toString());
            out.close();
            myLogger.debug("[OnLineCertificateInfo] save xml file successfully");
            return true;

        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OnLineCertificateInfo] failed to save xml file: " + ep.toString());
            return false;
        }
    }



    /**
     * If the given csr exists in the given doc object, then remove it and return doc.
     */
    private Document removeCSRFromDoc(String csr, Document doc) {
        NodeList list = doc.getElementsByTagName("Certificate");
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);
                NodeList list1 = e1.getElementsByTagName("CSR");
                Element e2 = (Element) list1.item(0);
                // remove the given csr and normalize
                if (list1.item(0).getFirstChild().getNodeValue().equals(csr)) {
                    Element certElement = (Element) e2.getParentNode();
                    certElement.getParentNode().removeChild(certElement);
                    doc.normalize();
                }
            }
        }
        return doc;
    }




}
