/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.management;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Shared singleton that wraps the {@link ClientKeyStore} class and hosts
 * a map of {@link KeyStoreEntryWrapper} objects which both constitute the 
 * application's shared data model. 
 * <p>
 * Provides methods for checking the keyStore entries online against the CA server 
 * for their current status (status according to the CA).
 * Importantly the keyStore is <b>NEVER reStored to disk</b> by any of the methods.
 * ReStoring to disk has to be called manually by the client via {@link ClientKeyStore}. 
 * 
 * @author Xiao Wang
 * @author David Meredith (modifications - more refactoring still needed)
 */
public class ClientKeyStoreCaServiceWrapper {

    // important member vars

    /** The password of the managed keyStore file */
    private char[] mKeystorePASSPHRASE = null;
    /** Wrapper object that holds the reference to the managed keyStore */
    private final ClientKeyStore clientKeyStore;
    /** Map.key is keyStore alias and Map.value is a KeyStoreEntryWrapper */
    private Map<String, KeyStoreEntryWrapper> keyStoreEntryMap = new ConcurrentHashMap<String, KeyStoreEntryWrapper>(0);

    // some internals
    private XPath certXpath = XPathFactory.newInstance().newXPath();
    private XPathExpression extractCertificateExpr;
    private XPath csrXpath = XPathFactory.newInstance().newXPath();
    private XPathExpression exptractCSR_Expr;
    /** Class is a singleton, so hold internal reference */
    private static ClientKeyStoreCaServiceWrapper instance = null;


    /**
     * Get a shared singleton <code>KeyStoreWrapper</code> instance
     * @param passphrase for the <tt>'$HOME/.ca/cakeystore.pkcs12'</tt> keyStore file.
     * @return
     * @throws KeyStoreException if keyStore file cannot be created or read
     * @throws IllegalStateException if class cannot load for some other reason
     */
    public static synchronized ClientKeyStoreCaServiceWrapper getInstance(char[] passphrase) {
        if(instance == null) {
            instance = new ClientKeyStoreCaServiceWrapper(passphrase);
        }
        return instance;
    }

    private ClientKeyStoreCaServiceWrapper(char[] passphrase)  {
        this.mKeystorePASSPHRASE = passphrase;
        try {
            extractCertificateExpr = certXpath.compile("/resources/resource/certificates/certificate");
            exptractCSR_Expr = csrXpath.compile("/resources/resource/CSRs/CSR");
        } catch (XPathExpressionException ex) {
            Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.SEVERE, null, ex);
            throw new IllegalStateException(ex);
        }
        this.clientKeyStore = ClientKeyStore.getClientkeyStore(this.mKeystorePASSPHRASE);
    }



    /**
     * (Re)load the managed keyStore object from file and populate
     * <code>this.mKeyStoreEntries</code> with <code>KeyStoreEntryWrapper</code> objects.
     * Involves no online interactions. 
     * 
     * @throws KeyStoreException
     */
    public void loadFromFile() throws KeyStoreException {
        this.keyStoreEntryMap.clear(); 
        Enumeration<String> keystoreAliases = this.clientKeyStore.aliases();
        while (keystoreAliases.hasMoreElements()) {
            String sAlias = keystoreAliases.nextElement();
            this.keyStoreEntryMap.put(sAlias, this.createKSEntryWrapperInstanceFromEntry(sAlias));    
        }    
    }
    
    /**
     * Using the given keyStore alias, create a new <tt>KeyStoreEntryWrapper</tt>
     * from the corresponding entry stored in the managed keyStore. Note, this 
     * does not put the KeyStoreEntryWrapper into the keyStore, it simply 
     * creates a new instance. 
     * 
     * @param sAlias
     * @return
     * @throws KeyStoreException  
     */
    public KeyStoreEntryWrapper createKSEntryWrapperInstanceFromEntry(String sAlias) throws KeyStoreException {
        String x500PrincipalName = "Unknown"; // provide a default incase
        String issuerName = "Unknown";
        Date notBefore = null, notAfter = null;

        // Lets correspond to the java keytool entry types, see:
        // http://download.oracle.com/javase/1.4.2/docs/tooldocs/windows/keytool.html
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE type;

        if (this.clientKeyStore.isCertificateEntry(sAlias)) {
            // A single public key certificate belonging and signed by another party
            type = KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.TRUST_CERT_ENTRY;
            X509Certificate trustedCert = (X509Certificate) this.clientKeyStore.getCertificate(sAlias);
            x500PrincipalName = trustedCert.getSubjectX500Principal().toString();
            issuerName = trustedCert.getIssuerX500Principal().toString();
            notAfter = trustedCert.getNotAfter();
            notBefore = trustedCert.getNotBefore();

        } else if (this.clientKeyStore.isKeyEntry(sAlias) && this.clientKeyStore.getCertificateChain(sAlias) != null
                && this.clientKeyStore.getCertificateChain(sAlias).length != 0) {
            // A private key accompanied by the certificate "chain" for the corresponding public key
            type = KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY;
            // get the first in the chain - we know it has a value.
            X509Certificate cert = (X509Certificate) this.clientKeyStore.getCertificateChain(sAlias)[0];
            x500PrincipalName = cert.getSubjectX500Principal().toString();
            issuerName = cert.getIssuerX500Principal().toString();
            notAfter = cert.getNotAfter();
            notBefore = cert.getNotBefore();

        } else {
            // Still a keyEntry but with no corresponding cert chain.
            type = KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_ENTRY;
        }
        // create and add the KeyStoreEntryWrapper.
        KeyStoreEntryWrapper keyStoreEntry = new KeyStoreEntryWrapper(sAlias, type, this.clientKeyStore.getCreationDate(sAlias));
        keyStoreEntry.setNotAfter(notAfter);
        keyStoreEntry.setNotBefore(notBefore);
        keyStoreEntry.setX500PrincipalName(x500PrincipalName);
        keyStoreEntry.setIssuerName(issuerName);
        return keyStoreEntry;
    }
    
    
    /**
     * Request an online update of every keyStore entry and update the keyStore model accordingly. 
     * Important: the keyStore is <b>NOT reStored to disk</b>. 
     * This method is long running and should run in a background thread. 
     * The data model it modifies is itself thread safe (delegation of thread safety to model).
     * 
     * @return true if a keyStoreEntry was updated in the keyStore, otherwise false. 
     * @throws KeyStoreException 
     */
    /*public boolean onlineUpdateKeyStore() throws KeyStoreException {
        boolean updateOccurred = false; 
        // If online (can simply comment out the followng calls to disable initialisation online).
        //if(SystemStatus.getInstance().getIsOnline()){
            // Append the CertificateCSRInfo instances to each KeyStoreEntryWrapper
            this.checkAllEntriesForUpdates();
            
            // Update any self-signed CSR certs with the CA issued certs. 
            // Would only need to reStore keyStore if we did actually update a 
            // cert - but leave that to the calling client. 
            for (Iterator<KeyStoreEntryWrapper> it = this.keyStoreEntryMap.values().iterator(); it.hasNext();) {
                if(this.updateKeyStoreEntry(it.next())){
                    updateOccurred = true; 
                }
            }
        //}
        return updateOccurred; 
    }*/
    
    /**
     * Requests an online update of the given keyStore entry object and updates the keyStore model accordingly. 
     * Important: the keyStore is <b>NOT reStored to disk</b>. 
     * This method is long running and could be run in a background thread. 
     * The data model it modifies is itself thread safe (delegation of thread safety to model).
     * 
     * @param keyStoreEntryWrapper
     * @return true if the keyStoreEntry was updated in the keyStore, otherwise false. 
     * @throws KeyStoreException 
     */
    public boolean onlineUpdateKeyStoreEntry(KeyStoreEntryWrapper keyStoreEntryWrapper) throws KeyStoreException {
         this.checkEntryForUpdates(keyStoreEntryWrapper);
         return this.updateKeyStoreEntry(keyStoreEntryWrapper); 
    }
    
    /**
     * Get the managed ClientKeyStore instance 
     * @return
     */
    public ClientKeyStore getClientKeyStore(){
        return this.clientKeyStore;
    }


    /**
     * Get the KeyStore entries as a map.
     * @return
     */
    public Map<String, KeyStoreEntryWrapper> getKeyStoreEntryMap(){
        return this.keyStoreEntryMap;
    }

    /**
     * Delete the key store entry identified by the given alias from the
     * KeyStore and from <code>this.KeyStoreEntryMap</code>. 
     * Important: <b>does NOT reStore (persist) the file</b>.
     * @param alias
     * @throws KeyStoreException
     */
    public void deleteEntry(String alias) throws KeyStoreException {
        // delete from the cached list and also from the keyStore. Do not want
        // to call loadKeyStoreWithOnlineEntryUpdate(); 
        this.keyStoreEntryMap.remove(alias);       
        this.clientKeyStore.deleteEntry(alias);
        //this.clientKeyStore.reStore();
    }


    /**
     * Check for updates for all KeyStoreEntryWrappers. 
     * Does not update the keyStore. 
     */
    /*private void checkAllEntriesForUpdates() {
        for (Iterator<KeyStoreEntryWrapper> it = this.keyStoreEntryMap.values().iterator(); it.hasNext();) {
            KeyStoreEntryWrapper keyStoreEntryWrapper = it.next();
            this.checkEntryForUpdates(keyStoreEntryWrapper);
        }
    }*/
 
    
    /**
     * Download the latest status for the given KeyStoreEntryWrapper (if any) and update the 
     * KeyStoreEntryWrapper's member CertificateCSRInfo object (does not update the keyStore). 
     * <p/>
     * If keyStoreEntryWrapper has KEY_PAIR_ENTRY type, get the PublicKey and
     * query our CA to see if it has a record of that PubKey. If recognised, 
     * create a new <code>CertificateCSRInfo</code> from the PubKey and the
     * server response (XML) and add as a member object of the <code>keyStoreEntryWrapper</code>.
     * 
     * @param keyStoreEntryWrapper 
     */ 
    private void checkEntryForUpdates(KeyStoreEntryWrapper keyStoreEntryWrapper) {
        try {
            // return if not KEY_PAIR_ENTRY
            if (!keyStoreEntryWrapper.getEntryType().equals(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)) {
                return;
            }

            // We do not want to check every possible keystore entry against
            // our CA - the keystore may have many different certs issued from
            // different CAs, therefore only continue if our certificate is 
            // issued by our CA or is a self-signed CSR entry (a Self-signed 
            // CSR cert is created by this tool and used for CSRs where 
            // issuer dn == subject dn). 
            
            // TODO: - need to check that this is the user's cert if this is
            // a cert chain (e.g. userCert - eScienceCA - eScience Root).
            // If this entry is a chain, getCertificate returns the first
            // element in that chain is returned.
            /*
             * String keyStoreAlias = keyStoreEntryWrapper.getAlias();
             * X509Certificate cert = (X509Certificate)
             * clientKeyStore.getKeyStoreCopy().getCertificate(keyStoreAlias); if (
             * !(cert.getSubjectDN().toString().equals(cert.getIssuerDN().toString())
             * || cert.getIssuerDN().toString().equals(
             * SysProperty.getValue("ngsca.issuer.dn") )) ) { return;
             *  }
             */
            String keyStoreAlias = keyStoreEntryWrapper.getAlias();
            X509Certificate cert = (X509Certificate) clientKeyStore.getCertificate(keyStoreAlias);
            
            // check if self signed
            boolean isSelfSignedCert = false;
            if(cert.getSubjectX500Principal().getName().equals(cert.getIssuerX500Principal().getName())){
                isSelfSignedCert = true;
            }
            // check if cert has known issuer DN
            boolean hasKnownIssuerDN = false;
            String[] allKnownDNs = SysProperty.getValue("ngsca.issuer.dn").split(";");
            for (int i = 0; i < allKnownDNs.length; i++) {
                String keystoreCertIssuerDN = cert.getIssuerX500Principal().getName(); 
                //System.out.println("Comparing: ["+keystoreCertIssuerDN+"] ["+allKnownDNs[i]+"]");
                if(keystoreCertIssuerDN.equals(allKnownDNs[i])) {
                    hasKnownIssuerDN = true;
                    break;
                }
            }
            
            if (isSelfSignedCert || hasKnownIssuerDN) {
                // ok, we either have a self signed cert (CSR) or the cert 
                // has a known issuer DN so we will continue on. 
            } else {
                return;
            }

            //String oldStatus = keyStoreEntryWrapper.getServerCertificateCSRInfo().getStatus();

            // Query CA and determine if it recognises this public key, 
            // if not, return as the CA will not know the status. 
            PublicKey keystorePublicKey = cert.getPublicKey();
            ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey(keystorePublicKey);
            if (!resourcesPublicKey.isExist()) {
                return;
            }  
            
            // doc would be null if not recognized by CA
            Document doc = resourcesPublicKey.getDocument();
            NodeList certNodes = (NodeList) extractCertificateExpr.evaluate(doc, XPathConstants.NODESET);
            NodeList csrNodes = (NodeList) exptractCSR_Expr.evaluate(doc, XPathConstants.NODESET);

            // Ok, this keyStore entry is recognised by our CA so first nullify 
            // the serverCertCSRInfo before we re-set it.
            keyStoreEntryWrapper.setServerCertificateCSRInfo(null);

            // For each <certificate/> (takes precidence) or <CSR/> node in the
            // returned XML, create a new CertificateCSRInfo object
            // populated from the returned XML and the m_keyStore PubKey, and
            // add it to the corresponding keyStoreEntryWrapper
            // (note, for certificate nodes, CertificateCSRInfo.isCSR is set to false).
            
            // ADD CertificateCSRInfo entries
            // =============================================
            if (certNodes.getLength() != 0) {
                // Iterate all the <certificate> XML nodes      
                // If there are multiple returned nodes, 
                // the LAST node is used. This is ok because the server 
                // gurantees that the last node is the latest. 
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

                        //***Add a new Certificate CertificateCSRInfo to keyStoreEntryWrapper***
                        CertificateCSRInfo serverInfo = new CertificateCSRInfo();
                        serverInfo.setIsCSR(false); // note !
                        serverInfo.setOwner(_owner);
                        serverInfo.setStatus(_status); // could be VALID or another cert status
                        serverInfo.setRole(_role);
                        serverInfo.setUserEmail(_useremail);
                        serverInfo.setId(_id);
                        serverInfo.setStartDate(_startdate);
                        serverInfo.setEndDate(_enddate);
                        serverInfo.setLifeDays(_lifedays);
                        serverInfo.setRenew(_renew);
                        //serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                        keyStoreEntryWrapper.setServerCertificateCSRInfo(serverInfo);
                    }
                }
            } else if (csrNodes.getLength() != 0) {
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
                        
                        NodeList _ownerList = _csrElement.getElementsByTagName("owner");
                        Element _ownerElement = (Element) _ownerList.item(0);
                        String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                        NodeList _roleList = _csrElement.getElementsByTagName("role");
                        Element _roleElement = (Element) _roleList.item(0);
                        String _role = _roleElement.getChildNodes().item(0).getTextContent();

                        NodeList _useremailList = _csrElement.getElementsByTagName("useremail");
                        Element _useremailElement = (Element) _useremailList.item(0);
                        String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                        String description = "Your certificate has an unrecognized status";
                        if ("DELETED".equals(_status)) {
                            description = "Your certificate has been deleted from our CA.";
                        }
                        else if ("NEW".equals(_status)) {
                            description = "Your certificate has been submitted and is awaiting approval.";
                        }
                        else if ("RENEW".equals(_status)) {
                            description = "Your renewal certificate has been submitted and is awaiting approval.";
                        }
                        else if ("APPROVED".equals(_status)) {
                            description = "Your certificate has been approved and is awaiting CA operator signing.";
                        }
                        //else if("VALID".equals(_status)){
                           // VALID is not an enum status for a CSR, only for a cert 
                        //}

                        //***Add a new CSR CertificateCSRInfo to keyStoreEntryWrapper***
                        CertificateCSRInfo serverInfo = new CertificateCSRInfo();
                        //serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                        serverInfo.setIsCSR(true); // note !
                        serverInfo.setOwner(_owner);
                        serverInfo.setRole(_role);
                        serverInfo.setUserEmail(_useremail);
                        serverInfo.setId(_id);
                        serverInfo.setDescription(description);
                        serverInfo.setStatus(_status);
                        // note we do not set the public key or date info if this
                        // is a CSR, but we do for a cert 
                        keyStoreEntryWrapper.setServerCertificateCSRInfo(serverInfo);
                    }
                }
            }

        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }


    /**
     * Download any certificate updates for the given KeyStoreEntryWrapper (if any) and update 
     * <code>this.clientKeyStore</code> (note, the keyStore is NOT reStored to disk). 
     * <p>
     * For the given keyStoreEntryWrapper, check the following;
     * <ul>
     *  <li>It is of type {@link KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE#KEY_PAIR_ENTRY}</li>
     *  <li>It has a member {@link CertificateCSRInfo} object with a status of 'VALID'. 
     *   Note, to set/update this status, call either {@link #checkAllEntriesForUpdates() }
     *   or {@link #checkEntryForUpdates(uk.ngs.ca.certificate.model.KeyStoreEntryWrapper) }</li>
     * </ul>
     * 
     * If both pre-conditions are true, then download the cert from the CA server and compare it to the 
     * cert in the managed keyStore. If the two certificates are identical, we 
     * do not need to update/replace the cert in our keyStore so return false. 
     * <p>
     * If the two certificates are different, then either;  
     * <ul>
     *   <li>The certificate for this entry has changed on the server 
     *   (maybe some new attributes have been added)</li>
     *   <li>The certificate in our keyStore is a self-signed CSR cert.</li> 
     * </ul>
     * Therefore, proceed to compare the PubKey of each to ensure they correspond. 
     * If the keys are identical, then replace the keyStore cert entry with the 
     * newly downloaded cert under the same alias (the private key already resides in keyStore). 
     * 
     * @param keyStoreEntryWrapper 
     * @return true if <code>this.clientKeyStore</code> was updated, otherwise false. 
     */ 
    public boolean updateKeyStoreEntry(KeyStoreEntryWrapper keyStoreEntryWrapper) throws KeyStoreException {

        if (keyStoreEntryWrapper.getEntryType().equals(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)
                && keyStoreEntryWrapper.getServerCertificateCSRInfo() != null
                && "VALID".equals(keyStoreEntryWrapper.getServerCertificateCSRInfo().getStatus())) {

            // Download the cert from server by passing the id dont think this returns a cert chain)
            X509Certificate downloadedCert =
                    (new CertificateDownload(keyStoreEntryWrapper.getServerCertificateCSRInfo().getId()))
                    .getCertificate();


            if (downloadedCert == null) {
                return false; // maybe we temporarily lost connection
            } else {
                try {
                    PublicKey downloadedPublicKey = downloadedCert.getPublicKey();
                    if(downloadedPublicKey == null) return false; 
                    Certificate[] ksChain = this.clientKeyStore
                            .getCertificateChain(keyStoreEntryWrapper.getAlias());
                    if(ksChain == null) {
                        // the keystore entry may have been deleted in another thread.
                        return false;
                    } 
                    PublicKey keystorePublicKey = ksChain[0].getPublicKey();

                    // We only want to update the clientKeyStore cert IF there 
                    // were changes to the cert on the server. We do not want to 
                    // replace each/every cert if it is identical to what we already have. 
                    X509Certificate x509 = this.clientKeyStore.getX509Certificate(keyStoreEntryWrapper.getAlias());
                    if(x509 == null){
                        return false; 
                    }
                    if(x509.equals(downloadedCert)){
                        return false; 
                    }
                    
                    // Ok, they are not the same so either; 
                    //  a) the cert has changed on the server (e.g. maybe some new usage extensions were addeed)
                    //  b) the cert we have in the keyStore is a self-signed CSR
                    // Regardless, check that the public keys are the same 
                    // (they must be identical for the private key to match) 
                    if (downloadedPublicKey.equals(keystorePublicKey)) {
                        // Replace the certificate chain
                        PrivateKey privateKey = 
                                (PrivateKey) this.clientKeyStore.getKey(keyStoreEntryWrapper.getAlias(), mKeystorePASSPHRASE);
                        
                        // Maybe the key was removed in an external process? 
                        // (keyStore is a normal pkcs12 that can be accessed from command line) 
                        if(privateKey == null){
                            return false; 
                        }
                        X509Certificate[] chain = {downloadedCert};
                        // Replace keystore entry with the new downloaded cert and its corresponding key.
                        // (i.e. replaces the self-signed cert that was used to do the CSR).
                        // TODO: need to check if the newly issued cert contains only the
                        // user cert? - what about the eSci CA and root certs in the chain ?
                        // According to javadoc, "If the given alias already exists, the keystore information
                        // associated with it is overridden by the given key (and possibly certificate chain)".
                        System.out.println("Replacing: [" + keyStoreEntryWrapper.getAlias() + "] with downloaded cert");

                        // Synchronize composite action on same lock so that 
                        // it is an atomic. The lock  is reentrant so we can call 
                        // out to nested synchronized methods locked by the same lock. 
                        synchronized(this.clientKeyStore){ 
                           this.clientKeyStore.deleteEntry(keyStoreEntryWrapper.getAlias());
                           this.clientKeyStore.setKeyEntry(keyStoreEntryWrapper.getAlias(), privateKey, mKeystorePASSPHRASE, chain);
                        }
                        // ok, we have have replaced this cert, so we need to
                        // update the ketStoreEntryWrapper for this entry.
                        // Note, no need to update online info (this.initCertCSRInfo_WithOnlineCheck(keyStoreEntryWrapper));
                        // or the alias as these have not changed. 
                        keyStoreEntryWrapper.setX500PrincipalName(chain[0].getSubjectX500Principal().toString());
                        keyStoreEntryWrapper.setIssuerName(chain[0].getIssuerX500Principal().toString());
                        keyStoreEntryWrapper.setNotAfter(chain[0].getNotAfter());
                        keyStoreEntryWrapper.setNotBefore(chain[0].getNotBefore());
                        return true;
                    }
                } catch (Exception ex) {
                    Logger.getLogger(ClientKeyStoreCaServiceWrapper.class.getName()).log(Level.SEVERE, null, ex);
                    throw new IllegalStateException(ex);
                }
            }
        }
        return false;
    }


}
