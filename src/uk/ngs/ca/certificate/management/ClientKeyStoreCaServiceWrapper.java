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
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Shared singleton that wraps the managed '$HOME/.ca/cakeystore.pkcs12' keyStore file. 
 * The class checks the keyStore entries against the CA server for their current 
 * status (according to the CA).
 *
 * @author Xiao Wang
 * @author David Meredith (modifications - lots still to refactor)
 */
public class ClientKeyStoreCaServiceWrapper {

    // important memeber vars

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
     * @param passphrase for the '$HOME/.ca/cakeystore.pkcs12' keystore file.
     * @return
     * @throws KeyStoreException if keystore file cannot be created or read
     * @throws IllegalStateException if class cannot load for some other reason
     */
    public static synchronized ClientKeyStoreCaServiceWrapper getInstance(char[] passphrase) throws KeyStoreException {
        if(instance == null) {
            instance = new ClientKeyStoreCaServiceWrapper(passphrase);
        }
        return instance;
    }

    private ClientKeyStoreCaServiceWrapper(char[] passphrase) throws KeyStoreException {
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
     * 
     * @throws KeyStoreException
     */
    public void reStoreReload() throws KeyStoreException {
        // keyStore object entries may have been modified, so
        // need to re-load this.keyStore pointer object from file because
        // the act of persisting then reloading seems to re-organize the
        // keystore entries so that Trusted certs that exist in an
        // imported cert chain are also stored as standalone entries in the
        // keyStore file.
        this.clientKeyStore.reStore();
        // Now refresh the keyStore entry map
        this.keyStoreEntryMap.clear(); 
        Enumeration<String> keystoreAliases = this.clientKeyStore.aliases();
        while (keystoreAliases.hasMoreElements()) {
            String sAlias = keystoreAliases.nextElement();
            this.keyStoreEntryMap.put(sAlias, this.createKeyStoreEntryWrapper(sAlias));    
        }    
    }
    
    /**
     * Using the given keyStore alias, create a new <tt>KeyStoreEntryWrapper</tt>
     * from the corresponding entry stored in the managed keyStore. 
     * 
     * @param sAlias
     * @return
     * @throws KeyStoreException 
     */
    public KeyStoreEntryWrapper createKeyStoreEntryWrapper(String sAlias) throws KeyStoreException {
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
     * Request an online update of every keyStore entry and update the keyStore accordingly. 
     * Note, the keyStore is NOT reStored to disk. 
     * This method is long running and should run in a background thread. 
     * The data model it modifies is itself thread safe (delegation of thread safety to model).
     * 
     * @return true if the keyStoreEntry was updated in the keyStore, otherwise false. 
     * @throws KeyStoreException 
     */
    public boolean onlineUpdateKeyStore() throws KeyStoreException {
        boolean updateOccurred = false; 
        // If online (can simply comment out the followng calls to disable initialisation online).
        if(PingService.getPingService().isPingService()){
            // Append the CertificateCSRInfo instances to each KeyStoreEntryWrapper
            this.checkAllEntriesForUpdates();
            
            // Update any self-signed CSR certs with the CA issued certs. Only
            // need to reStore keyStore if we did actually update a cert.
            for (Iterator<KeyStoreEntryWrapper> it = this.keyStoreEntryMap.values().iterator(); it.hasNext();) {
                if(this.updateKeyStoreEntry(it.next())){
                    updateOccurred = true; 
                }
            }
            /*if(updateOccurred){
                // If either a self-signed CSR cert or a VALID CA issued cert
                // was updated/replaced with a new/updated CA issued certificate
                // (i.e. occuring on new cert applications, renewals, online update),
                // then reStore keyStore to persist changes.
                this.clientKeyStore.reStore();
            }*/
        }
        return updateOccurred; 
    }
    
    /**
     * Request an online update of the given keyStore entry object and update the keyStore accordingly. 
     * Note, the keyStore is NOT reStored to disk. 
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
     * Important: does reStore (persist) the file.
     * @param alias
     * @throws KeyStoreException
     */
    public void deleteEntry(String alias) throws KeyStoreException {
        // delete from the cached list and also from the keyStore. Do not want
        // to call loadKeyStoreWithOnlineEntryUpdate(); 
        this.keyStoreEntryMap.remove(alias);       
        this.clientKeyStore.deleteEntry(alias);
        this.clientKeyStore.reStore();
    }


    /**
     * Check for updates for all KeyStoreEntryWrappers. 
     * Does not update the keyStore. 
     */
    private void checkAllEntriesForUpdates() {
        for (Iterator<KeyStoreEntryWrapper> it = this.keyStoreEntryMap.values().iterator(); it.hasNext();) {
            KeyStoreEntryWrapper keyStoreEntryWrapper = it.next();
            this.checkEntryForUpdates(keyStoreEntryWrapper);
        }
    }
 
    
    /**
     * Download the latest status for the given KeyStoreEntryWrapper (if any) and update the 
     * KeyStoreEntryWrapper's member CertificateCSRInfo object (does not update the keyStore). 
     * <p/>
     * If keyStoreEntryWrapper has KEY_PAIR_ENTRY type, get the PublicKey and
     * query our CA to see if it has a record of that PubKey.
     * If recognised, create a new <code>CertificateCSRInfo</code> from the PubKey and the
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
            //if ((cert.getSubjectDN().toString().equals(cert.getIssuerDN().toString()))) {
            // getIssuerX500Principal() is supports RFC 2253
            if(cert.getSubjectX500Principal().getName().equals(cert.getIssuerX500Principal().getName())){
                isSelfSignedCert = true;
            }
            // check if cert has known issuer DN
            boolean hasKnownIssuerDN = false;
            String[] allKnownDNs = SysProperty.getValue("ngsca.issuer.dn").split(";");
            for (int i = 0; i < allKnownDNs.length; i++) {
                String keystoreCertIssuerDN = cert.getIssuerX500Principal().getName(); //cert.getIssuerDN().toString()
                //System.out.println("Comparing: ["+keystoreCertIssuerDN+"] ["+allKnownDNs[i]+"]");
                //if (cert.getIssuerDN().toString().equals(allKnownDNs[i])) {
                if(keystoreCertIssuerDN.equals(allKnownDNs[i])) {
                    hasKnownIssuerDN = true;
                    break;
                }
            }
            //System.out.println("isSelfSigned, hasKnownIssuerDN: "+isSelfSignedCert+", "+hasKnownIssuerDN);

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

            // Ok, this keyStore entry is recognized by our CA so first nullify 
            // the serverCertCSRInfo before we re-set it.
            keyStoreEntryWrapper.setServerCertificateCSRInfo(null);

            // For each <certificate/> or <CSR/> node in the
            // returned XML, create a new <code>CertificateCSRInfo</code> object
            // populated from the returned XML and the m_keyStore PubKey, and
            // add it to the corresponding <code>keyStoreEntryWrapper</code>
            // (note, for certificate nodes, <code>CertificateCSRInfo.isCSR</code> is set to false).
            
            // ADD CertificateCSRInfo entries
            // =============================================
            if (certNodes.getLength() != 0) {
                // Iterate all the <certificate> XML nodes
                
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
                        serverInfo.setStatus(_status);
                        serverInfo.setRole(_role);
                        serverInfo.setUserEmail(_useremail);
                        serverInfo.setId(_id);
                        serverInfo.setStartDate(_startdate);
                        serverInfo.setEndDate(_enddate);
                        serverInfo.setLifeDays(_lifedays);
                        serverInfo.setRenew(_renew);
                        serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
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

                        String description = "Your certificate has an unrecognized status";
                        if ("DELETED".equals(_status)) {
                            //deleteKeyStoreFileEntry(keyStoreAlias); // remove from cakeystore.pkcs12 (need to think about deleted/archived)
                            //return;
                            description = "Your certificate has been deleted from our CA.";
                        }
                        if ("NEW".equals(_status)) {
                            description = "Your certificate has been submitted and is awaiting approval.";
                        }
                        if ("RENEW".equals(_status)) {
                            description = "Your renewal certificate has been submitted and is awaiting approval.";
                        }
                        if ("APPROVED".equals(_status)) {
                            description = "Your certificate has been approved and is waiting for CA operator signing.";
                        }

                        //***Add a new CSR CertificateCSRInfo to keyStoreEntryWrapper***
                        CertificateCSRInfo serverInfo = new CertificateCSRInfo();
                        serverInfo.setPublickey(EncryptUtil.getEncodedPublicKey(keystorePublicKey));
                        serverInfo.setIsCSR(true); // note !
                        serverInfo.setOwner(_owner);
                        serverInfo.setRole(_role);
                        serverInfo.setUserEmail(_useremail);
                        serverInfo.setId(_id);
                        serverInfo.setDescription(description);
                        serverInfo.setStatus(_status);
                        keyStoreEntryWrapper.setServerCertificateCSRInfo(serverInfo);
                    }
                }
            }

        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }


    /**
     * Download any updates for the given KeyStoreEntryWrapper and update 
     * <code>this.clientKeyStore</code> (note, the keyStore is NOT reStored to disk). 
     * 
     * For the given keyStoreEntryWrapper, check the following;
     *  a) it is a KEY_PAIR_ENTRY type
     *  b) it has a VALID CertificateCSRInfo object (issued by our our online CA)
     * If true, then download the cert from the CA server and compare to the PubKey of the
     * corresponding entry in this.m_keyStore. If there is a key match, then 
     * replace the keyStore entry with an updated entry under the same alias 
     * using the downloaded cert and the private key (which already resides in keyStore). 
     * 
     * @param keyStoreEntryWrapper 
     * @return true if <code>this.clientKeyStore</code> was updated, otherwise false. 
     */ 
    public boolean updateKeyStoreEntry(KeyStoreEntryWrapper keyStoreEntryWrapper) throws KeyStoreException {

        // we are only interested in replacing the cert with the CA issued
        // cert if the keyStoreEntryWrapper is:
        // 1) a KEY_PAIR_ENTRY,
        // 2) its CertificateCSRInfo is not null and has a VALID status (i.e. it was recognised by our CA online)
        if (keyStoreEntryWrapper.getEntryType().equals(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)
                && keyStoreEntryWrapper.getServerCertificateCSRInfo() != null
                && "VALID".equals(keyStoreEntryWrapper.getServerCertificateCSRInfo().getStatus())) {

            // Download the cert from server by passing the id 
            // (dont think this returns a cert chain)
            X509Certificate downloadedCert =
                    (new CertificateDownload(keyStoreEntryWrapper.getServerCertificateCSRInfo().getId())).getCertificate();


            if (downloadedCert == null) {
                return false; // maybe we temporarily lost connection
            } else {
                try {
                    PublicKey downloadedPublicKey = downloadedCert.getPublicKey();
                    Certificate[] ksChain = this.clientKeyStore.getCertificateChain(keyStoreEntryWrapper.getAlias());
                    if(ksChain == null) {
                        // the keystore entry may have been deleted in another thread.
                        return false;
                    } 
                    PublicKey keystorePublicKey = ksChain[0].getPublicKey();

                    if (downloadedPublicKey.equals(keystorePublicKey)) {
                        // Replace the certificate chain
                        PrivateKey privateKey = (PrivateKey) this.clientKeyStore.getKey(keyStoreEntryWrapper.getAlias(), mKeystorePASSPHRASE);
                        if(privateKey == null){
                            // the keystore entry may have been deleted in another thread.
                            return false; 
                        }
                        X509Certificate[] chain = {downloadedCert};
                        // Replace keystore entry with the new downloaded cert and its corresponding key.
                        // (i.e. replaces the self-signed cert that was used to do the CSR).
                        // TODO: need to check if the newly issued cert contains only the
                        // user cert? - what about the eSci CA and root certs in the chain ?
                        // According to javadoc, "If the given alias already exists, the keystore information
                        // associated with it is overridden by the given key (and possibly certificate chain)".
                        System.out.println("Refreshing: [" + keyStoreEntryWrapper.getAlias() + "] with downloaded cert");

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



 





    	/**
	 * TODO Get the KeyStoreReport as plain text.
	 *
	 * @return Keystore report
	 * @throws CryptoException A crypto related problem was encountered generating the keystore report
	 */
	/*private String getKeyStoreReport()
	{
		try
		{
			// Buffer to hold report
			StringBuilder sbReport = new StringBuilder(2000);

			// General keystore information...

			// Keystore type
			sbReport.append(m_keystore.getType());
			sbReport.append("\n");

			// Keystore provider
			sbReport.append(m_keystore.getProvider().getName());
			sbReport.append("\n");

			// Keystore size (entries)
			sbReport.append(m_keystore.size());
			sbReport.append("\n\n");

			Enumeration<String> aliases = m_keystore.aliases();

			// Get information on each keystore entry
			while (aliases.hasMoreElements())
			{
				// Alias
				String sAlias = aliases.nextElement();
				sbReport.append(sAlias);
				sbReport.append("\n");

				// Creation date

				//if (ksType.isEntryCreationDateUseful())
				//{
				//	Date dCreation = m_keystore.getCreationDate(sAlias);

					// Include time zone
				//	String sCreation =
				//	    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(dCreation);
				//	sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.creation"),
				//	    sCreation));
				//	sbReport.append("\n");
				//}

				Certificate[] certChain = null;

				// Get entry type and certificates
				if (m_keystore.isKeyEntry(sAlias))
				{
					certChain = m_keystore.getCertificateChain(sAlias);

					if (certChain == null || certChain.length == 0)
					{
						sbReport.append(RB.getString("DKeyStoreReport.report.key"));
						sbReport.append("\n");
					}
					else
					{
						sbReport.append(RB.getString("DKeyStoreReport.report.keypair"));
						sbReport.append("\n");
					}
				}
				else
				{
					sbReport.append(RB.getString("DKeyStoreReport.report.trustcert"));
					sbReport.append("\n");

					Certificate cert = m_keystore.getCertificate(sAlias);
					if (cert != null)
					{
						certChain = new Certificate[] { cert };
					}
				}

				// Get information on each certificate in an entry
				if (certChain == null || certChain.length == 0)
				{
					// Zero certificates
					sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.certs"), 0));
					sbReport.append("\n\n");
				}
				else
				{
					X509Certificate[] x509CertChain = X509CertUtil.convertCertificates(certChain);

					// One or more certificates
					int iChainLen = x509CertChain.length;
					sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.certs"),
					    iChainLen));
					sbReport.append("\n\n");

					for (int iCnt = 0; iCnt < iChainLen; iCnt++)
					{
						// Get information on an individual certificate
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.cert"),
						    iCnt + 1, iChainLen));
						sbReport.append("\n");

						X509Certificate x509Cert = x509CertChain[iCnt];

						// Version
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.version"),
						    x509Cert.getVersion()));
						sbReport.append("\n");

						// Subject
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.subject"),
						    x509Cert.getSubjectDN()));
						sbReport.append("\n");

						// Issuer
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.issuer"),
						    x509Cert.getIssuerDN()));
						sbReport.append("\n");

						// Serial Number
						StringBuilder sSerialNumber = StringUtil.toHex(x509Cert.getSerialNumber(), 4, " ");
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.serial"),
						    sSerialNumber));
						sbReport.append("\n");

						// Valid From
						Date dValidFrom = x509Cert.getNotBefore();
						String sValidFrom =
						    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM).format(
						        dValidFrom);
						sbReport.append(MessageFormat.format(
						    RB.getString("DKeyStoreReport.report.validfrom"), sValidFrom));
						sbReport.append("\n");

						// Valid Until
						Date dValidTo = x509Cert.getNotAfter();
						String sValidTo =
						    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM).format(
						        dValidTo);
						sbReport.append(MessageFormat.format(
						    RB.getString("DKeyStoreReport.report.validuntil"), sValidTo));
						sbReport.append("\n");

						// Public Key (algorithm and key size)
						int iKeySize = KeyPairUtil.getKeyLength(x509Cert.getPublicKey());
						String sKeyAlg = x509Cert.getPublicKey().getAlgorithm();
						String fmtKey =
						    (iKeySize == KeyPairUtil.UNKNOWN_KEY_SIZE)
						        ? "DKeyStoreReport.report.pubkeynosize" : "DKeyStoreReport.report.pubkey";
						sbReport.append(MessageFormat.format(RB.getString(fmtKey), sKeyAlg, iKeySize));
						sbReport.append("\n");

						// Signature Algorithm
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.sigalg"),
						    x509Cert.getSigAlgName()));
						sbReport.append("\n");

						byte[] bCert = x509Cert.getEncoded();

						// SHA-1 fingerprint
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.sha1"),
						    DigestUtil.getMessageDigest(bCert, DigestType.SHA1)));
						sbReport.append("\n");

						// MD5 fingerprint
						sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.md5"),
						    DigestUtil.getMessageDigest(bCert, DigestType.MD5)));
						sbReport.append("\n");

						if (iCnt + 1 < iChainLen)
						{
							sbReport.append("\n");
						}
					}

					if (aliases.hasMoreElements())
					{
						sbReport.append("\n");
					}
				}
			}

			// Return the report
			return sbReport.toString();
		}
		catch (Exception ex)
		{
			throw new IllegalStateException("report exeception", ex);
		}
	}*/

}
