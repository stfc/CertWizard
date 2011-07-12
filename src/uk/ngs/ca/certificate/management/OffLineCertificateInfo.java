/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.Collection;
import java.util.Iterator;
import java.util.Date;
import java.util.Observable;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.util.ArrayList;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import org.apache.log4j.Logger;
//import uk.ngs.ca.info.ExpiredReKey;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.common.ClientKeyStore;

/**
 * Class provides a single/consolidated view on top of the following files by defining
 * methods that query their entries regardless of which file is actually queried:
 * <p>
 * <ol>
 *  <li>'$HOME/.ca/cacertkeystore.pkcs12'  // contains only valid certificates
 *       recognised by the CA (this file is populated when online with creation of
 *       <code>OnLineCertificateInfo</code>).
 *  </li>
 *  <li>'$HOME/.ca/localcertificate.xml'   // contains only CSRs (CSRs are
 *       stored in this file when offline - is this really necessary?)
 *  </li>
 * </ol>
 * <p>
 * Note, on class creation, this class only reads cacertkeystore.pkcs12 and
 * localcertificate.xml files, it does not update/write to either. This class
 * needs lots of attention or maybe even depreciate this class and create a
 * CertificateCSRInfo class that can be used online or offline.
 *
 * @author xw75
 */
public class OffLineCertificateInfo extends Observable {
    private static final Logger myLogger = Logger.getLogger(OffLineCertificateInfo.class);
    private final String CERTIFICATE = "Certificate";
    private final String DN = "DN";
    private final String ALIAS = "Alias";
    

    //private String key_KeyStoreFilePath = null;  // '$HOME/.ca/cakeystore.pkcs12'
    private ClientKeyStore key_keyStore = null;
    private String cert_KeyStoreFilePath = null; // '$HOME/.ca/cacertkeystore.pkcs12'
    private KeyStore cert_KeyStore;
    private String csr_xmlFilePath;  // '$HOME/.ca/localcertificate.xml'
    private Document csrXMLDoc;
    private char[] PASSPHRASE = null;


    // Indicate the combined status of the cert_KeyStore and csrXMLDoc
    // (certs stored in cert_KeyStore, CSRs in csrXMLDoc).
    private enum KEYSTORE_CSR_STATUS {NO_CERTS_CSR, CERT_ONLY, CSR_ONLY, CERT_AND_CSR};


    public OffLineCertificateInfo(char[] passphrase) {
        this.PASSPHRASE = passphrase;
        this.key_keyStore =  ClientKeyStore.getClientkeyStore(passphrase); // create or read '$HOME/.ca/cakeystore.pkcs12'
        String caDir = System.getProperty("user.home") + File.separator + ".ca" + File.separator;
        this.cert_KeyStoreFilePath = caDir + SysProperty.getValue("ngsca.cert.keystore.file");
        initCertKeyStoreFromFile(); //Init this.cert_KeyStore from '$HOME/.ca/cacertkeystore.pkcs12'
        this.csr_xmlFilePath = SysProperty.getLocalCertXMLFilePath("ngsca.cert.xml.file", PASSPHRASE);
        touchAndInitCsrXMLDocFromFile(); // Init csrXMLDoc and csr_xmlFilePath
    }

    /**
     * Init <code>this.cert_KeyStore</code> from '$HOME/.ca/cacertkeystore.pkcs12'
     */
    private void initCertKeyStoreFromFile() {
        try {
            this.cert_KeyStore = PKCS12KeyStoreUnlimited.getInstance();
            if (new File(this.cert_KeyStoreFilePath).exists()) {
                FileInputStream fis = new FileInputStream(this.cert_KeyStoreFilePath);
                cert_KeyStore.load(fis, PASSPHRASE);
                fis.close();
            }
        } catch (IOException iep) {
            iep.printStackTrace();
        } catch (NoSuchAlgorithmException nae) {
            nae.printStackTrace();
        } catch (CertificateException ce) {
            ce.printStackTrace();
         } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } catch (NoSuchProviderException ne) {
            ne.printStackTrace();
        }
    }

    /**
     * Init <code>this.csrXMLDoc</code> from '$HOME/.ca/localcertificate.xml'
     * If file does not exist, create empty template.
     */
    private void touchAndInitCsrXMLDocFromFile() {
         try {
            File file = new File(csr_xmlFilePath);
            if (file.exists()) {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                csrXMLDoc = factory.newDocumentBuilder().parse(new File(csr_xmlFilePath));
                myLogger.debug("[OffLineCertificateInfo] success to access xml file of " + csr_xmlFilePath);
            } else {
                myLogger.error("[OffLineCertificateInfo] failed to find out local xml file");
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OffLineCertificateInfo] failed to access Document. " + ep.toString());
        }
    }

    public X509Certificate getCertificate(int index) {
        String[] aliases = getAliases();
        String alias = aliases[index];
        try {
            return (X509Certificate) cert_KeyStore.getCertificate(alias);
        } catch (KeyStoreException kse) {
            kse.printStackTrace();
            return null;
        }
    }

    private int getKeyStoreCertCount() {
        if (cert_KeyStore == null) {
            return -1;
        } else {
            int number = 0;
            try {
                Enumeration<String> aliases = cert_KeyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String n = aliases.nextElement();
                    if (cert_KeyStore.isKeyEntry(n)) {
                        ++number;
                    }
                }
            } catch (KeyStoreException ke) {
                ke.printStackTrace();
                myLogger.error("[OfflineCertificateInfo] failed to retrieve aliases: " + ke.getMessage());
            }
            return number;
        }
    }

    private int getCSRFileCSRCount() {
        if(!new File(csr_xmlFilePath).exists()){
            return -1;
        }
        int number = 0;
        NodeList list = csrXMLDoc.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            number = list.getLength();
        }
        return number;
    }


    /**
     * Determine what is the status of the CSR file and cert_KeyStore
     */
    private KEYSTORE_CSR_STATUS checkStatus(){
        int numofCerts = getKeyStoreCertCount();
        int numofCsrs = getCSRFileCSRCount();
        if ((numofCerts == -1) && (numofCsrs == -1)) {
            return KEYSTORE_CSR_STATUS.NO_CERTS_CSR;
        }
        if ((numofCerts == -1) && (numofCsrs != -1)) {
            return KEYSTORE_CSR_STATUS.CSR_ONLY;
        }
        if ((numofCerts != -1) && (numofCsrs == -1)) {
            return KEYSTORE_CSR_STATUS.CERT_ONLY;
        }
        if ((numofCerts != -1) && (numofCsrs != -1)) {
            return KEYSTORE_CSR_STATUS.CERT_AND_CSR;
        }
        return KEYSTORE_CSR_STATUS.NO_CERTS_CSR;
    }


    public String getDN(int index) {
        return getAllDNs()[index];
    }

    public String getEmail(int index) {
        // index is zero offset so index=0 refers to 1st item.
        try {
            if (checkStatus() == KEYSTORE_CSR_STATUS.NO_CERTS_CSR) {
                return null;
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_ONLY) {
                return _getEmailfromKeyStoreHelper(index);
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CSR_ONLY) {
                return _getEmailfromCSRFileHelper(index);
            } else if(checkStatus() == KEYSTORE_CSR_STATUS.CERT_AND_CSR){
                if (index  < getKeyStoreCertCount()) {
                    return _getEmailfromKeyStoreHelper(index);
                } else {
                    return _getEmailfromCSRFileHelper(index);
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] exception: " + ep.getMessage());
        }
        return null;
    }

    private String _getEmailfromCSRFileHelper(int index) {
        String alias = getAliases()[index];
        NodeList list = csrXMLDoc.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);
                NodeList list1 = e1.getElementsByTagName(ALIAS);
                Element e2 = (Element) list1.item(0);
                if (e2 == null) {
                    return null;
                }
                if (list1.item(0).getFirstChild().getNodeValue().equals(alias)) {
                    NodeList list2 = e1.getElementsByTagName("Email");
                    Element e3 = (Element) list2.item(0);
                    if (e3 == null) {
                        return null;
                    }
                    return list2.item(0).getFirstChild().getNodeValue();
                }
            }
        }
        return null;
    }


    private String _getEmailfromKeyStoreHelper(int index) {
        // index is zero offset so index=0 refers to 1st item.
        try {
            String alias = getAliases()[index];
            X509Certificate cert = (X509Certificate) cert_KeyStore.getCertificate(alias);
            //we need to decide to retrieve email from DN or from extension of the certificate??????
            //but in here we are retrieveing email from Extension....
            Collection col = cert.getSubjectAlternativeNames();
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
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve algorithm: " + ke.getMessage());
            return null;
        } catch (CertificateParsingException ce) {
            ce.printStackTrace();
            myLogger.error("[OnlineCertificateManager] certificate parsing exception: " + ce.getMessage());
            return null;
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OnlineCertificateManager] exception: " + ep.getMessage());
            return null;
        }
    }

    public String getStatus(int index) {
        // index is zero offset so index=0 refers to 1st item.
        try {
            if (checkStatus() == KEYSTORE_CSR_STATUS.NO_CERTS_CSR) {
                return "---------------";
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_ONLY) {
                if (_isExpired( getEndDate(index) )) {
                    return "Expired";
                } else {
                    return "Valid";
                }
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CSR_ONLY) {
                return "UnSubmitted";
            } else if(checkStatus() == KEYSTORE_CSR_STATUS.CERT_AND_CSR){
                if ( index  <= getKeyStoreCertCount()) {
                    Date date = getEndDate(index);
                    if (_isExpired(date)) {
                        return "Expired";
                    } else {
                        //please note that it may not be right. eg.
                        //if the real status is REVOKED, then here is Valid.
                        return "Valid";
                    }
                } else {
                    return "UnSubmitted";
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] exception: " + ep.getMessage());
        }
        return "------------------";
    }

    public Date getStartDate(int index) {
        // index is zero offset so index=0 refers to 1st item.
        try {
            if (checkStatus() == KEYSTORE_CSR_STATUS.NO_CERTS_CSR) {
                return null;
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_ONLY) {
                // run common code below
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CSR_ONLY) {
                return null;
            } else if(checkStatus() == KEYSTORE_CSR_STATUS.CERT_AND_CSR){
                if (index < getKeyStoreCertCount()) {
                    // run common code below
                } else {
                    return null;
                }
            }
            // not returned, so run common code
            String alias = getAliases()[index];
            X509Certificate cert = (X509Certificate) cert_KeyStore.getCertificate(alias);
            return cert.getNotBefore();
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
        }
        return null;
    }

    public boolean remove(int index) {
         // index is zero offset so index=0 refers to 1st item.
        if (checkStatus() == KEYSTORE_CSR_STATUS.NO_CERTS_CSR) {
            return true;
        } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_ONLY) {
            return _removeCertHelper(index);
        } else if (checkStatus() == KEYSTORE_CSR_STATUS.CSR_ONLY) {
            return _removeCSRHelper(index);
        } else if(checkStatus() == KEYSTORE_CSR_STATUS.CERT_AND_CSR){
            if (index < getKeyStoreCertCount()) {
                return _removeCertHelper(index);
            } else {
                return _removeCSRHelper(index);
            }
        }
        //notify MainWindow
        setChanged();
        notifyObservers(this);
        return false;
    }

    private boolean _removeCertHelper(int index) {
        try {
            String alias = getAliases()[index];
            PrivateKey _privateKey = (PrivateKey) cert_KeyStore.getKey(alias, PASSPHRASE);
            cert_KeyStore.deleteEntry(alias);
            File f = new File(this.cert_KeyStoreFilePath);
            FileOutputStream fos = new FileOutputStream(f);
            cert_KeyStore.store(fos, PASSPHRASE);
            fos.close();
            this.key_keyStore.removeKey(_privateKey);
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
        }
        return false;
    }

    private boolean _removeCSRHelper(int index) {
        String alias = getAliases()[index];
        NodeList list = csrXMLDoc.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);
                NodeList list1 = e1.getElementsByTagName(ALIAS);
                Element e2 = (Element) list1.item(0);
                if (list1.item(0).getFirstChild().getNodeValue().equals(alias)) {
                    Element certElement = (Element) e2.getParentNode();
                    certElement.getParentNode().removeChild(certElement);
                    csrXMLDoc.normalize();
                }
            }
        }
        return _updateXMLFile();
    }

    private boolean _updateXMLFile() {
        try {
            // transform the Document into a String
            DOMSource domSource = new DOMSource(csrXMLDoc);
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
            FileWriter fstream = new FileWriter(csr_xmlFilePath);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(xml);
            out.close();
            csrXMLDoc.normalizeDocument();
            myLogger.debug("[CertificateRequestManager] save xml file successfully");
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[CertificateRequestManager] failed to save xml file: " + ep.toString());
            return false;
        }
    }

    /*public void notifyObserver() {
        //notify MainWindow
        setChanged();
        notifyObservers(this);

    }*/

    public String getFormatStartDate(int index) {
        Date date = getStartDate(index);
        if (date == null) {
            return "-------------";
        } else {
            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String result = formatter.format(date);
            return result;
        }
    }

    public Date getEndDate(int index) {
        // index is zero offset so index=0 refers to 1st item.
        try {
            if (checkStatus() == KEYSTORE_CSR_STATUS.NO_CERTS_CSR) {
                return null;
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_ONLY) {
                // run common code below
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CSR_ONLY) {
                return null;
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_AND_CSR) {
                if (index < getKeyStoreCertCount()) { // we have a cert
                    // run common code below
                } else {
                    return null; // this is a CSR
                }
            }
            // ok, not returned so run common code
            String alias = getAliases()[index];
            X509Certificate cert = (X509Certificate) cert_KeyStore.getCertificate(alias);
            Date date = cert.getNotAfter();
            return date;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
        }
        return null;
    }

    public String getFormatEndDate(int index) {
         // index is zero offset so index=0 refers to 1st item.
        Date date = getEndDate(index);
        if (date == null) {
            return "-------------";
        } else {
            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String result = formatter.format(date);
            return result;
        }
    }

    public String getLifeDays(int index) {
        // index is zero offset so index=0 refers to 1st item.
        try {
            if (checkStatus() == KEYSTORE_CSR_STATUS.NO_CERTS_CSR) {
                return "-------------";
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_ONLY) {
                // Run common code below
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CSR_ONLY) {
                return "----------------";
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_AND_CSR) {
                if (index < getKeyStoreCertCount()) {
                    // Run common code below
                } else {
                    return "--------------";
                }
            }
            // Not returned, so run the common code
            String alias = getAliases()[index];
            X509Certificate cert = (X509Certificate) cert_KeyStore.getCertificate(alias);
            long currentMillis = new Date().getTime();
            long endMillis = cert.getNotAfter().getTime();
            if (endMillis < currentMillis) {
                return "N/A";
            }
            long diffDays = (endMillis - currentMillis) / (24 * 60 * 60 * 1000);
            //the live days would include the extra rekey days.
            return new Long(diffDays).toString();

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        }
        return "----------------";
    }





    public String getRenewDate(int index) {
        // index is zero offset so index=0 refers to 1st item.
        try {
            if (checkStatus() == KEYSTORE_CSR_STATUS.NO_CERTS_CSR) {
                return null;
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_ONLY) {
                // run common code below
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CSR_ONLY) {
                return "-------------------";
            } else if (checkStatus() == KEYSTORE_CSR_STATUS.CERT_AND_CSR) {
                if (index < getKeyStoreCertCount()) {
                    // run common code below
                } else {
                    return "-------------"; // we are referring to a CSR
                }
                // Not returned, so run the common code
                String alias = getAliases()[index];
                X509Certificate cert = (X509Certificate) cert_KeyStore.getCertificate(alias);
                DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
                Date endDate = cert.getNotAfter();
                String result = formatter.format(endDate);
                return result;
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        }
        return "--------------";
    }

    private boolean _isExpired(Date date) {
        long current = new Date().getTime();
        long end = date.getTime();
        if (current < end) {
            return false;
        } else {
            return true;
        }
    }

    public String[] getAliases() {
        ArrayList<String> aliasList = new ArrayList<String>(0);
        if (getKeyStoreCertCount() != -1) {
            try {
                Enumeration<String> aliases = cert_KeyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String n = aliases.nextElement();
                    if (cert_KeyStore.isKeyEntry(n)) {
                        aliasList.add(n);
                    }
                }
            } catch (KeyStoreException ke) {
                ke.printStackTrace();
                myLogger.error("[OfflineCertificateInfo] failed to retrieve aliases: " + ke.getMessage());
            }
        }

        NodeList list = csrXMLDoc.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                NodeList list1 = element.getElementsByTagName(ALIAS);
                if (list1.item(0) == null) return null; // why on earth return null?
                aliasList.add( list1.item(0).getFirstChild().getNodeValue());
            }
        }
        // better to return a list than array
        return aliasList.toArray(new String[aliasList.size()]);
    }


    public String[] getAllDNs() {
        ArrayList<String> dnList = new ArrayList<String>(0);
        // add all the certs from cert_KeyStore
        try {
            if (getKeyStoreCertCount() != -1) {
                Enumeration<String> aliases = cert_KeyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    X509Certificate cert = (X509Certificate) cert_KeyStore.getCertificate(alias);
                    String _dn = cert.getSubjectDN().getName();
                    if (cert_KeyStore.isKeyEntry(alias)) {
                        dnList.add(_dn);
                    }
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] failed to retrieve aliases: " + ke.getMessage());
        }
        // now add all the CSR DNs
        NodeList list = csrXMLDoc.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                NodeList list1 = element.getElementsByTagName(DN);
                if (list1.item(0) == null)  return null; // why on earth return null ?
                dnList.add(list1.item(0).getFirstChild().getNodeValue());
            }
        }
        // better to return a list than array
        return dnList.toArray(new String[dnList.size()]);
    }




}
