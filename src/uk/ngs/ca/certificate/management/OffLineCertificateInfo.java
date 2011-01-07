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
import java.util.Vector;
import java.util.Collection;
import java.util.Iterator;
import java.util.Date;
import java.util.Properties;
import java.util.Observable;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.BufferedWriter;

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
 *
 * @author xw75
 */
public class OffLineCertificateInfo extends Observable {

    private char[] PASSPHRASE = null;
    private boolean ISEXISTKEYPAIR = false;
    private boolean ISEXISTCSRFILE = false;
    static final Logger myLogger = Logger.getLogger(OffLineCertificateInfo.class);
    static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private Properties properties = new Properties();
    private final String FILEPATH = ".ca";
    private String keyStoreFile = null;
    private KeyStore keyStore;
    private String xmlFileName;
    private Document document;
    private String CERTIFICATE = "Certificate";
    private String DN = "DN";
    private String ALIAS = "Alias";

    private ClientKeyStore clientKeyStore = null;

    public OffLineCertificateInfo(char[] passphrase) {
        PASSPHRASE = passphrase;
        clientKeyStore = new ClientKeyStore(passphrase);
        init(passphrase);
        keyStore = getCertKeyStoreFile();
        ISEXISTKEYPAIR = isExistKeyPair();
        ISEXISTCSRFILE = isExistCSRFile();
    }

    public X509Certificate getCertificate(int index) {
        String[] aliases = getAliases();
        String alias = aliases[index];
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            return cert;
        } catch (KeyStoreException kse) {
            kse.printStackTrace();
            return null;
        }
    }

    private int getCertNuminKeyStore() {
        if (keyStore == null) {
            return -1;
        } else if (!ISEXISTKEYPAIR) {
            return -1;
        } else {
            int number = 0;
            try {
                Enumeration aliases = keyStore.aliases();
                Vector vector = new Vector();

                while (aliases.hasMoreElements()) {
                    String n = (String) aliases.nextElement();
                    if (keyStore.isKeyEntry(n)) {
                        vector.addElement(n);
                    }
                }

                number = vector.size();

            } catch (KeyStoreException ke) {
                ke.printStackTrace();
                myLogger.error("[OfflineCertificateInfo] failed to retrieve aliases: " + ke.getMessage());
            } finally {
                return number;
            }
        }
    }

    private int getNuminCSRFile() {
        if (!ISEXISTCSRFILE) {
            return -1;
        } else {
            int number = 0;
            NodeList list = document.getElementsByTagName(CERTIFICATE);
            if (!(list.getLength() == 0)) {
                number = list.getLength();
            }
            return number;
        }
    }

    /**
     * find out certificate status by the index.
     * @return -1 if there is no certificate and csr, 0 if there is only certificate in keystore,
     * 1 if there is only csr, 2 if there are keystore and csr.
     */
    private int _checkStatus() {
        int numofCerts = getCertNuminKeyStore();
        int numofCsrs = getNuminCSRFile();
        if ((numofCerts == -1) && (numofCsrs == -1)) {
            return -1;
        }
        if ((numofCerts == -1) && (numofCsrs != -1)) {
            return 1;
        }
        if ((numofCerts != -1) && (numofCsrs == -1)) {
            return 0;
        }
        if ((numofCerts != -1) && (numofCsrs != -1)) {
            return 2;
        }
        return -1;
    }

    public String getDN(int index) {
        return getAllDNs()[index];
    }

    public String getEmail(int index) {
        try {
            if (_checkStatus() == -1) {
                return null;
            } else if (_checkStatus() == 0) {
                return _getEmailfromKeyStore(index);
            } else if (_checkStatus() == 1) {
                return _getEmailfromCSRFile(index);
            } else {
                int _index = index + 1;
                if (_index <= getCertNuminKeyStore()) {
                    return _getEmailfromKeyStore(index);
                } else {
                    return _getEmailfromCSRFile(index);
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] exception: " + ep.getMessage());
            return null;
        }

    }

    public String getStatus(int index) {
        try {
            if (_checkStatus() == -1) {
                return "---------------";
            } else if (_checkStatus() == 0) {
                Date date = getEndDate(index);
                if (_isExpired(date)) {
                    return "Expired";
                } else {
                    return "Valid";
                }
            } else if (_checkStatus() == 1) {
                return "UnSubmitted";
            } else {
                int _index = index + 1;
                if (_index <= getCertNuminKeyStore()) {
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
            return "------------------";
        }
    }

    public Date getStartDate(int index) {
        try {
            if (_checkStatus() == -1) {
                return null;
            } else if (_checkStatus() == 0) {
                String alias = getAliases()[index];
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                Date date = cert.getNotBefore();

                return date;
            } else if (_checkStatus() == 1) {
                return null;
            } else {
                int _index = index + 1;
                if (_index <= getCertNuminKeyStore()) {
                    String alias = getAliases()[index];
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    Date date = cert.getNotBefore();
                    return date;
                } else {
                    return null;
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
            return null;
        }
    }

    public boolean remove(int index) {
        if (_checkStatus() == -1) {
            return true;
        } else if (_checkStatus() == 0) {
            try {
                String alias = getAliases()[index];
                PrivateKey _privateKey = (PrivateKey)keyStore.getKey(alias, PASSPHRASE);

                keyStore.deleteEntry(alias);

                File f = new File(keyStoreFile);
                FileOutputStream fos = new FileOutputStream(f);
                keyStore.store(fos, PASSPHRASE);
                fos.close();

                boolean b = clientKeyStore.removeKey(_privateKey);
                return true;

            } catch (Exception ep) {
                ep.printStackTrace();
                return false;
            }
        } else if (_checkStatus() == 1) {
            String alias = getAliases()[index];

            NodeList list = document.getElementsByTagName(CERTIFICATE);
            if (!(list.getLength() == 0)) {
                for (int i = 0; i < list.getLength(); i++) {
                    Element e1 = (Element) list.item(i);
                    NodeList list1 = e1.getElementsByTagName(ALIAS);
                    Element e2 = (Element) list1.item(0);
                    if (list1.item(0).getFirstChild().getNodeValue().equals(alias)) {
                        Element certElement = (Element) e2.getParentNode();
                        certElement.getParentNode().removeChild(certElement);
                        document.normalize();
                    }
                }
            }
            return _updateXMLFile();
        } else {
            int _index = index + 1;
            if (_index <= getCertNuminKeyStore()) {
                try {
                    String alias = getAliases()[index];
                    PrivateKey _privateKey = (PrivateKey)keyStore.getKey(alias, PASSPHRASE);

                    keyStore.deleteEntry(alias);

                    File f = new File(keyStoreFile);
                    FileOutputStream fos = new FileOutputStream(f);
                    keyStore.store(fos, PASSPHRASE);
                    fos.close();

                    boolean b = clientKeyStore.removeKey(_privateKey);
                    return true;

                } catch (Exception ep) {
                    ep.printStackTrace();
                    return false;
                }
            } else {
                String alias = getAliases()[index];

                NodeList list = document.getElementsByTagName(CERTIFICATE);
                if (!(list.getLength() == 0)) {
                    for (int i = 0; i < list.getLength(); i++) {
                        Element e1 = (Element) list.item(i);
                        NodeList list1 = e1.getElementsByTagName(ALIAS);
                        Element e2 = (Element) list1.item(0);
                        if (list1.item(0).getFirstChild().getNodeValue().equals(alias)) {
                            Element certElement = (Element) e2.getParentNode();
                            certElement.getParentNode().removeChild(certElement);
                            document.normalize();
                        }
                    }
                }
                return _updateXMLFile();
            }

        }

    }

    private boolean _updateXMLFile() {
        try {

            // transform the Document into a String
            DOMSource domSource = new DOMSource(document);
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

            FileWriter fstream = new FileWriter(xmlFileName);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(xml);
            out.close();

            document.normalizeDocument();

            myLogger.debug("[CertificateRequestManager] save xml file successfully");
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[CertificateRequestManager] failed to save xml file: " + ep.toString());
            return false;
        }
    }

    public void notifyObserver() {
        //notify MainWindow
        setChanged();
        notifyObservers(this);

    }

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
        try {
            if (_checkStatus() == -1) {
                return null;
            } else if (_checkStatus() == 0) {
                String alias = getAliases()[index];
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                Date date = cert.getNotAfter();
                return date;
            } else if (_checkStatus() == 1) {
                return null;
            } else {
                int _index = index + 1;
                if (_index <= getCertNuminKeyStore()) {
                    String alias = getAliases()[index];
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    Date date = cert.getNotAfter();
                    return date;
                } else {
                    return null;
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
            return null;
        }
    }

    public String getFormatEndDate(int index) {
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
        try {
            if (_checkStatus() == -1) {
                return "-------------";
            } else if (_checkStatus() == 0) {
                String alias = getAliases()[index];
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                /*
                long startMillis = cert.getNotBefore().getTime();
                long endMillis = cert.getNotAfter().getTime();
                if (endMillis < startMillis) {
                return "N/A";
                }
                 */
                long currentMillis = new Date().getTime();
                long endMillis = cert.getNotAfter().getTime();
                if (endMillis < currentMillis) {
                    return "N/A";
                }
                long diffDays = (endMillis - currentMillis) / (24 * 60 * 60 * 1000);
                //the live days would include the extra rekey days.
                return new Long(diffDays).toString();

            } else if (_checkStatus() == 1) {
                return "----------------";
            } else {
                int _index = index + 1;
                if (_index <= getCertNuminKeyStore()) {
                    String alias = getAliases()[index];
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    /*
                    long startMillis = cert.getNotBefore().getTime();
                    long endMillis = cert.getNotAfter().getTime();
                    if (endMillis < startMillis) {
                    return "N/A";
                    }
                    long diffDays = (endMillis - startMillis) / (24 * 60 * 60 * 1000);
                     */
                    long currentMillis = new Date().getTime();
                    long endMillis = cert.getNotAfter().getTime();
                    if (endMillis < currentMillis) {
                        return "N/A";
                    }
                    long diffDays = (endMillis - currentMillis) / (24 * 60 * 60 * 1000);
                    //the live days would include the extra rekey days.
                    return new Long(diffDays).toString();

                } else {
                    return "--------------";
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            return "----------------";
        }
    }

    public String getRenewDate(int index) {
        try {
            if (_checkStatus() == -1) {
                return null;
            } else if (_checkStatus() == 0) {
                String alias = getAliases()[index];
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
                Date endDate = cert.getNotAfter();
                String result = formatter.format(endDate);
                return result;
            } else if (_checkStatus() == 1) {
                return "-------------------";
            } else {
                int _index = index + 1;
                if (_index <= getCertNuminKeyStore()) {
                    String alias = getAliases()[index];
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                    DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
                    Date endDate = cert.getNotAfter();
                    String result = formatter.format(endDate);
                    return result;
                } else {
                    return "-------------";
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            return "--------------";
        }
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

    private String _getEmailfromKeyStore(int index) {
        try {
            String alias = getAliases()[index];
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
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

    private String _getEmailfromCSRFile(int index) {

        String alias = getAliases()[index];
        return _getCSRValue(alias, "Email");
    }

    private String _getCSRValue(String alias, String value) {
        NodeList list = document.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);

                NodeList list1 = e1.getElementsByTagName(ALIAS);
                Element e2 = (Element) list1.item(0);
                if (e2 == null) {
                    return null;
                }
                if (list1.item(0).getFirstChild().getNodeValue().equals(alias)) {
                    NodeList list2 = e1.getElementsByTagName(value);
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

    private String _getCertValue(String dn, String value) {
        NodeList list = document.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);

                NodeList list1 = e1.getElementsByTagName(DN);
                Element e2 = (Element) list1.item(0);
                if (e2 == null) {
                    return null;
                }
                if (list1.item(0).getFirstChild().getNodeValue().equals(dn)) {
                    NodeList list2 = e1.getElementsByTagName(value);
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

    public String[] getAliases() {
        String[] certNames = null;
        String[] csrNames = null;
        if (getCertNuminKeyStore() != -1) {

            try {
                Enumeration aliases = keyStore.aliases();
                Vector vector = new Vector();
                while (aliases.hasMoreElements()) {
                    String n = (String) aliases.nextElement();
                    if (keyStore.isKeyEntry(n)) {
                        vector.addElement(n);
                    }
                }
                certNames = new String[vector.size()];
                for (int i = 0; i < certNames.length; i++) {
                    certNames[i] = (String) vector.elementAt(i);
                }
            } catch (KeyStoreException ke) {
                ke.printStackTrace();
                myLogger.error("[OfflineCertificateInfo] failed to retrieve aliases: " + ke.getMessage());
            }
        }

        NodeList list = document.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            csrNames = new String[list.getLength()];
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                NodeList list1 = element.getElementsByTagName(ALIAS);
                Element e1 = (Element) list1.item(0);
                if (e1 == null) {
                    return null;
                }
                csrNames[i] = list1.item(0).getFirstChild().getNodeValue();
            }
        }

        if (certNames == null) {
            if (csrNames == null) {
                return null;
            } else {
                return csrNames;
            }
        } else {
            if (csrNames == null) {
                return certNames;
            } else {
                int length = certNames.length + csrNames.length;
                String[] result = new String[length];
                for (int i = 0; i < certNames.length; i++) {
                    result[i] = certNames[i];
                }
                for (int i = 0; i < csrNames.length; i++) {
                    result[i + certNames.length] = csrNames[i];
                }
                return result;
            }
        }
    }

    public String[] getAllDNs() {
        String[] certNames = null;
        String[] csrNames = null;
        if (getCertNuminKeyStore() != -1) {

            try {
                Enumeration aliases = keyStore.aliases();
                Vector vector = new Vector();
                while (aliases.hasMoreElements()) {
                    String n = (String) aliases.nextElement();
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(n);
                    String _dn = cert.getSubjectDN().getName();
                    if (keyStore.isKeyEntry(n)) {
                        vector.addElement(_dn);
                    }
                }
                certNames = new String[vector.size()];
                for (int i = 0; i < certNames.length; i++) {
                    certNames[i] = (String) vector.elementAt(i);
                }
            } catch (KeyStoreException ke) {
                ke.printStackTrace();
                myLogger.error("[OfflineCertificateInfo] failed to retrieve aliases: " + ke.getMessage());
            }
        }

        NodeList list = document.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            csrNames = new String[list.getLength()];
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                NodeList list1 = element.getElementsByTagName(DN);
                Element e1 = (Element) list1.item(0);
                if (e1 == null) {
                    return null;
                }
                csrNames[i] = list1.item(0).getFirstChild().getNodeValue();
            }
        }

        if (certNames == null) {
            if (csrNames == null) {
                return null;
            } else {
                return csrNames;
            }
        } else {
            if (csrNames == null) {
                return certNames;
            } else {
                int length = certNames.length + csrNames.length;
                String[] result = new String[length];
                for (int i = 0; i < certNames.length; i++) {
                    result[i] = certNames[i];
                }
                for (int i = 0; i < csrNames.length; i++) {
                    result[i + certNames.length] = csrNames[i];
                }
                return result;
            }
        }

    }

    private boolean isExistCSRFile() {
        boolean isExist = false;

        //we need to create a new method of SysProperty.getLocalCertXMLFilePath(String s)
        xmlFileName = SysProperty.getLocalCertXMLFilePath("ngsca.cert.xml.file", PASSPHRASE);

        if (xmlFileName == null) {
            myLogger.error("[OffLineCertificateInfo] failed to find out the certificate xml file.");
            return isExist;
        }

        try {
            File file = new File(xmlFileName);
            if (file.exists()) {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                // Create the builder and parse the file
                document = factory.newDocumentBuilder().parse(new File(xmlFileName));
//below line is error!
//                document = factory.newDocumentBuilder().parse(xmlFileName);
                myLogger.debug("[OffLineCertificateInfo] success to access xml file of " + xmlFileName);
                isExist = true;
            } else {
                myLogger.error("[OffLineCertificateInfo] failed to find out local xml file");
                isExist = false;
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OffLineCertificateInfo] failed to access Document. " + ep.toString());
            isExist = false;
        } finally {
            return isExist;
        }
    }

    private boolean isExistKeyPair() {

        String fileName = SysProperty.getValue("ngsca.key.keystore.file");

        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
            return false;
        } else {
            homePath = homePath + System.getProperty("file.separator") + fileName;
            if (!new File(homePath).exists()) {
                try {
                    new File(homePath).createNewFile();
                    return false;
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                    return false;
                }
            } else {
                if (new File(homePath).length() == 0) {
                    return false;
                }
                //maybe we need to check if there is keypair in the file.
                return true;
            }
        }
    }

    private void init(char[] passphrase) {
        myLogger.debug("[OfflineCertificateInfo] init...");
        try {

            keyStore = PKCS12KeyStoreUnlimited.getInstance();
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

    private KeyStore getCertKeyStoreFile() {
        KeyStore _keyStore = null;

        myLogger.debug("[OfflineCertificateInfo] get keystore ...");
        String key = "ngsca.cert.keystore.file";
        String value = properties.getProperty(key);
        if (value == null) {
            myLogger.error("[OfflineCertificateInfo] could not find out the value of " + key + " in your property file.");
        }
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + FILEPATH;
        homePath = homePath + System.getProperty("file.separator") + value;
        keyStoreFile = homePath;
        try {
            if (new File(keyStoreFile).exists()) {
                FileInputStream fis = new FileInputStream(keyStoreFile);
                keyStore.load(fis, PASSPHRASE);
                fis.close();
                _keyStore = keyStore;
            }
        } catch (IOException iep) {
            iep.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] failed to read keystore file from: " + keyStoreFile + ". with the message: " + iep.getMessage());
        } catch (NoSuchAlgorithmException nae) {
            nae.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] algorithm error: " + nae.getMessage());
        } catch (CertificateException ce) {
            ce.printStackTrace();
            myLogger.error("[OfflineCertificateInfo] certificate error: " + ce.getMessage());
        } finally {
            return _keyStore;
        }
    }


}
