/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

import org.apache.log4j.Logger;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.File;
import java.io.FileWriter;
import java.io.BufferedWriter;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.stream.StreamResult;

import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.common.EncryptUtil;
/**
 *
 * @author xw75
 */
public class CertificateRequestManager {

    static final Logger myLogger = Logger.getLogger(CertificateRequestManager.class);
    String xmlFileName;
    public Document document;
    public static String CERTIFICATE = "Certificate";
    public static String CERTIFICATES = "Certificates";
    public static String ITEM = "Item";
    public static String DN = "DN";
    public static String STATUS = "Status";
    public static String PRIVATEKEY = "PrivateKey";
    public static String PUBLICKEY = "PublicKey";
    public static String REQID = "ReqID";
    public static String CSR = "CSR";
    public static String EMAIL = "Email";
    public static String PIN = "PIN";

    public CertificateRequestManager( char[] passphrase ) {
        init( passphrase );
    }

    private void init( char[] passphrase ) {
        xmlFileName = SysProperty.getLocalCertXMLFilePath("ngsca.cert.xml.file", passphrase);
        if (xmlFileName == null) {
            myLogger.error("[CertificateRequestManager] failed to find out the certificate xml file.");
        } else {
        }
        try {
            File file = new File(xmlFileName);
            if (file.exists()) {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                // Create the builder and parse the file
                document = factory.newDocumentBuilder().parse(new File(xmlFileName));
                myLogger.debug("[CertificateRequestManager] success to access xml file of " + xmlFileName);
            } else {
                myLogger.error("[CertificateRequestManager] failed to find out local xml file");
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[CertificateRequestManager] failed to access Document. " + ep.toString());
        }
    }

    /**
     * Returns all the DNs restored in the configure xml file.
     * @return distinguish names as array of string.
     */
    public String[] getAllDNs() {
        NodeList list = document.getElementsByTagName(CERTIFICATE);
        String[] dns = null;
        if (!(list.getLength() == 0)) {
            dns = new String[list.getLength()];
            for (int i = 0; i < list.getLength(); i++) {
                Element element = (Element) list.item(i);
                NodeList list1 = element.getElementsByTagName(DN);
                Element e1 = (Element) list1.item(0);
                if (e1 == null) {
                    return null;
                }
                dns[i] = list1.item(0).getFirstChild().getNodeValue();
            }
        }
        return dns;
    }

    /**
     * returns DN.
     * @param index index. the minimum value is 1.
     * @return DN
     *
     */
    public String getDN(int index) {
        String[] dns = null;
        dns = getAllDNs();
        if (dns == null) {
            return null;
        } else {
            return dns[index - 1];
        }
    }

    /**
     * Returns certificate status
     * @param dn distinguish name
     * @return certificate status
     */
    public String getStatus(String dn) {
        return getCertValue(dn, STATUS);
    }

    /**
     * Returns email
     * @param dn distinguish name
     * @return email
     */
    public String getEmail( String dn ){
        return getCertValue(dn, EMAIL);
    }

    /**
     * Returns certificate request id
     * @param dn distinguish name
     * @return certificate request id
     */
    public String getRequestID(String dn) {
        return getCertValue(dn, REQID);
    }


    /**
     * Returns private key.
     * @param passphrase passphrase to encrypt the private key
     * @return private key string
     */
    public PrivateKey getPrivateKey(char[] passphrase) {
        NodeList list = document.getElementsByTagName(PRIVATEKEY);
        String encryptedPrivateKey = list.item(0).getFirstChild().getNodeValue();

        PrivateKey privateKey = EncryptUtil.getDecryptedPrivateKey(passphrase, encryptedPrivateKey);

        return privateKey;
    }

    /**
     * returns the public key string from the xml file
     *
     * @return public key
     *
     */
    public PublicKey getPublicKey() {
        NodeList list = document.getElementsByTagName(PUBLICKEY);
        String encodedKey = list.item(0).getFirstChild().getNodeValue();

        return EncryptUtil.getPublicKey(encodedKey);

    }

    /**
     * returns CSR PEM string.
     *
     * @param dn distinguish name
     * @param passphrase passphrase to encrypt the csr
     * @return CSR pem in string
     */
    public String getCSR(String dn, char[] passphrase) {
        String csr = null;
        csr = getCertValue(dn, CSR);

        return csr;
    }

    /**
     * addup the status. if there is no DN element, then create a certificate elemenet with the DN
     * @param dn DN
     * @param value status value
     * @return true if successfully, otherwise false
     */
    public boolean addStatus(String dn, String value) {
        return setupCertValue(dn, STATUS, value);
    }

    /**
     * adds up a encrypted private key. if theres is no DN element, then create a new certificate element with the dn.
     *
     * @param dn DN
     * @param passphrase passphrase to encrypt the private key
     * @param private key value
     * @return true if successfully, otherwise false
     */
    public boolean addPrivateKey(String dn, char[] passphrase, PrivateKey privateKey) {
        boolean result = true;
        String value = EncryptUtil.getEncryptedPrivateKey(passphrase, privateKey);
        return setupCertValue(dn, PRIVATEKEY, value);
    }

    /**
     * adds up a public key. if theres is no DN element, then create a new certificate element with the dn.
     *
     * @param dn DN
     * @param public key
     * @return true if successfully, otherwise false
     */
    public boolean addPublicKey(String dn, PublicKey publicKey) {
        String value = publicKey.toString();
        return setupCertValue(dn, PUBLICKEY, value);
    }

    /**
     * adds up request id. if there is no dn element, then create a new certificate element with the dn.
     * @param dn DN
     * @param reqIDValue request id
     * @return true if successfully, otherwise false
     */
    public boolean addReqID(String dn, String reqIDValue) {
        return setupCertValue(dn, REQID, reqIDValue);
    }

    public boolean addEmail(String dn, String emailValue) {
        return setupCertValue(dn, EMAIL, emailValue);
    }

    public boolean addAlias( String dn, String alias ){
        return setupCertValue( dn, "Alias", alias );
    }

    public boolean addPIN( String dn, String pin ){
        return setupCertValue( dn, PIN, pin );
    }

    /** adds up a encrypted csr. if theres is no DN element, then create a new certificate element with the dn.
     *
     * @param dn DN
     * @param csrValue CSR
     * @return true if successfully, otherwise false
     */
    public boolean addCSR(String dn, String csrValue) {
        return setupCertValue(dn, CSR, csrValue);
    }

    /**
     * Removes CSR record from XML document
     *
     * @param dn value of DN
     * 
     */
    public void remove(String dn) {

        NodeList list = document.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);
                NodeList list1 = e1.getElementsByTagName(DN);
                Element e2 = (Element) list1.item(0);
                if (list1.item(0).getFirstChild().getNodeValue().equals(dn)) {
                    Element certElement = (Element)e2.getParentNode();
                    certElement.getParentNode().removeChild(certElement);

                    document.normalize();
                }
            }
        }
    }

    /**
     * saves the xml configure file
     *
     * @return true if successfully, otherwise false
     */
    public boolean saveFile() {
        //to save the updated document in xml file.
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
/*
    private PrivateKey getDecryptedPrivateKey(char[] passphrase, String value) {
        PBEKeySpec pbeSpec = new PBEKeySpec(passphrase);
        PBEParameterSpec defParams = new PBEParameterSpec(SALT, ITERATIONCOUNT);

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(ENCRYPTIONALGORITHM);
            params.init(defParams);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ENCRYPTIONALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTIONALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyFact.generateSecret(pbeSpec), params);
            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(Base64.decode(value));
            PKCS8EncodedKeySpec keySpec = pInfo.getKeySpec(cipher);

            KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

//                String decryptedValue = new String(Base64.decode(pInfo.getEncoded()));
            return privKey;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }
*/
/*
    private String getEncryptedPrivateKey(char[] passphrase, PrivateKey privateKey) {
        PBEParameterSpec defParams = new PBEParameterSpec(SALT, ITERATIONCOUNT);
        try {

            AlgorithmParameters params = AlgorithmParameters.getInstance(ENCRYPTIONALGORITHM);
            params.init(defParams);
            PBEKeySpec pbeSpec = new PBEKeySpec(passphrase);

            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ENCRYPTIONALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTIONALGORITHM);
            cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), params);
            byte[] wrappedKey = cipher.wrap(privateKey);

            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(params, wrappedKey);
            String encryptedKey = new String(Base64.encode(pInfo.getEncoded()));

            return encryptedKey;

        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }
*/

    private boolean setupCertValue(String dn, String name, String value) {
        NodeList list = document.getElementsByTagName(CERTIFICATE);
        if (!(list.getLength() == 0)) {
            for (int i = 0; i < list.getLength(); i++) {
                Element e1 = (Element) list.item(i);
                NodeList list1 = e1.getElementsByTagName(DN);
                Element e2 = (Element) list1.item(0);
                if (list1.item(0).getFirstChild().getNodeValue().equals(dn)) {
                    NodeList list2 = e1.getElementsByTagName(name);

                    Element e3 = (Element) list2.item(0);
                    if (e3 == null) {
                        Element newElement = document.createElement(name);
                        newElement.appendChild(document.createTextNode(value));
                        e1.appendChild(newElement);
                        return true;
                    } else {
                        list2.item(0).setTextContent(value);
                        return true;
                    }
                }
            }
            createElement(dn, name, value);
            return true;
        } else {
            createElement(dn, name, value);
            return true;
        }
    }

    private void createElement(String dn, String name, String value) {

        Element certElement = document.createElement(CERTIFICATE);
        Element dnElement = document.createElement(DN);
        Element newElement = document.createElement(name);

        dnElement.appendChild(document.createTextNode(dn));
        newElement.appendChild(document.createTextNode(value));

        certElement.appendChild(dnElement);
        certElement.appendChild(newElement);

        NodeList list = document.getElementsByTagName(CERTIFICATES);
        Element certsElement = (Element) list.item(0);
        certsElement.appendChild(certElement);
    }

    private String getCertValue(String dn, String value) {
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


}
