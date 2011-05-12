/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.tools.property;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.BufferedWriter;

import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Properties;
import java.util.Date;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Element;

import java.security.PrivateKey;
import java.security.KeyPair;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.bouncycastle.openssl.PEMReader;

import org.apache.log4j.Logger;


import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * This class manages the attributes which recorede in the property file.
 * @author xw75
 */
public class SysProperty {

    static final Logger myLogger = Logger.getLogger(SysProperty.class);
    static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private static boolean isInitialized = false;
    private static Properties properties = new Properties();
    private static final String FILEPATH = ".ca";

    /**
     *  Returns property value
     * @param key property key
     * @return value of the key
     */
    public static String getValue(String key) {
        if (!SysProperty.isInitialized) {
            SysProperty.init();
        }

        String value = properties.getProperty(key);
        if (value == null) {
            myLogger.error("[SysProperty] could not find out the value of " + key + " in your property file.");
        }
        return value;
    }

    /**
     * Returns configure xml file path. If there is no file, then create a template one.
     * @param key property key
     * @param passphrase passphrase
     * @return configure xml file path
     */
    public static String getLocalCertXMLFilePath(String key, char[] passphrase) {
        myLogger.debug("[SysProperty] getLocalXMLFilePath ...");
        File myFile;
        if (!SysProperty.isInitialized) {
            SysProperty.init();
        }
        String value = properties.getProperty(key);
        if (value == null) {
            myLogger.error("[SysProperty] could not find out the value of " + key + " in your property file.");
            return null;
        }

        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + FILEPATH;
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
            String _homePath = homePath + System.getProperty("file.separator") + value;
            try {
                new File(_homePath).createNewFile();
                boolean result = SysProperty.createTemplateFile(_homePath, passphrase);
            } catch (IOException ioe) {
                ioe.printStackTrace();
                myLogger.error("[SysProperty] failed to create file ");
                return null;
            }
        }

        homePath = homePath + System.getProperty("file.separator") + value;
        if (!new File(homePath).exists()) {
            try {
                new File(homePath).createNewFile();
                SysProperty.createTemplateFile(homePath, passphrase);
            } catch (IOException ioe) {
                ioe.printStackTrace();
                myLogger.error("[SysProperty] failed to create file");
                return null;
            }
        }

        // check if the size of file is zero, if yes, then remove it and create a new template file.
        if (new File(homePath).length() == 0) {
            SysProperty.createTemplateFile(homePath, passphrase);
        }

        return homePath;
    }

    private static boolean createTemplateFile(String filePath, char[] passphrase) {
        try {

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            DOMImplementation impl = builder.getDOMImplementation();

            Document doc = impl.createDocument(null, null, null);
            Element rootElement = doc.createElement("Certificates");

            doc.appendChild(rootElement);
            // transform the Document into a String
            DOMSource domSource = new DOMSource(doc);
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

            FileWriter fstream = new FileWriter(filePath);
            BufferedWriter out = new BufferedWriter(fstream);
            out.write(xml);
            out.close();
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[SysProperty]failed to create a template file ");
            return false;
        }
        return true;

    }

    public static String setupTrustStore() {
        String message = null;
        X509Certificate cert = null;
        KeyPair keypair = null;
        PrivateKey privateKey = null;

        KeyStore keyStore = null;

        final String password = SysProperty.getValue("ngsca.cert.truststore.password");

        X509Certificate[] chain = null;

        try {
            /*
             * we need to find out if Bouncycastle supports JKS format.
             * if we adopt java keystore, the password is limited within 7 characters
             * if no importing unlimited policy file.
             */
            keyStore = KeyStore.getInstance("JKS", "SUN");

            keyStore.load(null, null);
        } catch (Exception ep) {
            ep.printStackTrace();
            message = "error to create a trustStore.";
        }

        try {

            InputStream certInput = SysProperty.class.getResourceAsStream("/uk/ngs/ca/tools/property/hostcert.pem");

            Writer writer = new StringWriter();
            char[] buffer = new char[1024];
            Reader reader = new BufferedReader(new InputStreamReader(certInput, "UTF-8"));
            int n;
            while ((n = reader.read(buffer)) != -1) {
                writer.write(buffer, 0, n);
            }
            certInput.close();
            String hostCertString = writer.toString();

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource();
            is.setCharacterStream(new java.io.StringReader(hostCertString));
            Document document = db.parse(is);

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/hostcerts/hostcert/text()");
            Object result = expr.evaluate(document, XPathConstants.NODESET);
            NodeList nodes = (NodeList) result;
            chain = new X509Certificate[nodes.getLength()];
            for (int i = 0; i < nodes.getLength(); i++) {
                String _hostCertString = nodes.item( i ).getNodeValue();
                StringReader certStringReader = new StringReader( _hostCertString );
                PEMReader certPemReader = new PEMReader(certStringReader);
                cert = (X509Certificate) certPemReader.readObject();
                chain[ i ] = cert;
            }


        } catch (Exception ep) {
            message = "There is wrong to read /uk/ngs/ca/tools/property/hostcert.pem.";
            ep.printStackTrace();
        }
        long _alias = new Date().getTime();
        String my_alias = new Long(_alias).toString();
        try {

            for( int i = 0; i < chain.length; i++ ){
                long __alias = new Date().getTime();
                String my__alias = new Long(__alias).toString();
                //sleep 10mss to get different alias.
                Thread.sleep(10);
                keyStore.setCertificateEntry(my__alias, chain[ i ]);
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            message = "error to restore keypair in the trustStore.";
        }

        String key = "ngsca.truststore.file";
        String value = SysProperty.getValue(key);
        if (value == null) {
            message = "There is no trust store file name. Please check out config.properties.";
        }

        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + value;

        String keyStoreFile = homePath;

        try {

            //create a new file.
                File f = new File(keyStoreFile);
                FileOutputStream fos = new FileOutputStream(f);
                keyStore.store(fos, password.toCharArray());
                fos.close();
        } catch (Exception ep) {
            ep.printStackTrace();

            message = "A wrong happens when create a trustStore on the USER_HOME/.ca/";
        }
        return message;
    }

    public static String removed_setupTrustStore() {
        String message = null;
        X509Certificate cert = null;
        KeyPair keypair = null;
        PrivateKey privateKey = null;

        KeyStore keyStore = null;

        final String password = SysProperty.getValue("ngsca.cert.truststore.password");

        try {
            /*
             * we need to find out if Bouncycastle supports JKS format.
             * if we adopt java keystore, the password is limited within 7 characters
             * if no importing unlimited policy file.
             */
            keyStore = KeyStore.getInstance("JKS", "SUN");

            keyStore.load(null, null);
        } catch (Exception ep) {
            ep.printStackTrace();
            message = "error to create a trustStore.";
        }

        try {
            InputStream certInput = SysProperty.class.getResourceAsStream("/uk/ngs/ca/tools/property/hostcert.pem");
            InputStreamReader certInputReader = new InputStreamReader(certInput);
            PEMReader certPemReader = new PEMReader(certInputReader);

            cert = (X509Certificate) certPemReader.readObject();
            certInput.close();
        } catch (Exception ep) {
            message = "There is wrong to read /uk/ngs/ca/tools/property/hostcert.pem.";
            ep.printStackTrace();
        }

        X509Certificate[] chain = new X509Certificate[1];
        chain[ 0 ] = cert;
        long _alias = new Date().getTime();
        String my_alias = new Long(_alias).toString();
        try {
            /*
             * only publickey is restored in client ketstore.
             */
            keyStore.setCertificateEntry(my_alias, cert);
        } catch (Exception ep) {
            ep.printStackTrace();
            message = "error to restore keypair in the trustStore.";
        }

        String key = "ngsca.truststore.file";
        String value = SysProperty.getValue(key);
        if (value == null) {
            message = "There is no trust store file name. Please check out config.properties.";
        }

        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + value;

        String keyStoreFile = homePath;

        try {
            
            //create a new file.
                File f = new File(keyStoreFile);
                FileOutputStream fos = new FileOutputStream(f);
                keyStore.store(fos, password.toCharArray());
                fos.close();
        } catch (Exception ep) {
            ep.printStackTrace();

            message = "A wrong happens when create a trustStore on the USER_HOME/.ca/";
        }
        return message;
    }

    private static void init() {
        myLogger.debug("[SysProperty] init...");
        try {
            InputStream input = SysProperty.class.getResourceAsStream(PROP_FILE);
            properties.load(input);
            input.close();
            isInitialized = true;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            myLogger.error("[SysProperty] Property file is failed to load.");
        }
    }

}
