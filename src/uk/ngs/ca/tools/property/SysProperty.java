/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.tools.property;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
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
import java.util.logging.Level;

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
 * This class manages the attributes which recorded in the property file.
 * @author xw75
 */
public class SysProperty {

    private static final Logger myLogger = Logger.getLogger(SysProperty.class);
    private static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private static boolean isInitialized = false;
    private static Properties properties = new Properties();
    private static final String FILEPATH = ".ca";

    private static int timeoutMilliSecs = 8000; 
    
    /**
     * Get the timeout in millisecs for the http(s) connections.
     * @return 
     */
    public static int getTimeoutMilliSecs(){
        return timeoutMilliSecs; 
    }
    
    /**
     * Set the timeout in milliseconds for the http(s) connections. 
     * @param milliSecs 
     */
    public static void setTimeoutMilliSecs(int milliSecs){
        timeoutMilliSecs = milliSecs; 
    }
        
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
           throw new IllegalStateException("[SysProperty] could not find out the value of " + key + " in your property file.");
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
        //File myFile;
        if (!SysProperty.isInitialized) {
            SysProperty.init();
        }
        String value = properties.getProperty(key);
        if (value == null) {
            throw new IllegalStateException("[SysProperty] could not find out the value of " + key + " in your property file.");
        }

        /*String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + FILEPATH;
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
            String _homePath = homePath + System.getProperty("file.separator") + value;
            try {
                new File(_homePath).createNewFile();
                //boolean result = SysProperty.createTemplateFile(_homePath, passphrase);
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
                SysProperty.createTemplateFile(homePath);
            } catch (IOException ioe) {
                ioe.printStackTrace();
                myLogger.error("[SysProperty] failed to create file");
                return null;
            }
        }*/

        String absPath = System.getProperty("user.home") + File.separator + FILEPATH + File.separator + value;
        // check if the size of file is zero, if yes, then remove it and create a new template file.
        if ( !(new File(absPath).exists()) || (new File(absPath).length() == 0)) {
            SysProperty.createTemplateFile(absPath);
        }

        return absPath;
    }

    private static boolean createTemplateFile(String filePath) {
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

    /**
     * Create the truststore.jks file on disk (typically under
     * '$USER_HOME/.ca/truststore.jks' unless otherwise specified in the
     * configure.properties file). This KeyStore is used to establish SSL with the
     * CA rest server.
     *
     * @throws IllegalStateException if any problem occurs creating and
     * deploying the trustore.jks file.
     */
    public static void setupTrustStore() {
          
        // 1) read the hostcert.pem and write it to the hostCertString String
        // ==================================================================
        String hostCertString = null;
        InputStream certInput = null;
        Writer writer = null;
        Reader reader = null;
        try {
            certInput = SysProperty.class.getResourceAsStream("/uk/ngs/ca/tools/property/hostcert.pem");
            writer = new StringWriter();
            char[] buffer = new char[1024];
            reader = new BufferedReader(new InputStreamReader(certInput, "UTF-8"));
            int n;
            while ((n = reader.read(buffer)) != -1) {
                writer.write(buffer, 0, n);
            }
            hostCertString = writer.toString();
        }
        catch(Exception ex){
              throw new IllegalStateException("An error occurred reading into buffer /uk/ngs/ca/tools/property/hostcert.pem", ex);
        } finally {
            try{ certInput.close(); }catch(Exception ex){}
            try{ reader.close(); }catch(Exception ex){}
            try{ writer.close(); }catch(Exception ex){}
        }

        // 2) read all the certificates from hostCertString String into chain array
        // ==================================================================
        X509Certificate[] chain = null;
        java.io.StringReader hostCertStringReader = null;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource();
            hostCertStringReader = new java.io.StringReader(hostCertString);
            is.setCharacterStream(hostCertStringReader);
            Document document = db.parse(is);

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/hostcerts/hostcert/text()");
            Object result = expr.evaluate(document, XPathConstants.NODESET);
            NodeList nodes = (NodeList) result;
            chain = new X509Certificate[nodes.getLength()];
            for (int i = 0; i < nodes.getLength(); i++) {
                String _hostCertString = nodes.item(i).getNodeValue();
                StringReader certStringReader = new StringReader(_hostCertString);
                PEMReader certPemReader = new PEMReader(certStringReader);
                X509Certificate cert = (X509Certificate) certPemReader.readObject();
                chain[i] = cert;
                certPemReader.close();
                certStringReader.close();
                //System.out.println("cert total: " + i);
            }
        }catch (Exception ep) {
            throw new IllegalStateException("An error occurred parsing XML /uk/ngs/ca/tools/property/hostcert.pem.", ep);
        } finally {
           try{ hostCertStringReader.close(); }catch(Exception ex){}
        }


        // 3) create a keystore file used to hold the CA server's hostcert.
        // and load with the certs using different aliases.
        // ==================================================================
        KeyStore keyStore = null;
         try {
             //we need to find out if Bouncycastle supports JKS format.
             //if we adopt java keystore, the password is limited within 7 characters
             //if no importing unlimited policy file.
            keyStore = KeyStore.getInstance("JKS", "SUN");
            keyStore.load(null, null);
            for( int i = 0; i < chain.length; i++ ){
                keyStore.setCertificateEntry("alias_"+i, chain[ i ]);
            }
        } catch (Exception ep) {
            throw new IllegalStateException("Error creating a trustStore.", ep);
        }

        // 4) Always overwrite the file: ~/.ca/truststore.jks with the newly
        // created keystore.
        // ==================================================================
        String key = "ngsca.truststore.file";   // 'truststore.jks'
        String value = SysProperty.getValue(key);
        if (value == null) {
            throw new IllegalStateException("There is no trust store file name. Please check out config.properties.");
        }
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + value;

        String keyStoreFile = homePath; // ~/.ca/truststore.jks
        FileOutputStream fos = null;
        try {
                File f = new File(keyStoreFile);
                if(f.exists()){
                    if(!f.delete()) throw new IllegalStateException("Could not remove existing trustore file");
                }
                f = new File(keyStoreFile); // re-create the file.
                fos = new FileOutputStream(f);
                keyStore.store(fos, SysProperty.getValue("ngsca.cert.truststore.password").toCharArray());
        } catch (Exception ep) {
            throw new IllegalStateException("A wrong happens when create a trustStore on the USER_HOME/.ca/", ep);
        } finally {
            try { fos.close(); } catch (IOException ex) { }
        }
    }



    /*public static String removed_setupTrustStore() {
        String message = null;
        X509Certificate cert = null;
        KeyPair keypair = null;
        PrivateKey privateKey = null;

        KeyStore keyStore = null;

        final String password = SysProperty.getValue("ngsca.cert.truststore.password");

        try {
            
//             we need to find out if Bouncycastle supports JKS format.
//             if we adopt java keystore, the password is limited within 7 characters
//             if no importing unlimited policy file.
//
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
            
             //only publickey is restored in client ketstore.
            
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
    }*/

    public static void alterProperties(String key, String value) {
        
        String _property = SysProperty.getValue(key);
        properties.setProperty(_property, value);
        try {
            FileOutputStream out = new FileOutputStream(PROP_FILE);
            properties.store(out, _property);
            out.close();

        } catch (FileNotFoundException ex) {
            myLogger.error("[SysProperty] Could not find the properties file!");
        } catch (IOException ex2) {
            myLogger.error("[SysProperty] Error writing to the file.");   
        }
        SysProperty.init(); //in order to read the properties file again with the
                            //newest modifications.
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
