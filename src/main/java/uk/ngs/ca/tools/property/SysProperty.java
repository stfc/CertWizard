/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.tools.property;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.ngs.ca.common.SystemStatus;

/**
 * This class manages the attributes which recorded in the property file.
 *
 * @author xw75
 */
public class SysProperty {

    private static final Logger myLogger = LogManager.getLogger(SysProperty.class);
    private static final String PROP_FILE = "/configure.properties";
    private static boolean isInitialized = false;
    private static Properties properties = new Properties();
    private static final String FILEPATH = ".ca";

    private static int timeoutMilliSecs = 5000;

    /**
     * Get the timeout in millisecs for the http(s) connections.
     *
     * @return
     */
    public static int getTimeoutMilliSecs() {
        return timeoutMilliSecs;
    }

    /**
     * Set the timeout in milliseconds for the http(s) connections.
     *
     * @param milliSecs
     */
    public static void setTimeoutMilliSecs(int milliSecs) {
        timeoutMilliSecs = milliSecs;
    }

    /**
     * Returns property value
     *
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
     * Returns configure xml file path. If there is no file, then create a
     * template one.
     *
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

        String absPath = SystemStatus.getInstance().getHomeDir().getAbsolutePath()
                + File.separator + FILEPATH + File.separator + value;
        // check if the size of file is zero, if yes, then remove it and create a new template file.
        if (!(new File(absPath).exists()) || (new File(absPath).length() == 0)) {
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
     * configure.properties file). This KeyStore is used to establish SSL with
     * the CA rest server.
     *
     * @throws IllegalStateException if any problem occurs creating and
     * deploying the trustore.jks file.
     */
    public static void setupTrustStore() {

        // create a keystore file used to hold the CA server's hostcert.
        // and load with the root cert
        // ==================================================================
        KeyStore keyStore = null;
        try {
            InputStream escience2b = SysProperty.class.getResourceAsStream("/escience-2b.pem");
            InputStream escienceroot = SysProperty.class.getResourceAsStream("/escience-root.pem");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate escienceRootCert = certificateFactory.generateCertificate(escienceroot);
            Certificate escience2bCert = certificateFactory.generateCertificate(escience2b);

            keyStore = KeyStore.getInstance("JKS", "SUN");
            keyStore.load(null, null);
            keyStore.setCertificateEntry("eScienceRoot", escienceRootCert);
            keyStore.setCertificateEntry("eScienceRoot2B", escience2bCert);
        } catch (Exception ep) {
            System.out.println(ep.toString());
            throw new IllegalStateException("Error creating a trustStore.", ep);
        }

        // Always overwrite the file: ~/.ca/truststore.jks with the newly
        // created keystore.
        // ==================================================================
        String key = "ngsca.truststore.file";   // 'truststore.jks'
        String value = SysProperty.getValue(key);
        if (value == null) {
            throw new IllegalStateException("There is no trust store file name. Please check out config.properties.");
        }
        String homePath = SystemStatus.getInstance().getHomeDir().getAbsolutePath();
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + value;

        String keyStoreFile = homePath; // ~/.ca/truststore.jks
        FileOutputStream fos = null;
        try {
            File f = new File(keyStoreFile);
            if (f.exists()) {
                if (!f.delete()) {
                    throw new IllegalStateException("Could not remove existing trustore file");
                }
            }
            f = new File(keyStoreFile); // re-create the file.
            fos = new FileOutputStream(f);
            keyStore.store(fos, SysProperty.getValue("ngsca.cert.truststore.password").toCharArray());
        } catch (Exception ep) {
            throw new IllegalStateException("A wrong happens when create a trustStore on the USER_HOME/.ca/", ep);
        } finally {
            try {
                fos.close();
            } catch (IOException ex) {
            }
        }
    }

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
