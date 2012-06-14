/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.ResourceBundle;
import net.sf.portecle.FPortecle;
import net.sf.portecle.StringUtil;
import net.sf.portecle.crypto.DigestType;
import net.sf.portecle.crypto.DigestUtil;
import net.sf.portecle.crypto.KeyPairUtil;
import net.sf.portecle.crypto.X509CertUtil;

/**
 * Create a report of the managed keyStore
 * Based on Portecle. 
 * 
 * @author David Meredith
 */
public class ClientKeyStoreReport {

    private KeyStore m_keystore;
    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    /**
     * Portecle Resource bundle
     */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);

    public ClientKeyStoreReport(char[] passphrase) {
        this.m_keystore = ClientKeyStoreCaServiceWrapper.getInstance(passphrase).getClientKeyStore().getKeyStoreCopy();
    }

    /**
     * Get the KeyStoreReport as plain text.
     *
     * @return Keystore report
     * @throws IllegalStateException If a problem was encountered
     * generating the keystore report
     */
    public String getKeyStoreReport() {
        try {
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
            while (aliases.hasMoreElements()) {
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
                if (m_keystore.isKeyEntry(sAlias)) {
                    certChain = m_keystore.getCertificateChain(sAlias);

                    if (certChain == null || certChain.length == 0) {
                        sbReport.append(RB.getString("DKeyStoreReport.report.key"));
                        sbReport.append("\n");
                    } else {
                        sbReport.append(RB.getString("DKeyStoreReport.report.keypair"));
                        sbReport.append("\n");
                    }
                } else {
                    sbReport.append(RB.getString("DKeyStoreReport.report.trustcert"));
                    sbReport.append("\n");

                    Certificate cert = m_keystore.getCertificate(sAlias);
                    if (cert != null) {
                        certChain = new Certificate[]{cert};
                    }
                }

                // Get information on each certificate in an entry
                if (certChain == null || certChain.length == 0) {
                    // Zero certificates
                    sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.certs"), 0));
                    sbReport.append("\n\n");
                } else {
                    X509Certificate[] x509CertChain =
                            X509CertUtil.convertCertificates(certChain);

                    // One or more certificates
                    int iChainLen = x509CertChain.length;
                    sbReport.append(MessageFormat.format(RB.getString("DKeyStoreReport.report.certs"),
                            iChainLen));
                    sbReport.append("\n\n");

                    for (int iCnt = 0; iCnt < iChainLen; iCnt++) {
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

                        if (iCnt + 1 < iChainLen) {
                            sbReport.append("\n");
                        }
                    }

                    if (aliases.hasMoreElements()) {
                        sbReport.append("\n");
                    }
                }
            }

            // Return the report
            return sbReport.toString();
        } catch (Exception ex) {
            throw new IllegalStateException("report exeception", ex);
        }
    }
}
