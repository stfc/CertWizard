package uk.ngs.ca.certificate.management;

import java.util.Date;

/**
 * Data transfer object that represents an entry in a PKCS12 or JKS KeyStore.
 * It wraps required and optional values.
 * @author David Meredth
 */
public class KeyStoreEntryWrapper {
    /* The choices for a valid keystore entry type */
    public static enum KEYSTORE_ENTRY_TYPE {KEY_PAIR_ENTRY, TRUST_CERT_ENTRY, KEY_ENTRY};

    /* Required fields - not nullable */
    private String alias;
    private KEYSTORE_ENTRY_TYPE entrytype;
    private Date creationDate;

    /* Optional fields - nullable */
    private CertificateCSRInfo serverCertificateCSRInfo = null;  // need to replace with better transfer object
    private String x500PrincipalName = null, issuerName = null;
    private Date notBefore = null, notAfter = null;


    /**
     * Constructor
     * @param sAlias KeyStore entry alias
     * @param eEntryType entry type
     * @param dCreationDate the creation date
     * @throws IllegalArgumentException if any of the given params are null.
     */
    public KeyStoreEntryWrapper(String sAlias, KEYSTORE_ENTRY_TYPE eEntryType, 
            Date dCreationDate){
        if(sAlias == null || dCreationDate == null){
            throw new IllegalArgumentException("alias or creation date is null");
        }
        this.alias  = sAlias;
        this.entrytype = eEntryType;
        this.creationDate = dCreationDate;
    }


    /**
     * The CertificateCSRInfo object is a holder for the information
     * known about this certificate by the CA server. 
     * @return the mCertificateCSRInfo or null if it does not exist.
     */
    public CertificateCSRInfo getServerCertificateCSRInfo() {
        return serverCertificateCSRInfo;
    }

    /**
     * @param mCertificateCSRInfo the mCertificateCSRInfo to set
     */
    public void setServerCertificateCSRInfo(CertificateCSRInfo mCertificateCSRInfo) {
        this.serverCertificateCSRInfo = mCertificateCSRInfo;
    }



    /**
     * @return the mAlias
     */
    public String getAlias() {
        return alias;
    }

    /**
     * @return the mEntryType
     */
    public KEYSTORE_ENTRY_TYPE getEntryType() {
        return entrytype;
    }

    /**
     * @return the mDate
     */
    public Date getCreationDate() {
        return creationDate;
    }

        /**
     * @return the x500PrincipalName
     */
    public String getX500PrincipalName() {
        return x500PrincipalName;
    }

    /**
     * @param x500PrincipalName the x500PrincipalName to set
     */
    public void setX500PrincipalName(String x500PrincipalName) {
        this.x500PrincipalName = x500PrincipalName;
    }

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName the issuerName to set
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore the notBefore to set
     */
    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return notAfter;
    }

    /**
     * @param notAfter the notAfter to set
     */
    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

}
