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
package uk.ngs.ca.certificate.management;

import java.util.Date;

/**
 * Data transfer object that represents an entry in a PKCS12 or JKS KeyStore. A
 * single instance can be shared by multiple threads and its state is mutable,
 * therefore access to all member variables is synchronized.
 *
 * @author David Meredth
 */
public class KeyStoreEntryWrapper {

    /* The choices for a valid keystore entry type */
    public enum KEYSTORE_ENTRY_TYPE {
        KEY_PAIR_ENTRY, TRUST_CERT_ENTRY, KEY_ENTRY
    }

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
     *
     * @param sAlias        KeyStore entry alias
     * @param eEntryType    entry type
     * @param dCreationDate the creation date
     * @throws IllegalArgumentException if any of the given params are null.
     */
    public KeyStoreEntryWrapper(String sAlias, KEYSTORE_ENTRY_TYPE eEntryType,
                                Date dCreationDate) {
        if (sAlias == null || dCreationDate == null) {
            throw new IllegalArgumentException("alias or creation date is null");
        }
        this.alias = sAlias;
        this.entrytype = eEntryType;
        this.creationDate = dCreationDate;
    }

    /**
     * The CertificateCSRInfo object is a holder for the information known about
     * this certificate by the CA server.
     *
     * @return the mCertificateCSRInfo or null if it does not exist.
     */
    public synchronized CertificateCSRInfo getServerCertificateCSRInfo() {
        return serverCertificateCSRInfo;
    }

    /**
     * @param mCertificateCSRInfo the mCertificateCSRInfo to set
     */
    public synchronized void setServerCertificateCSRInfo(CertificateCSRInfo mCertificateCSRInfo) {
        this.serverCertificateCSRInfo = mCertificateCSRInfo;
    }

    public synchronized void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * @return the mAlias
     */
    public synchronized String getAlias() {
        return alias;
    }

    /**
     * @return the mEntryType
     */
    public synchronized KEYSTORE_ENTRY_TYPE getEntryType() {
        return entrytype;
    }

    /**
     * @return the x500PrincipalName
     */
    public synchronized String getX500PrincipalName() {
        return x500PrincipalName;
    }

    /**
     * @param x500PrincipalName the x500PrincipalName to set
     */
    public synchronized void setX500PrincipalName(String x500PrincipalName) {
        this.x500PrincipalName = x500PrincipalName;
    }

    /**
     * @return the issuerName
     */
    public synchronized String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName the issuerName to set
     */
    public synchronized void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return the notBefore
     */
    public synchronized Date getNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore the notBefore to set
     */
    public synchronized void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * @return the notAfter
     */
    public synchronized Date getNotAfter() {
        return notAfter;
    }

    /**
     * @param notAfter the notAfter to set
     */
    public synchronized void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * @return True if this is certificate signing request certificate,
     * otherwise false.
     */
    public synchronized boolean isCSR() {
        if (x500PrincipalName != null && issuerName != null
                && x500PrincipalName.equals(issuerName) && x500PrincipalName.contains(" CSR ")) {
            return true;
        } else {
            return false;
        }
    }

}
