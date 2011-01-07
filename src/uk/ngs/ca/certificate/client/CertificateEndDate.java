/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import java.util.Date;
import java.security.cert.X509Certificate;

/**
 *
 * @author xw75
 */
public class CertificateEndDate {

    Date endDate = null;

    public CertificateEndDate(String certID) {
        CertificateDownload certDownload = new CertificateDownload(certID);
        X509Certificate cert = certDownload.getCertificate();
        endDate = cert.getNotAfter();
    }

    public Date getEndDate() {
        return endDate;
    }
}
