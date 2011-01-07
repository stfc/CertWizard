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
public class CertificateStartDate {

    Date startDate = null;

    public CertificateStartDate(String certID) {
        CertificateDownload certDownload = new CertificateDownload(certID);
        X509Certificate cert = certDownload.getCertificate();
        startDate = cert.getNotBefore();
    }

    public Date getStartDate() {
        return startDate;
    }
}
