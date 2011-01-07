/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

import java.io.File;
import java.io.IOException;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ClientCertificates {

    CertificateRequestManager certRequestManager;
    OnlineCertificateManager onlineCertManager;
    private char[] PASSPHRASE;

    public ClientCertificates(char[] passphrase) {
        PASSPHRASE = passphrase;
        init();
    }

    private void init() {
        certRequestManager = new CertificateRequestManager(PASSPHRASE);
        onlineCertManager = new OnlineCertificateManager(PASSPHRASE);
    }

    public boolean isExistKeyPair() {

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

    public String[] getDNs() {
        String[] aliases = onlineCertManager.getAllAliases();
        String[] _dns = certRequestManager.getAllDNs();
        int index = aliases.length + _dns.length;
        String[] result = new String[index];
        for (int i = 0; i < aliases.length; i++) {
            result[i] = aliases[i];
        }
        for (int i = 0; i < _dns.length; i++) {
            result[i + aliases.length] = _dns[i];
        }

        return result;
    }

    private int getKeyStoreSize() {
        String[] aliases = onlineCertManager.getAllAliases();
        return aliases.length;
    }

    private int getCSRStoreSize() {
        String[] _dns = certRequestManager.getAllDNs();
        return _dns.length;
    }

    public String getDN(int index) {
        if (index < getKeyStoreSize()) {
            return onlineCertManager.getDN(index);
        } else {
            return certRequestManager.getDN(index);
        }
    }

    public String getEmail(int index) {
        if (index < getKeyStoreSize()) {
            String alias = onlineCertManager.getDN(index);
            return onlineCertManager.getEmail(alias);
        } else {
            String dn = certRequestManager.getDN(index);
            return certRequestManager.getEmail(dn);
        }
    }

    public String getValidFrom(int index) {
        if (index < getKeyStoreSize()) {
            String alias = onlineCertManager.getDN(index);
            return onlineCertManager.getStartDate(alias);
        } else {
            return "N/A";
        }
    }

    public String getValidTo(int index) {
        if (index < getKeyStoreSize()) {
            String alias = onlineCertManager.getDN(index);
            return onlineCertManager.getEndDate(alias);
        } else {
            return "N/A";
        }
    }

    public String getRemainDays(int index) {
        if (index < getKeyStoreSize()) {
            String alias = onlineCertManager.getDN(index);
            return onlineCertManager.getLiveDays(alias);
        } else {
            return "N/A";
        }
    }

    public String getRenewDate(int index) {
        if (index < getKeyStoreSize()) {
            String alias = onlineCertManager.getDN(index);
            return onlineCertManager.getRenewDate(alias);
        } else {
            return "N/A";
        }
    }

    public String getStatus(int index) {
        if (index < getKeyStoreSize()) {
            String alias = onlineCertManager.getDN(index);
            return onlineCertManager.getStatus(alias);
        } else {
            String dn = certRequestManager.getDN(index);
            return certRequestManager.getStatus(dn);
        }
    }

    public boolean remove(int index) {
        if (index < getKeyStoreSize()) {
            String alias = onlineCertManager.getDN(index);
            boolean bool = onlineCertManager.remove(alias);
            return bool;
        } else {
            String dn = certRequestManager.getDN(index);
            certRequestManager.remove(dn);
            boolean bool = certRequestManager.saveFile();
            return bool;
        }
    }

}
