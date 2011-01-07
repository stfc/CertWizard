/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Date;
import java.util.Observable;

import java.security.PublicKey;
import java.security.PrivateKey;

import uk.ngs.ca.certificate.management.CertificateRequestManager;
import uk.ngs.ca.common.HashUtil;
import uk.ngs.ca.common.ClientKeyStore;

/**
 * This class requests new certificate under offline.
 * @author xw75
 */
public class OffLineUserCertificateRequest extends Observable {

    private String RA = null;
    private String Name = null;
    private String Email = null;
    private String PIN1 = null;
    private String PIN2 = null;
    private char[] PASSPHRASE = null;
    private boolean isCSRSuccess = false;

    private String errorMessage = null;
    
    public OffLineUserCertificateRequest(char[] passphrase) {
        PASSPHRASE = passphrase;
    }

    /**
     * Notifies MainWindow any modification.
     */
    public void notifyObserver() {
        setChanged();
        notifyObservers(this);
    }

    /**
     * Checks if creating a CSR and restoring in localcertificate.xml file.
     * @return true if successful, otherwise false
     */
    public boolean doOffLineCSR() {
        if (getError().equals("")) {
            ClientKeyStore clientKeyStore = new ClientKeyStore(PASSPHRASE);
            String alias = clientKeyStore.createNewKeyPair();
            PublicKey publicKey = clientKeyStore.getPublicKey(alias);
            PrivateKey privateKey = clientKeyStore.getPrivateKey(alias);

            CertificateRequestCreator csrCreator = new CertificateRequestCreator();
            csrCreator.setCN(Name);
            csrCreator.setEmail(Email);
            csrCreator.setRA(getOU(), getL());
            String hashPIN1 = HashUtil.getHash(PIN1);
            String hashPIN2 = HashUtil.getHash(PIN2);
            csrCreator.setPIN1(hashPIN1);
            csrCreator.setPIN2(hashPIN2);
            csrCreator.createDN(false);
            String csrString = csrCreator.createCertificateRequest(privateKey, publicKey);
            String dn = csrCreator.getDN().toString();

            //please note that the PASSPHRASE would be removed from CertificateRequestManager
            CertificateRequestManager manager = new CertificateRequestManager(PASSPHRASE);
            manager.addCSR(dn, csrString);
            manager.addStatus(dn, "UnSubmitted");
            manager.addEmail(dn, Email);
            manager.addPIN(dn, hashPIN1);
            manager.addAlias(dn, new Long(new Date().getTime()).toString());
            manager.saveFile();
            isCSRSuccess = true;
            return true;
        } else {
            isCSRSuccess = false;
            return false;
        }
    }

    /**
     * Gets error message. It is null if doOffLineCSR is true.
     * @return
     */
    public String getMessage() {
        if (isCSRSuccess) {
            return "Your Certificate Request has been restore in the local file. \n" +
                    "The request will be submitted to CA server when you run online.";
        } else {
            return errorMessage;
        }
    }

    private String getOU() {
        if (isValidRA()) {
            int index = RA.trim().indexOf(" ");
            String ou = RA.substring(0, index);
            return ou;
        } else {
            return null;
        }
    }

    private String getL() {
        if (isValidRA()) {
            int index = RA.trim().indexOf(" ");
            int length = RA.length();
            String l = RA.substring(index, length).trim();
            return l;
        } else {
            return null;
        }
    }

    /**
     * Sets up RA
     * @param ra RA
     */
    public void setRA(String ra) {
        RA = ra;
    }

    /**
     * Sets up Name
     * @param name name
     */
    public void setName(String name) {
        Name = name;
    }

    /**
     * Sets up email
     * @param email email
     */
    public void setEmail(String email) {
        Email = email;
    }

    /**
     * Sets up first PIN
     * @param pin1 PIN
     */
    public void setPIN1(String pin1) {
        PIN1 = pin1;
    }

    /**
     * Sets up second PIN
     * @param pin2 PIN
     */
    public void setPIN2(String pin2) {
        PIN2 = pin2;
    }

    private String getError() {
        if (!isValidRA()) {
            errorMessage = "Please select a RA from the pull-down menu.";
            return errorMessage;
        }
        if (!isValidName()) {
            errorMessage = "Please input your name (firstname lastname)";
            return errorMessage;
        }
        if (!isValidEmail()) {
            errorMessage = "Please input your valid email";
            return errorMessage;
        }
        if (!isValidPIN()) {
            errorMessage = "Please input two same PIN";
            return errorMessage;
        }
        return "";
    }

    private boolean isValidRA() {

        if (RA == null) {
            return false;
        }
        int index = RA.trim().indexOf(" ");
        if (index == -1) {
            return false;
        } else {
            return true;
        }
    }

    private boolean isValidName() {

        if (Name == null) {
            return false;
        }
        int index = Name.trim().indexOf(" ");
        if (index == -1) {
            return false;
        } else {
            return true;
        }
    }

    private boolean isValidEmail() {
        //Set the email pattern string
        Pattern p = Pattern.compile(".+@.+\\.[a-z]+");
        //Match the given string with the pattern
        Matcher m = p.matcher(Email);
        //check whether match is found
        boolean matchFound = m.matches();
        if (matchFound) {
            return true;
        } else {
            return false;
        }
    }

    private boolean isValidPIN() {
        if (PIN1 == null) {
            return false;
        }
        if (PIN2 == null) {
            return false;
        }
        if (!PIN1.equals(PIN2)) {
            return false;
        }
        return true;
    }

}
