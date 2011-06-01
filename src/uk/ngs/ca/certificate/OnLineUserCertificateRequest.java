/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Observable;

import java.security.PublicKey;
import java.security.PrivateKey;

import uk.ngs.ca.common.HashUtil;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.certificate.client.CSRRequest;

/**
 * This class requests a new certificate under online
 * @author xw75
 */
public class OnLineUserCertificateRequest extends Observable{

    private String RA = null;
    private String Name = null;
    private String Email = null;
    private String PIN1 = null;
    private String PIN2 = null;
    private char[] PASSPHRASE = null;
    private String MESSAGE = null;
    private String Alias = null;

    public OnLineUserCertificateRequest(char[] passphrase) {
        this.PASSPHRASE = passphrase;
    }

    /**
     * Notifies MainWindow any modification
     */
    public void notifyObserver(){
        setChanged();
        notifyObservers( this.Alias );
    }

    /**
     * Calls CA server to request certificate
     * @return true if successful, otherwise false.
     */
    public boolean doOnLineCSR() {
        if (getError().equals("")) {
            ClientKeyStore clientKeyStore = ClientKeyStore.getClientkeyStore(this.PASSPHRASE);
            String alias = clientKeyStore.createNewKeyPair();
            this.Alias = alias;
            PublicKey publicKey = clientKeyStore.getPublicKey(alias);
            PrivateKey privateKey = clientKeyStore.getPrivateKey(alias);

            CertificateRequestCreator csrCreator = new CertificateRequestCreator();
            csrCreator.setCN(this.Name);
            csrCreator.setEmail(this.Email);
            csrCreator.setRA(getOU(), getL());
            String hashPIN1 = HashUtil.getHash(this.PIN1);
            String hashPIN2 = HashUtil.getHash(this.PIN2);
            csrCreator.setPIN1(hashPIN1);
            csrCreator.setPIN2(hashPIN2);
            csrCreator.createDN(false);
            String csrString = csrCreator.createCertificateRequest(privateKey, publicKey);
            String dn = csrCreator.getDN().toString();

            CSRRequest csrRequest = new CSRRequest(csrString, hashPIN1, this.Email);
            this.MESSAGE = csrRequest.getMessage();
            return csrRequest.isCSRREquestSuccess();
        } else {
            this.MESSAGE = "Please check you input parameters.";
            return false;
        }
    }

    /**
     * Gets error message. It is null if doOnlineCSR is true.
     * @return
     */
    public String getMessage() {
        return this.MESSAGE;
    }

    private String getOU() {
        if (isValidRA()) {
            int index = this.RA.trim().indexOf(" ");
            String ou = this.RA.substring(0, index);
            return ou;
        } else {
            return null;
        }
    }

    private String getL() {
        if (isValidRA()) {
            int index = this.RA.trim().indexOf(" ");
            int length = this.RA.length();
            String l = this.RA.substring(index, length).trim();
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
        this.RA = ra;
    }

    /**
     * Sets up name
     * @param name name
     */
    public void setName(String name) {
        this.Name = name;
    }

    /**
     * Sets up email
     * @param email email
     */
    public void setEmail(String email) {
        this.Email = email;
    }

    /**
     * Sets up first pin
     * @param pin1 pin
     */
    public void setPIN1(String pin1) {
        this.PIN1 = pin1;
    }

    /**
     * Sets up second pin
     * @param pin2 pin
     */
    public void setPIN2(String pin2) {
        this.PIN2 = pin2;
    }

    private String getError() {
        if (!isValidRA()) {
            return "Please select a RA from the pull-down menu.";
        }
        if (!isValidName()) {
            return "Please input your name (firstname lastname)";
        }
        if (!isValidEmail()) {
            return "Please input your email";
        }
        if (!isValidPIN()) {
            return "Please input two same PIN";
        }
        return "";
    }

    private boolean isValidRA() {

        if (this.RA == null) {
            return false;
        }
        int index = this.RA.trim().indexOf(" ");
        if (index == -1) {
            return false;
        } else {
            return true;
        }
    }

    private boolean isValidName() {

        if (this.Name == null) {
            return false;
        }
        int index = this.Name.trim().indexOf(" ");
        if (index == -1) {
            return false;
        } else {
            return true;
        }
    }

    private boolean isValidEmail() {
        //Set the email pattern string
//        Pattern p = Pattern.compile(".+@.+\\.[a-z]+");
        Pattern p = Pattern.compile("[-\\.a-zA-Z0-9_]+@[-a-zA-Z0-9\\.]+\\.[a-z]+");
        //Match the given string with the pattern
        Matcher m = p.matcher(this.Email);
        //check whether match is found
        boolean matchFound = m.matches();
        if (matchFound) {
            return true;
        } else {
            return false;
        }
    }

    private boolean isValidPIN() {
        if (this.PIN1 == null) {
            return false;
        }
        if (this.PIN2 == null) {
            return false;
        }
        if (!this.PIN1.equals(this.PIN2)) {
            return false;
        }
        return true;
    }

}
