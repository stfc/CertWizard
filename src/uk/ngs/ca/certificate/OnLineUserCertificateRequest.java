/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import uk.ngs.ca.certificate.client.CSRRequest;
import uk.ngs.ca.certificate.management.ClientKeyStore;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.HashUtil;

/**
 * This class requests a new certificate under online
 * @author xw75 (Xiao Wang) 
 */
public class OnLineUserCertificateRequest /*extends Observable*/{

    private String RA= null;
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
    /*public void notifyObserver(){
        setChanged();
        notifyObservers( this.Alias );
    }*/

    /**
     * Calls CA server to request certificate and creates a new keyStore entry. 
     * Important: the keyStore is NOT reStored to file. 
     * 
     * @return newly created keyStore entry alias if successful, otherwise null
     */
    public String doOnLineCsrUpdateKeyStore() throws KeyStoreException {
        if (getError().equals("")) {
            // caKeyStore.pkcs12
            ClientKeyStore clientKeyStore = ClientKeyStoreCaServiceWrapper.getInstance(this.PASSPHRASE).getClientKeyStore(); 
            // create new keypair entry under new meaningless alias and re-save file.
            // TODO: pass-through the info provided by the user rather than
            // creating a new dummy CSR certificate. 
            
            this.Alias = clientKeyStore.createNewSelfSignedCert(this.Alias, getOU(), getL(), this.Name);
            
            PublicKey publicKey; 
            // Add a new keystore entry rather than reloading all the entries!
            ClientKeyStoreCaServiceWrapper caKeyStoreModel = ClientKeyStoreCaServiceWrapper.getInstance(PASSPHRASE); 
            KeyStoreEntryWrapper newCsrEntry = caKeyStoreModel.createKSEntryWrapperInstanceFromEntry(this.Alias);
            caKeyStoreModel.getKeyStoreEntryMap().put(this.Alias, newCsrEntry);
            publicKey = clientKeyStore.getPublicKey(this.Alias);
            
            
            PrivateKey privateKey = clientKeyStore.getPrivateKey(this.Alias);

            CertificateRequestCreator csrCreator = new CertificateRequestCreator(
                    CertificateRequestCreator.TYPE.USER, this.Name, getOU(), getL(), this.Email);
            String csrString = csrCreator.createCertificateRequest(privateKey, publicKey);
            
            String hashPIN1 = HashUtil.getHash(this.PIN1);
            String hashPIN2 = HashUtil.getHash(this.PIN2);
            if(!hashPIN1.equals(hashPIN2)){
               return null;  
            }
            CSRRequest csrRequest = new CSRRequest(csrString, hashPIN1, this.Email);
            this.MESSAGE = csrRequest.getMessage();
            if(csrRequest.isCSRREquestSuccess()){
                return this.Alias; 
            } else {
                return null; 
            }
            
            //return true;
        } else {
            this.MESSAGE = "Please check you input parameters.";
            return null;
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

    public void setAlias(String alias){
            this.Alias = alias;
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
            return "Invalid RA";
        }
        if (!isValidName()) {
            return "Invalid CN";
        }
        if (!isValidEmail()) {
            return "Invalid Email";
        }
        if (!isValidPIN()) {
            return "Invalid PIN";
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
