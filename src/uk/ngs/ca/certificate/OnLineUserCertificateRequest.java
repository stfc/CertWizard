/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import uk.ngs.ca.certificate.client.CSRRequest;
import uk.ngs.ca.certificate.management.ClientKeyStore;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.CAKeyPair;
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
    //private char[] PASSPHRASE = null;
    private String MESSAGE = null;
    private String Alias = null;
    private final ClientKeyStore clientKeyStore; 
    private final ClientKeyStoreCaServiceWrapper caKeyStoreModel; 

    public OnLineUserCertificateRequest(ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        //this.PASSPHRASE = passphrase;
        this.caKeyStoreModel = caKeyStoreModel;
        this.clientKeyStore = caKeyStoreModel.getClientKeyStore(); 
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
    /*public String doOnLineCsrUpdateKeyStore() throws KeyStoreException {
        if (getError().equals("")) {
            
            String hashPIN1 = HashUtil.getHash(this.PIN1);
            String hashPIN2 = HashUtil.getHash(this.PIN2);
            if(!hashPIN1.equals(hashPIN2)){
               return null;  
            }
          
            // create/add a new-self signed cert in keystore   
            this.Alias = clientKeyStore.createNewSelfSignedCert(this.Alias, getOU(), getL(), this.Name);
            
            // Add a new keystore entry to map rather than reloading all the entries!
            //ClientKeyStoreCaServiceWrapper caKeyStoreModel = ClientKeyStoreCaServiceWrapper.getInstance(PASSPHRASE); 
            KeyStoreEntryWrapper newCsrEntry = caKeyStoreModel.createKSEntryWrapperInstanceFromEntry(this.Alias);
            caKeyStoreModel.getKeyStoreEntryMap().put(this.Alias, newCsrEntry);
            
            // fetch the pub/private key from the keystore for the newly added self-signed cert 
            PublicKey publicKey = clientKeyStore.getPublicKey(this.Alias);            
            PrivateKey privateKey = clientKeyStore.getPrivateKey(this.Alias);

            // create a PKCS#10 from keys and DN info 
            CertificateRequestCreator csrCreator = new CertificateRequestCreator(
                    CertificateRequestCreator.TYPE.USER, this.Name, getOU(), getL(), this.Email);
            String csrString = csrCreator.createCertificateRequest(privateKey, publicKey);
            
            // send PKCS#10 to server
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
    }*/
    
    public boolean doOnLineCsrUpdateKeyStore() throws KeyStoreException {
        if (!getError().equals("")) {
            this.MESSAGE = "Please check you input parameters.";
            return false;
        }

        String hashPIN1 = HashUtil.getHash(this.PIN1);
        String hashPIN2 = HashUtil.getHash(this.PIN2);
        if (!hashPIN1.equals(hashPIN2)) {
            return false;
        }

        // Create a new key pair for new user cert 
        KeyPair keyPair = CAKeyPair.getNewKeyPair();
        PublicKey csrPublicKey = keyPair.getPublic();
        PrivateKey csrPrivateKey = keyPair.getPrivate();

        // create a PKCS#10 from keys and DN info 
        CertificateRequestCreator csrCreator = new CertificateRequestCreator(
                CertificateRequestCreator.TYPE.USER, this.Name, getOU(), getL(), this.Email);
        String csrString = csrCreator.createCertificateRequest(csrPrivateKey, csrPublicKey);

        // send PKCS#10 to server
        CSRRequest csrRequest = new CSRRequest(csrString, hashPIN1, this.Email);
        this.MESSAGE = csrRequest.getMessage();
        if (csrRequest.isCSRREquestSuccess()) {
            return true;
        } else {
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
