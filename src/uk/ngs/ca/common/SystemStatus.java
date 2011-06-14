/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.io.File;
import java.util.Observable;
//import java.util.concurrent.atomic.AtomicBoolean;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class SystemStatus extends Observable {

    // ISONLINE and ISINIT represent shared mutable state: Need to be atomic.
    //public static AtomicBoolean ISONLINE = new AtomicBoolean(true);
    //public static AtomicBoolean ISINIT = new AtomicBoolean(false);;
    private String errorMessage = null;

    private boolean isOnline = false;
   
    public synchronized boolean getIsOnline(){
        return this.isOnline;
    }

    /**
     * Set the online system status flag and update any Observers registered
     * to observe online status changes.
     * @param online
     */
    public synchronized void setIsOnline(boolean online){
        if (online != this.isOnline) {
            this.isOnline = online;
            setChanged();
            notifyObservers();
        }
    }


   
   /**
    * SystemStatusHolder is loaded on the first execution of SystemStatus.getInstance()
    * or the first access to SystemStatusHolder.sysStatus, not before.
    */
    private static class SystemStatusHolder {
         public static final SystemStatus sysStatus = new SystemStatus();
    }

    //force non-instantiation
    private SystemStatus() {
    }

     /**
     * Get the shared, thread safe instance.
     * @return
     */
    public static SystemStatus getInstance(){
      return SystemStatusHolder.sysStatus;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public synchronized boolean isExistKeyStore() {
        String key = "ngsca.key.keystore.file";
        String value = SysProperty.getValue(key);
        if (value == null) {
            System.out.println("[SystemStatus] could not find out the value of " + key + " in your property file.");
        }
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + value;
        if (new File(homePath).exists()) {
            return true;
        } else {
            return false;
        }
    }

    public synchronized boolean isValidPassphrase(char[] passphrase) {
        //uk.ngs.ca.common.ClientKeyStore keyStore = new uk.ngs.ca.common.ClientKeyStore(passphrase);
        ClientKeyStore keyStore = ClientKeyStore.getClientkeyStore(passphrase);
        String _errorMessage = keyStore.getErrorMessage();

        if (_errorMessage == null) {
            uk.ngs.ca.common.ClientCertKeyStore certStore = uk.ngs.ca.common.ClientCertKeyStore.getClientCertKeyStore(passphrase);
            String __errorMessage = certStore.getErrorMessage();
            if (__errorMessage == null) {
                return true;
            } else if (__errorMessage.indexOf("key size") >= 0) {
                __errorMessage = "A problem was encountered trying to create your Globus/Grid environment.\n" + "US encryption policy means password cannot be more than 7 characters.\n" + "This may be corrected in some cases by changing Java Security policy files.\n" + "See the User Certificate help page.";
                errorMessage = __errorMessage;
                return false;
            } else {
                errorMessage = __errorMessage;
                return false;
            }
        } else if (_errorMessage.indexOf("key size") >= 0) {
            _errorMessage = "A problem was encountered trying to create your Globus/Grid environment.\n" + "US encryption policy means password cannot be more than 7 characters.\n" + "This may be corrected in some cases by changing Java Security policy files.\n" + "See the User Certificate help page.";
            errorMessage = _errorMessage;
            return false;
        } else {
            errorMessage = _errorMessage;
            return false;
        }

    }
}
