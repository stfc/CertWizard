/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.io.File;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class SystemStatus {

    public static boolean ISONLINE = true;
    public static boolean ISINIT = false;
    private String errorMessage = null;

    public SystemStatus() {
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public boolean isExistKeyStore() {
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

    public boolean isValidPassphrase(char[] passphrase) {
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
