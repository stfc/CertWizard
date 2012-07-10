/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.io.File;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75 (Xiao Wang)
 */
public class LocalBackup {

    String Message = null;

    public LocalBackup() {
    }

    public boolean isSuccess() {
        String _keyFile = SysProperty.getValue("ngsca.key.keystore.file");
        String _keyBackupFile = SysProperty.getValue("ngsca.key.keystore.backup.file");
        String backupDir = System.getProperty("user.home");
        backupDir = backupDir + System.getProperty("file.separator") + ".ca";
        String configDir = backupDir;
        backupDir = backupDir + System.getProperty("file.separator") + "backup";
        String keyFile = configDir + System.getProperty("file.separator") + _keyFile;
        String keyBackupFile = backupDir + System.getProperty("file.separator") + _keyBackupFile;

        File file = new File(backupDir);
        if (!file.isDirectory()) {
            file.mkdir();
        } else {
            if (!file.canWrite()) {
                Message = "Could not make keyStore backup file (permissions denied). Please make a manaual backup of :\n"
                        + keyFile;
                return false;
            }
        }

        try {
            File inF, outF;

            inF = new File(keyFile);
            outF = new File(keyBackupFile);

            if (inF.exists() && inF.isFile() && inF.length() > 0L) {
                FileUtils.copyFile(inF, outF, true); 
            }

            return true;
        } catch (Exception ex) {
            Message = "Could not make keyStore backup file. Please make a manaual backup of :\n"
                    + keyFile + "\n\n"
                    + " \nError cause: " + ex.getMessage();
            return false;
        }



    }

    public String getMessage() {
        return Message;
    }

}
