/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import java.nio.channels.FileChannel;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class LocalBackup {

    String Message = null;

    public LocalBackup() {
    }

    public boolean isSuccess() {
        //String _xmlFile = SysProperty.getValue("ngsca.cert.xml.file");
        String _keyFile = SysProperty.getValue("ngsca.key.keystore.file");
        //String _certKeyFile = SysProperty.getValue("ngsca.cert.keystore.file");

        //String _xmlBackupFile = SysProperty.getValue("ngsca.cert.xml.backup.file");
        String _keyBackupFile = SysProperty.getValue("ngsca.key.keystore.backup.file");
        //String _certKeyBackupFile = SysProperty.getValue("ngsca.cert.keystore.backup.file");

        String backupDir = System.getProperty("user.home");
        backupDir = backupDir + System.getProperty("file.separator") + ".ca";
        String sourceDir = backupDir;
        backupDir = backupDir + System.getProperty("file.separator") + "backup";
        File file = new File(backupDir);
        if (!file.isDirectory()) {
            file.mkdir();
        } else {
            if (!file.canWrite()) {
                Message = "no permission to write in file. Please contact admin or modify configure file";
                return false;
            }

        }
        //String xmlFile = sourceDir + System.getProperty("file.separator") + _xmlFile;
        String keyFile = sourceDir + System.getProperty("file.separator") + _keyFile;
        //String certKeyFile = sourceDir + System.getProperty("file.separator") + _certKeyFile;
        //String xmlBackupFile = backupDir + System.getProperty("file.separator") + _xmlBackupFile;
        String keyBackupFile = backupDir + System.getProperty("file.separator") + _keyBackupFile;
        //String certKeyBackupFile = backupDir + System.getProperty("file.separator") + _certKeyBackupFile;
        try {
            File inF = null, outF = null;
            //File inF = new File(xmlFile);
            //File outF = new File(xmlBackupFile);

            copyFile(inF, outF);

            inF = new File(keyFile);
            outF = new File(keyBackupFile);

            copyFile(inF, outF);

            //inF = new File(certKeyFile);
            //outF = new File(certKeyBackupFile);

            //copyFile(inF, outF);

            return true;
        } catch (Exception ep) {
            Message = "Failed to backup files";
            return false;
        }



    }

    private void copyFile(File inFile, File outFile) throws IOException {
        FileChannel inChannel = null;
        FileChannel outChannel = null;
        try {
            inChannel = new FileInputStream(inFile).getChannel();
            outChannel = new FileOutputStream(outFile).getChannel();
            inChannel.transferTo(0, inChannel.size(), outChannel);
        } catch (FileNotFoundException fep) {
//            Message = "file not found";
        } finally {
            if (inChannel != null) {
                inChannel.close();
            }
            if (outChannel != null) {
                outChannel.close();
            }
        }
    }

    public String getMessage() {
        return Message;
    }

}
