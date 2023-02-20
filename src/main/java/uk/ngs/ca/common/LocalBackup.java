/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.common;

import uk.ngs.ca.tools.property.SysProperty;

import java.io.File;

/**
 * @author xw75 (Xiao Wang)
 */
public class LocalBackup {

    String Message = null;

    public LocalBackup() {
    }

    public boolean isSuccess() {
        String _keyFile = SysProperty.getValue("ngsca.key.keystore.file");
        String _keyBackupFile = SysProperty.getValue("ngsca.key.keystore.backup.file");
        String configDir = SystemStatus.getInstance().getCwDataDirectory().getAbsolutePath();
        String backupDir = configDir;
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
