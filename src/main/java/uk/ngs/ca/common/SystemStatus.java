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

import java.io.File;
import java.util.Observable;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * This class is <code>Observable</code>. Registered <code>Observer</code>s will
 * be updated when the <code>isOnline</code> system changes.
 *
 * @author xw75
 */
public class SystemStatus extends Observable {

    private String errorMessage = null;

    private File homeDir = new File(System.getProperty("user.home"));

    private boolean isOnline = false;

    public synchronized File getHomeDir() {
        return new File(this.homeDir.getAbsolutePath());
    }

    public synchronized void setHomeDir(File dir) {
        this.homeDir = dir;
    }

    public synchronized boolean getIsOnline() {
        return this.isOnline;
    }

    /**
     * Set the online system status flag and update any Observers registered to
     * observe online status changes.
     *
     * @param online
     */
    public synchronized void setIsOnline(boolean online) {
        //if (online != this.isOnline) {
        this.isOnline = online;
        setChanged();
        notifyObservers();
        //}
    }

    /**
     * SystemStatusHolder is loaded on the first execution of
     * SystemStatus.getInstance() or the first access to
     * SystemStatusHolder.sysStatus, not before.
     */
    private static class SystemStatusHolder {

        public static final SystemStatus sysStatus = new SystemStatus();
    }

    //force non-instantiation
    private SystemStatus() {
    }

    /**
     * Get the shared, thread safe instance.
     *
     * @return
     */
    public static SystemStatus getInstance() {
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
        String homePath = SystemStatus.getInstance().getHomeDir().getAbsolutePath();
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + value;
        if (new File(homePath).exists()) {
            return true;
        } else {
            return false;
        }
    }

}
