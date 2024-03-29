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
package uk.ngs.ca.task;

import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.BackgroundTask;
import uk.ngs.certwizard.gui.MainWindowPanel;

/**
 * For all the entries in the given {@link KeyStoreEntryWrapper} map, perform an
 * online status update against the CA. The task runs in a background worker
 * thread while the <tt>onCompletion()</tt> and <tt>onProgress()</tt>
 * methods are executed in the AWT event dispatch thread to perform GUI updates.
 * This class provides similar functionality as
 * {@link OnlineUpdateKeyStoreEntriesSwingWorker} but is compatible with JDK1.5.
 *
 * @deprecated use {@link OnlineUpdateKeyStoreEntriesSwingWorker} instead
 * (requires jdk1.6).
 * @author David Meredith
 */
public class OnlineUpdateKeyStoreEntries extends BackgroundTask<Void> {

    private final Map<String, KeyStoreEntryWrapper> updateEntriesByAlias;
    private final ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    //private final AtomicBoolean runningFlag;

    public OnlineUpdateKeyStoreEntries(final Map<String, KeyStoreEntryWrapper> updateEntriesByAlias,
            ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        this.updateEntriesByAlias = updateEntriesByAlias;
        this.caKeyStoreModel = caKeyStoreModel;
        //this.runningFlag = runningFlag;
    }

    @Override
    protected Void doInBackground() throws Exception {

        try {
            //runningFlag.set(true);
            if (!PingService.getPingService().isPingService()) {
                return null; // no point if not online 
            }
            // Run online update for each keyStore entry in application thread. 
            boolean updated = false;
            int i = 0;
            for (Iterator<KeyStoreEntryWrapper> it = updateEntriesByAlias.values().iterator(); it.hasNext();) {
                //for (Iterator<String> it = updateEntriesByAlias.iterator; it.hasNext();) {
                KeyStoreEntryWrapper keyStoreEntryWrapper = it.next();
                // First check to see this runnable has not been interrupted, e.g. by cancel button. 
                if (isCancelled()) {
                    break;
                }
                //Thread.sleep(2000); // to test 
                if (caKeyStoreModel.onlineUpdateKeyStoreEntry(keyStoreEntryWrapper)) {
                    updated = true;
                }
                // call setProgress which will call onProgress in the AWT event thread. 
                setProgress(i, caKeyStoreModel.getKeyStoreEntryMap().size());
                ++i;
            }
            // After updating all keyStore entries, write (reStore)
            // keyStore to file ONLY if any new certs were updated
            // (e.g. replacing CSRs with newly valid Certs). 
            if (updated) {
                caKeyStoreModel.getClientKeyStore().reStore();
            }

        } catch (Exception ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
        }
        return null;
    }

    @Override
    public void onCompletion(Void result, Throwable exception, boolean cancelled) {
        this.doNotifyObservers();
    }

    @Override
    public void onProgress(int current, int max) {
        this.doNotifyObservers();
    }

    private void doNotifyObservers() {
        this.setChanged();
        this.notifyObservers();
    }
}
