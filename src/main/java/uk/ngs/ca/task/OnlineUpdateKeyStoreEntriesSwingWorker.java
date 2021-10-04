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

import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.certwizard.gui.MainWindowPanel;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * For all the entries in the given {@link KeyStoreEntryWrapper} map, perform an
 * online status update against the CA. The task runs in a background worker
 * thread while the <tt>done()</tt> and <tt>process()</tt>
 * methods are executed in the AWT event dispatch thread to perform GUI updates.
 * <p>
 * If any certificate entries are updated, then the application's managed
 * keyStore is saved to file.
 * <p>
 * If you intend to use an Executor to run this SwingWorker, then beware of this
 * top 25 bug (SwingWorker can deadlock if one thread in the swingworker-pool)
 *
 * @author David Meredith
 * @see http://bugs.sun.com/view_bug.do;jsessionid=e13cfc6ea10a4ffffffffce8c9244b60e54d?bug_id=6880336
 */
public class OnlineUpdateKeyStoreEntriesSwingWorker extends SwingWorker<Void, Object[]> {

    private final Map<String, KeyStoreEntryWrapper> updateEntriesByAlias;
    private final ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    private final MainWindowPanel pane;
    private Exception exception = null;

    public OnlineUpdateKeyStoreEntriesSwingWorker(final Map<String, KeyStoreEntryWrapper> updateEntriesByAlias,
                                                  ClientKeyStoreCaServiceWrapper caKeyStoreModel, MainWindowPanel pane) {
        this.updateEntriesByAlias = updateEntriesByAlias;
        this.caKeyStoreModel = caKeyStoreModel;
        this.pane = pane;
    }

    @Override
    protected Void doInBackground() {
        try {

            if (!SystemStatus.getInstance().getIsOnline()) {
                // we are not online, so try to ping....
                if (!PingService.getPingService().isPingService()) {
                    return null; // no point if not online 
                }
            }

            // Run online update for each keyStore entry in application thread. 
            boolean updated = false;
            int i = 0;
            for (KeyStoreEntryWrapper keyStoreEntryWrapper : updateEntriesByAlias.values()) {
                // First check to see this runnable has not been interrupted, e.g. by cancel button. 
                if (isCancelled()) {
                    break;
                }

                if (caKeyStoreModel.onlineUpdateKeyStoreEntry(keyStoreEntryWrapper)) {
                    updated = true;
                }
                publish(new Object[0]);
                ++i;
            }
            // After updating all keyStore entries, write (reStore)
            // keyStore to file ONLY if any new certs were updated
            // (e.g. replacing CSRs with newly valid Certs). 
            if (updated) {
                caKeyStoreModel.getClientKeyStore().reStore();
            }

        } catch (KeyStoreException | CertificateException | IOException ex) {
            // swallow and log the exception
            Logger.getLogger(OnlineUpdateKeyStoreEntriesSwingWorker.class.getName()).log(Level.SEVERE, null, ex);
            this.exception = ex;
        }
        return null;
    }

    @Override
    public void done() {
        if (this.exception != null) {
            JOptionPane.showMessageDialog(null,
                    "Please contact the helpdesk. A backup of your keystore is located in:\n"
                            + SystemStatus.getInstance().getHomeDir().getAbsolutePath() + File.separator + ".ca\n"
                            + "Exeption message: " + this.exception.getMessage(),
                    "Keystore problem",
                    JOptionPane.WARNING_MESSAGE);
        }
        pane.updateKeyStoreGuiFromModel();
    }

    @Override
    protected void process(List<Object[]> chunks) {
        pane.updateKeyStoreGuiFromModel();
    }
}
