/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.task;

import java.security.KeyStoreException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.SwingWorker;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.certwizard.gui.MainWindowPanel;

/**
 * For all the entries in the given <tt>ClientKeyStoreCaServiceWrapper</tt> 
 * perform an online status update against the CA. 
 * The task runs in a background worker thread while the <tt>done()</tt> and <tt>process()</tt> 
 * methods are executed in the AWT event dispatch thread to perform GUI updates. 
 * 
 * @author David Meredith 
 */
public class OnlineUpdateKeyStoreEntriesSwingWorker extends SwingWorker<Void, Object[]> {

    private final Map<String, KeyStoreEntryWrapper> updateEntriesByAlias;
    private final ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    private final MainWindowPanel pane;

    
    public OnlineUpdateKeyStoreEntriesSwingWorker(final Map<String, KeyStoreEntryWrapper> updateEntriesByAlias,
            ClientKeyStoreCaServiceWrapper caKeyStoreModel, MainWindowPanel pane) {
        this.updateEntriesByAlias = updateEntriesByAlias;
        this.caKeyStoreModel = caKeyStoreModel;
        this.pane = pane;
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
                //if(false){
                if (caKeyStoreModel.onlineUpdateKeyStoreEntry(keyStoreEntryWrapper)) {
                    updated = true;
                }
                //}
                // call setProgress which will call onProgress in the AWT event thread. 
                //setProgress(i, caKeyStoreModel.getKeyStoreEntryMap().size());
                publish(new Object[0]);
                ++i;
            }
            // After updating all keyStore entries, write (reStore)
            // keyStore to file ONLY if any new certs were updated
            // (e.g. replacing CSRs with newly valid Certs). 
            if (updated) {
                caKeyStoreModel.getClientKeyStore().reStore();
            }


        } catch (KeyStoreException ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
        }
        return null;
    }

    @Override
    public void done() {
        //System.out.println("done in swing worker");
        pane.updateKeyStoreGuiFromModel();
    }

    @Override
    protected void process(List<Object[]> chunks) {
        //System.out.println("process called in swing worker");
        pane.updateKeyStoreGuiFromModel();
    }
}
