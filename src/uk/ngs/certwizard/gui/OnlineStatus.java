package uk.ngs.certwizard.gui;

import java.awt.Color;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.common.GuiExecutor;

/**
 * Display the current online status of the tool and set the application's
 * <code>SystemStatus.ISONLINE</code> property. Thread safe.
 *
 * @author David Meredith
 */
public class OnlineStatus extends javax.swing.JPanel /*implements Observer*/ {

    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    // Records whether the last ping check completed ok 
    private AtomicBoolean pingedOK = new AtomicBoolean(false); 
    
    /**
     * Creates new form OnlineStatus
     */
    public OnlineStatus() {
        initComponents();
        this.timeoutTextField.setVisible(false);
        this.jLabel2.setVisible(false);
     }
    
    /**
     * Starts the periodic Ping task in a background thread. 
     */
    public void startScheduledPingCheckTask() {    
        // DM: I wanted to use a SwingWorker and a property change listener on the
        // SwingWorker 'state' property as this gives more control, however
        // this top 25 bug (SwingWorker deadlocks due to 
        // one thread in the swingworker-pool) caused me issues so i use a 
        // simple runnable instead. 
        // http://bugs.sun.com/view_bug.do;jsessionid=e13cfc6ea10a4ffffffffce8c9244b60e54d?bug_id=6880336 
        //pingTask = new PingTask();
        //pingTask.addPropertyChangeListener(pingTaskPropertyListener);
        executor.scheduleWithFixedDelay(new PingCheckTask(), 0, 10, TimeUnit.MINUTES);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        connectButton = new javax.swing.JButton();
        onlineLabel = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        timeoutTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();

        setToolTipText("Online CA status indicates whether the tool can contact the UK Certification Authority Server");

        connectButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/arrow_refresh_small.png"))); // NOI18N
        connectButton.setToolTipText("Attempt to ping the CA server to test online connection. ");
        connectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectButtonActionPerformed(evt);
            }
        });

        onlineLabel.setForeground(new java.awt.Color(255, 0, 51));
        onlineLabel.setText("Cannot Contact Server - Click help to configure connection.");

        jLabel1.setText("Online Status:");

        timeoutTextField.setText("8");
        timeoutTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                timeoutTextFieldActionPerformed(evt);
            }
        });
        timeoutTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                timeoutTextFieldFocusLost(evt);
            }
        });

        jLabel2.setText("Connect timeout (secs)");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(onlineLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 315, Short.MAX_VALUE)
                .addGap(30, 30, 30)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(timeoutTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(31, 31, 31)
                .addComponent(connectButton, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(connectButton, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
            .addComponent(timeoutTextField)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel1)
                .addComponent(onlineLabel)
                .addComponent(jLabel2))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void connectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectButtonActionPerformed
        //System.setProperty("http.proxyHost", "wwwcache.dl.ac.uk");
        this.doPingCheckActionPerformed();
    }//GEN-LAST:event_connectButtonActionPerformed

private void timeoutTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_timeoutTextFieldActionPerformed
// TODO add your handling code here:
    //this.doChangeTimeout();
}//GEN-LAST:event_timeoutTextFieldActionPerformed

private void timeoutTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_timeoutTextFieldFocusLost
// TODO add your handling code here:
    //this.doChangeTimeout();
}//GEN-LAST:event_timeoutTextFieldFocusLost

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton connectButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel onlineLabel;
    private javax.swing.JTextField timeoutTextField;
    // End of variables declaration//GEN-END:variables

    /*private void doHelpButtonActionPerformed(java.awt.event.ActionEvent evt) {
        JOptionPane.showMessageDialog(this, "todo",
                    "Configure Network Connection", JOptionPane.INFORMATION_MESSAGE);
    }*/

    /**
     * change the timeout value
     */
    /*private void doChangeTimeout() {
        try {
            String timeoutMilliSecs = this.timeoutTextField.getText();
            int timeout = Integer.parseInt(timeoutMilliSecs);
            if (timeout <= 0) {
                throw new NumberFormatException();
            }
            SysProperty.setTimeoutMilliSecs(timeout * 1000);
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Invalid timeout value. Please specify a number (timout in seconds)",
                    "Invalid timeout", JOptionPane.ERROR_MESSAGE);
            this.timeoutTextField.setText(String.valueOf(SysProperty.getTimeoutMilliSecs() / 1000));
        }
    }*/

    /**
     * Attempt a ping check and update our global state. 
     */
    private void doPingCheckActionPerformed() {
        // Clicking to start this task should not clash with another ping task 
        // because the button that calls this method is disabled when a task
        // executes. 
        Runnable sleepTask = new PingCheckTask(); 
        Thread t = new Thread(sleepTask); 
        t.setDaemon(true);
        t.start();
    }

    /**
     * Update this panels online status GUI components in the AWT event dispatch 
     * thread. Online status is based on the <code>SystemStatus.ISONLINE</code> property. 
     */
    /*public void update(Observable o, Object arg) {
        SwingUtilities.invokeLater(new Runnable() {

            public void run() {
                //System.out.println("Will print true: "+SwingUtilities.isEventDispatchThread()); 
                updateGUI();
            }
        });
    }*/
    
    /**
     * Updates the GUI. Guarantees to run the GUI updates in the AWT event dispatch thread. 
     * @param running 
     */
    private void updateGUI(final boolean running) {
        GuiExecutor.instance().execute( new Runnable() {
            public void run() {
                if (running) {
                    onlineLabel.setText("Pinging Server...");
                    onlineLabel.setForeground(Color.RED);
                    connectButton.setEnabled(false);
                } else {
                    Date lastOnline = new Date();
                    if(pingedOK.get()){
                        onlineLabel.setText("Last online check at:  " + lastOnline.toString());
                        onlineLabel.setForeground(new Color(0, 153, 0));
                    } else {
                        onlineLabel.setText("Last online check failed at:  " + lastOnline.toString());
                        onlineLabel.setForeground(Color.RED);
                    }
                    connectButton.setEnabled(true);
                }
            }
        });
    }
    
    

    private class PingCheckTask implements Runnable {
        @Override
        public void run() {
            try {
                updateGUI(true);
                // call the ping 
                pingedOK.set(PingService.getPingService().isPingService());   
            } finally {
                updateGUI(false);
            }
        }
    }
    
    /*private class SleepTask implements Runnable {
        @Override
        public void run() {
            try {
                updateGUI(true);
                try { Thread.sleep(3000);} catch(Exception ignore){}
            } finally {
                updateGUI(false);
            }
        }
    }*/
        
    
    /**
     * Handle onlineUpdateTask property changes (runs in AWT Event thread) 
     */    
   /* private PropertyChangeListener pingTaskPropertyListener = new PropertyChangeListener() {

        public void propertyChange(PropertyChangeEvent e) {
            String propertyName = e.getPropertyName();
            if ("progress".equals(propertyName)) {
                // not handled currently 
                System.out.println("progress called");
            } else if ("state".equals(propertyName)) {
                System.out.println("state change is: "+pingTask.getState());
                if (SwingWorker.StateValue.DONE.equals(pingTask.getState())) {
                    updateGUI(false);
                } else if (SwingWorker.StateValue.PENDING.equals(pingTask.getState())) {
                    updateGUI(true);
                } else if (SwingWorker.StateValue.STARTED.equals(pingTask.getState())) {
                    updateGUI(true);
                } else {
                    updateGUI(false);
                }
            }
        }
    };*/
    
    // I wanted to use a SwingWorker with a listener but beware of this 
    // top 25 bug: http://bugs.sun.com/view_bug.do;jsessionid=e13cfc6ea10a4ffffffffce8c9244b60e54d?bug_id=6880336 
    /*private class PingTask extends SwingWorker<Void, Object[]>{
        @Override
        protected Void doInBackground() throws Exception {
            PingService.getPingService().isPingService();
            return null; 
        }
        @Override
        public void done() {
            //System.out.println("done in AWT event dispatch thread");
            //updateGUI(false);
        }
    }*/
  
}
