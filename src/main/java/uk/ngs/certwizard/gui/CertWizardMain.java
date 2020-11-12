/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.awt.BorderLayout;
import java.awt.Toolkit;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * The main frame class.
 *
 * @author Xiao Wang
 * @author David Meredith (modifications)
 */
public class CertWizardMain extends javax.swing.JFrame {

    private OnlineStatus onlineStatusPanel = new OnlineStatus();
    private JTabbedPane tabbedPane = new JTabbedPane();

    /**
     * Creates new form CertWizardMainFrame
     */
    public CertWizardMain() {
        initComponents();
        setupFrame();
    }

    private void setupFrame() {
        this.setLayout(new BorderLayout());
        URL iconURL = CertWizardMain.class.getResource("/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String title = SysProperty.getValue("ngsca.certwizard.version");
        this.setTitle(title);

        this.createGlobusDirIfNotExistsShowWarnings();
        this.setupHomeDir();

        // TODO - determine how the Apache http/https connector (org.apache.httpclient.jar)
        // determines the proxy settings to use. 
        //System.out.println("http.proxyHost "+System.getProperty("http.proxyHost"));
        //System.out.println("http.proxyPort "+System.getProperty("http.proxyPort"));
        try {
            SysProperty.setupTrustStore(); // throws IllegalStateException if prob
            String trustStoreFile = SysProperty.getValue("ngsca.truststore.file");
            String trustStorePath = SystemStatus.getInstance().getHomeDir().getAbsolutePath();
            trustStorePath = trustStorePath + System.getProperty("file.separator") + ".ca";
            trustStorePath = trustStorePath + System.getProperty("file.separator") + trustStoreFile;
            System.out.println("trustStore file path [" + trustStorePath + "]");

            String password = SysProperty.getValue("ngsca.cert.truststore.password");
            System.setProperty("javax.net.ssl.trustStore", trustStorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", password);

            // check files exist and are readable
            File truststore = new File(trustStorePath);
            if (!truststore.exists() || !truststore.canRead()) {
                throw new IllegalStateException("Trustore cannot be read");
            }

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        this.initTabbedPane();

        // Here we start the ping task in the background so we need to: 
        // 1) maybe read a file for the webproxy host/port/username/password
        // 2) if file is not present, attempt to determine webproxy settings automatically (vole) 
        // 3) Can always fallback to a dialox  
        // 
        // This needs the proxy settings to be set correctly . 
        //System.setProperty("http.proxyHost", "wwwnotexist.tr.ld");
        //System.setProperty("http.proxyHost", "wwwcache.dl.ac.uk");     
        // Run ping check in a new thread so we don't block while it tries to connect.
        onlineStatusPanel.startScheduledPingCheckTask();

        //Timer timer = new Timer();
        // execute once with no delay required.
        //timer.schedule(new runPingCheck(), 0); 
        // repeat every n millisecs with no delay (GUI will automatically update if the connection is lost).
        //timer.schedule(new runPingCheck(), 0, 10000); 
        this.getContentPane().add(BorderLayout.CENTER, this.tabbedPane);
        this.getContentPane().add(BorderLayout.SOUTH, this.onlineStatusPanel);
        this.pack();
    }

    private void setupHomeDir() {
        // ********************* USE this for Java 1.6 (DONT forget to comment out the java.nio import above) 
        /*File homeDir = new File(System.getProperty("user.home"));
        SystemStatus.getInstance().setHomeDir(homeDir);
        File caDir = new File(homeDir, System.getProperty("file.separator") + ".ca");
        if (!caDir.exists()) {
            if (!caDir.mkdir()) {
                JOptionPane.showMessageDialog(null,
                        "Can't create '$HOME/.ca' dir. Please edit this directories permissions \n[" + caDir.getAbsolutePath() + "]",
                        "Error", JOptionPane.ERROR_MESSAGE);
                System.exit(0);
            }
        }
        // Check that caDir is a directory 
        if (!caDir.isDirectory()) {
            JOptionPane.showMessageDialog(null,
                    "'HOME/.ca' is not a directory. CWiz needs to store its configuration in the following dir: \n[" + caDir.getAbsolutePath() + "]",
                    "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }
        
        // See if the HOME/.ca directory is writable 
        boolean writable = true; 
        if(!caDir.canWrite()){
            writable = false; 
        }
        // Also need to create a tmp file to see if this dir is writable (can't just rely on 
        // caDir.canWrite() as this is not reliable due to java bug: 
        // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4787931 
        File tmp = null; 
        try{
            tmp = File.createTempFile("cwiztouchtmp", ".tmp", caDir); 
            writable = true; 
        } catch(IOException ex){
            writable = false; 
        } finally {
            try{ if(tmp!=null){tmp.delete(); }}catch(Exception ex){}
        }
        if (!writable) {
            JOptionPane.showMessageDialog(null,
                    "Can't write to 'HOME/.ca' directory. CWiz needs to store its configuration in the following dir: \n[" + caDir.getAbsolutePath() + "]",
                    "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }*/

        // ********************* USE this for Java 1.7 
        GetBootstrapDir bootDia = new GetBootstrapDir(this, true, ".ca");
        bootDia.setLocationRelativeTo(null);
        bootDia.setVisible(true);
        Path homeDir = bootDia.getBootDir();

        if (homeDir == null) {
            System.exit(0);
        } else if (homeDir.endsWith(".ca")) {
            homeDir = homeDir.getParent();
        }
        SystemStatus.getInstance().setHomeDir(homeDir.toFile());
        //*********************************
    }

    private void createGlobusDirIfNotExistsShowWarnings() {
        // Java 1.6 compatible

        // create home.globus dir as a precaution
        File globusDir = new File(System.getProperty("user.home") + System.getProperty("file.separator") + ".globus");
        if (!globusDir.exists()) {
            globusDir.mkdir();
        }

        boolean isDir = true;
        if (!globusDir.isDirectory()) {
            isDir = false;
        }

        // See if the HOME/.globus directory is writable 
        boolean writableDir = true;
        if (!globusDir.canWrite()) {
            writableDir = false;
        }
        // Also need to create a tmp file to see if this dir is writable (can't just rely on 
        // caDir.canWrite() as this is not reliable due to java bug: 
        // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4787931 
        File tmp = null;
        try {
            tmp = File.createTempFile("cwiztouchtmp", ".tmp", globusDir);
            writableDir = true;
        } catch (IOException ex) {
            writableDir = false;
        } finally {
            try {
                if (tmp != null) {
                    tmp.delete();
                }
            } catch (Exception ex) {
            }
        }

        if (!writableDir || !isDir) {
            JOptionPane.showMessageDialog(null,
                    "Can't write to 'HOME/.globus' directory. "
                    + "Globus needs to store configuration in the following dir: \n[" + globusDir.getAbsolutePath() + "]\n"
                    + "You will not be able to use MyProxy or grid-proxy-init. Please add this directory manually, provide write permissions and restart.",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void initTabbedPane() {
        JPanel tabPanelManageCerts = new JPanel();
        // JPanel tabPanelSetup = new JPanel();
        // JPanel tabPanelUseCert = new JPanel();
        tabbedPane.addTab("Apply For/Manage Your Certificate", tabPanelManageCerts);
        // JK comment out next 2 lines once other references to these things have gone
        // tabbedPane.addTab("Use Your Installed Certificate", tabPanelUseCert);
        // tabbedPane.addTab("Setup", tabPanelSetup);

        // Tidy up ComponentSettingsPanel and DoActionsPanel since no longer needed
        // First, create the settings/setup panel and the doActions panel.
        // final ComponentSettingsPanel setupPanel = new ComponentSettingsPanel(tabPanelSetup);
        // final DoActionsPanel doActions = new DoActionsPanel(tabPanelUseCert);
        final PasswordPanel pp = new PasswordPanel(tabPanelManageCerts);

        // tabPanelSetup.add(setupPanel);
        // tabPanelUseCert.add(doActions);
        tabPanelManageCerts.add(pp);

        // if the user's pem files already exist in the default location, then 
        // set the focus on the Use Certifiate panel 
        // if (doPemFilesExist()) {
        // tabbedPane.setSelectedComponent(tabPanelUseCert);
        // }
        // Second, add componentListeners so that the panel's can be refreshed
        // when the appropriate tab is shown.
        /*
        tabPanelSetup.addComponentListener(new ComponentAdapter() {

            @Override
            public void componentShown(ComponentEvent evt) {
                // we could refresh the dislay from this listener which will be
                // called whenever the settings tab is re-shown.
                //System.out.println("settings tab shown....");
                setupPanel.updateCertificateComponent();
            }
        });
         */
 /*
        tabPanelUseCert.addComponentListener(new ComponentAdapter() {

            @Override
            public void componentShown(ComponentEvent evt) {
                // we need to refresh the display on the CertWizard's 'use certificate'
                // panel because we have chosen a new certificate.
                //System.out.println("use cert tab shown....");
                doActions.update();
            }
        });
         */
    }

    /**
     * See if pem files already exist in default location
     */
//    private boolean doPemFilesExist() {
//        CoGProperties props = CoGProperties.getDefault();
//        String certPemFile = props.getUserCertFile();
//        String keyPemFile = props.getUserKeyFile();
//        File fCertFile = new File(certPemFile);
//        File fKeyFile = new File(keyPemFile);
//
//        boolean fKeyExist = false;
//        boolean fCertExist = false;
//        if (fKeyFile.exists()) {
//            fKeyExist = true;
//        }
//        if (fCertFile.exists()) {
//            fCertExist = true;
//        }
//        if (fKeyExist && fCertExist) {
//            return true;
//        } else {
//            return false;
//        }
//    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setName("frame"); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 678, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 431, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /*
         * Set the Nimbus look and feel
         */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /*
         * If Nimbus (introduced in Java SE 6) is not available, stay with the
         * default look and feel. For details see
         * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
 /*try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(CertWizardMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(CertWizardMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(CertWizardMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(CertWizardMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }*/
        //</editor-fold>

        /*
         * Create and display the form
         */
        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                CertWizardMain cw = new CertWizardMain();
                cw.setLocationRelativeTo(null);
                cw.setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    // End of variables declaration//GEN-END:variables
}
