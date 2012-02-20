/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.awt.BorderLayout;
import java.awt.Toolkit;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.File;
import java.net.URL;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import org.globus.common.CoGProperties;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * The main frame class. 
 * 
 * @author Xiao Wang
 * @author David Meredith
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
        URL iconURL = CertWizardMain.class.getResource("/uk/ngs/ca/images/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String title = SysProperty.getValue("ngsca.certwizard.version");
        this.setTitle(title);
        //frame = new JFrame( title );
        //frame.setResizable(true);
        if (!checkGlobusDirectory()) {
            System.exit(0);
        }
        if (!checkCADirectory()) {
            System.exit(0);
        }

        // TODO - determine how the Apache http/https connector (org.apache.httpclient.jar)
        // determines the proxy settings to use. 
        //System.out.println("http.proxyHost "+System.getProperty("http.proxyHost"));
        //System.out.println("http.proxyPort "+System.getProperty("http.proxyPort"));

        try {
            SysProperty.setupTrustStore(); // throws IllegalStateException if prob
            String trustStoreFile = SysProperty.getValue("ngsca.truststore.file");
            String trustStorePath = System.getProperty("user.home");
            trustStorePath = trustStorePath + System.getProperty("file.separator") + ".ca";
            trustStorePath = trustStorePath + System.getProperty("file.separator") + trustStoreFile;

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

        // We want to ensure onlineStatusPanel can observe any changes in online system status
        // so that we can update its GUI accordingly.
        SystemStatus.getInstance().addObserver(onlineStatusPanel);

        //System.setProperty("http.proxyHost", "wwwnotexist.tr.ld");
        //System.setProperty("http.proxyHost", "wwwcache.dl.ac.uk");     
        // Run ping check in a new thread so we don't block while it tries to connect.
        onlineStatusPanel.runPingCheck();

        //Timer timer = new Timer();
        // execute once with no delay required.
        //timer.schedule(new runPingCheck(), 0); 
        // repeat every n millisecs with no delay (GUI will automatically update if the connection is lost).
        //timer.schedule(new runPingCheck(), 0, 10000); 

        this.getContentPane().add(BorderLayout.CENTER, this.tabbedPane);
        this.getContentPane().add(BorderLayout.SOUTH, this.onlineStatusPanel);
    }

    private void initTabbedPane() {
        JPanel tabPanelManageCerts = new JPanel();
        JPanel tabPanelSetup = new JPanel();
        JPanel tabPanelUseCert = new JPanel();
        tabbedPane.addTab("Apply For/Manage Your Certificate", tabPanelManageCerts);
        tabbedPane.addTab("Use Your Installed Certificate", tabPanelUseCert);
        tabbedPane.addTab("Setup", tabPanelSetup);

        // First, create the settings/setup panel and the doActions panel.
        final ComponentSettingsPanel setupPanel = new ComponentSettingsPanel(tabPanelSetup);
        final DoActionsPanel doActions = new DoActionsPanel(tabPanelUseCert);
        final PasswordPanel pp = new PasswordPanel(tabPanelManageCerts);

        tabPanelSetup.add(setupPanel);
        tabPanelUseCert.add(doActions);
        tabPanelManageCerts.add(pp);

        // if the user's pem files already exist in the default location, then 
        // set the focus on the Use Certifiate panel 
        if (doPemFilesExist()) {
            tabbedPane.setSelectedComponent(tabPanelUseCert);
        }

        // Second, add componentListeners so that the panel's can be refreshed
        // when the appropriate tab is shown.
        tabPanelSetup.addComponentListener(new ComponentAdapter() {

            @Override
            public void componentShown(ComponentEvent evt) {
                // we could refresh the dislay from this listener which will be
                // called whenever the settings tab is re-shown.
                //System.out.println("settings tab shown....");
                setupPanel.updateCertificateComponent();
            }
        });
        tabPanelUseCert.addComponentListener(new ComponentAdapter() {

            @Override
            public void componentShown(ComponentEvent evt) {
                // we need to refresh the display on the CertWizard's 'use certificate'
                // panel because we have chosen a new certificate.
                //System.out.println("use cert tab shown....");
                doActions.update();
            }
        });
    }

    /**
     * Checks if the ~/.globus directory exists. If not, it creates one. Returns
     * false if an error has occurred
     */
    private boolean checkGlobusDirectory() {
        //if(true)return false;
        File globusDir = new File(System.getProperty("user.home"), ".globus");
        if (globusDir.exists() && globusDir.isDirectory()) {
            return true;
        } else {
            // try to make the dir !
            if (globusDir.mkdir()) {
                return true;
            } else {
                JOptionPane.showMessageDialog(
                        null,
                        "[" + globusDir.getAbsolutePath() + "]  is not a directory.\n"
                        + "A .globus directory is needed in your HOME directory.\n"
                        + "However this directory could not be created: Either a file "
                        + "with that name already exists or you do not have the required permissions."
                        + "\nPlease either remove or rename the .globus file or ensure you have the necessary permissions, then restart this wizard.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }
    }

    /**
     * Checks if the ~/.ca directory exists. If not, it creates one. Returns
     * false if an error has occurred
     */
    private boolean checkCADirectory() {
        //if(true)return false;
        File caDir = new File(System.getProperty("user.home"), ".ca");
        if (caDir.exists() && caDir.isDirectory()) {
            return true;
        } else {
            // try to make the dir !
            if (caDir.mkdir()) {
                return true;
            } else {
                JOptionPane.showMessageDialog(
                        null,
                        "[" + caDir.getAbsolutePath() + "]  is not a directory.\n"
                        + "A .ca directory is needed in your HOME directory.\n"
                        + "However this directory could not be created: Either a file "
                        + "with that name already exists or you do not have the required permissions."
                        + "\nPlease either remove or rename the .ca file or ensure you have the necessary permissions, then restart this wizard.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }
    }

    /**
     * See if pem files already exist in default location
     */
    private boolean doPemFilesExist() {
        CoGProperties props = CoGProperties.getDefault();
        String certPemFile = props.getUserCertFile();
        String keyPemFile = props.getUserKeyFile();
        File fCertFile = new File(certPemFile);
        File fKeyFile = new File(keyPemFile);

        boolean fKeyExist = false;
        boolean fCertExist = false;
        if (fKeyFile.exists()) {
            fKeyExist = true;
        }
        if (fCertFile.exists()) {
            fCertExist = true;
        }
        if (fKeyExist && fCertExist) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenu2 = new javax.swing.JMenu();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setName("frame");

        jMenu1.setText("File");
        jMenuBar1.add(jMenu1);

        jMenu2.setText("Edit");
        jMenuBar1.add(jMenu2);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 863, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 506, Short.MAX_VALUE)
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
        try {
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
        }
        //</editor-fold>

        /*
         * Create and display the form
         */
        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                new CertWizardMain().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenuBar jMenuBar1;
    // End of variables declaration//GEN-END:variables
}
