/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Toolkit;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.File;
import java.net.URL;
import java.util.Observer;
import java.util.Observable;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;
import org.globus.common.CoGProperties;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class CertWizardMain implements Observer{

    //private CardLayout cardLayout;
    private JFrame frame;
    private JTabbedPane jp;
    private JPanel getCertificatePanel;
    //private JPanel settingsPanel;
    //private JPanel useCertificatePanel;

    //private ComponentSettingsPanel settingsComponentPanel;

    //private RAOperationPanel raopPanel = null;
    //private RAUtilityPanel rautilPanel = null;


    public CertWizardMain() {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String title = SysProperty.getValue("ngsca.certwizard.version");
        frame = new JFrame( title );

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

        try{
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
            if(!truststore.exists() || !truststore.canRead()){
                throw new IllegalStateException("Trustore cannot be read"); 
            }

        } catch(Exception ex) {
            JOptionPane.showMessageDialog(null,ex.getMessage(),"Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }


        URL iconURL = CertWizardMain.class.getResource("/uk/ngs/ca/images/ngs-icon.png");
        if (iconURL != null) {
            frame.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }

        frame.setSize(880, 540);
        frame.setLocation(300, 200);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        jp = new JTabbedPane();
        //getCertificatePanel = new JPanel();
        //settingsPanel = new JPanel();
        //useCertificatePanel = new JPanel();
        //cardLayout = new CardLayout();

        initComponents();

        frame.getContentPane().add(BorderLayout.CENTER, jp);
        frame.setVisible(true);

    }

    /**
     * Checks if the ~/.globus directory exists. If not, it creates one.
     * Returns false if an error has occured
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
                        "[" + globusDir.getAbsolutePath() + "]  is not a directory.\n" +
                        "A .globus directory is needed in your HOME directory.\n" +
                        "However this directory could not be created: Either a file " +
                        "with that name already exists or you do not have the required permissions." +
                        "\nPlease either remove or rename the .globus file or ensure you have the necessary permissions, then restart this wizard.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }
    }

    /**
     * Checks if the ~/.ca directory exists. If not, it creates one.
     * Returns false if an error has occured
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
                        "[" + caDir.getAbsolutePath() + "]  is not a directory.\n" +
                        "A .ca directory is needed in your HOME directory.\n" +
                        "However this directory could not be created: Either a file " +
                        "with that name already exists or you do not have the required permissions." +
                        "\nPlease either remove or rename the .ca file or ensure you have the necessary permissions, then restart this wizard.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }
    }


    private void initComponents() {

        getCertificatePanel = new JPanel();
        JPanel settingsPanel = new JPanel();
        JPanel useCertificatePanel = new JPanel();
        jp.addTab("Apply For/Manage Your Certificate", getCertificatePanel);
        jp.addTab("Use Your Installed Certificate", useCertificatePanel);
        jp.addTab("Setup", settingsPanel);


        // First, create the settings/setup panel and the doActions panel.
        final ComponentSettingsPanel setupPanel = new ComponentSettingsPanel(this.frame);
        final DoActionsPanel doActions = new DoActionsPanel(this.frame);
        settingsPanel.add(setupPanel);
        useCertificatePanel.add(doActions);

     
        getCertificatePanel.setLayout(new CardLayout());
        getCertificatePanel.add(new ContactServerPanel(this), "ContactServer");
        //SystemStatus.ISONLINE = uk.ngs.ca.certificate.client.PingService.getPingService().isPingService();

        if (isExistPemFiles()) {
            jp.setSelectedComponent(useCertificatePanel);
        }

        /*if (isExistPemFiles()) {
            jp.setSelectedComponent(useCertificatePanel);
        } else {
            String _property = SysProperty.getValue("uk.ngs.ca.immegration.password.property");
            String _passphrase = System.getProperty(_property);
            if (_passphrase == null) {
                getCertificatePanel.add(new ContactServerPanel(this), "ContactServer");
            } else {
                cardLayout.show(getCertificatePanel, "MainWindowPanel");
            }
        }*/


       
        /*getCertificatePanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent evt) {
                getCertPanelComponentShown(evt);
            }
        });*/

        
        
        // Second, add componentListeners so that the panel's can be refreshed
        // when the appropriate tab is shown.
        settingsPanel.addComponentListener( new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent evt) {
                // we could refresh the dislay from this listener which will be
                // called whenever the settings tab is re-shown.
                //System.out.println("settings tab shown....");
                setupPanel.updateCertificateComponent();
            }
        });
        useCertificatePanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent evt) {
                // we need to refresh the display on the CertWizard's 'use certificate'
                // panel because we have chosen a new certificate.
                //System.out.println("use cert tab shown....");
                doActions.update();
            }
        });
    }
    



    public JPanel getCertificatePanel(){
        return this.getCertificatePanel;
    }

    public void update( Observable o, Object obj ){

    }

    
    //test only
    /*public void update( Observable o, Object obj ){
//comment it temperately for real ca server test.
        String _className = o.getClass().getSimpleName();
        if( _className.equals("CertWizardObservable") ){
            CertificateCSRInfo _info = (CertificateCSRInfo)obj;
            String _role = _info.getRole();
            
//            if( _role.equals("RA Operator") || _role.equals("CA Operator")){
//
//                WaitDialog.showDialog();
//                if( jp.getTabCount() != 5 ){
//                    String _id = _info.getId();
//                    CertificateDownload certDownload = new CertificateDownload(_id);
//                    if( ! certDownload.isCertificateExpired() ){
//                        jp.addTab("RA Operation", new RAOperationPanel( _info ));
//
//                        jp.addTab("RA Utilities", new RAUtilityPanel( _info ));
//                    }
//                }else{
//                    jp.remove( 4 );
//                    jp.remove(3);
//                }
//
//                WaitDialog.hideDialog();
//
//================///commented out as RA Utils tab is currently not supported!

//                WaitDialog.showDialog();
//                if( jp.getTabCount() != 5 ){
//                    String _id = _info.getId();
//                    CertificateDownload certDownload = new CertificateDownload(_id);
//                    if( ! certDownload.isCertificateExpired() ){
//                        if( ( this.raopPanel == null ) || ( this.rautilPanel == null ) ){
//                            this.raopPanel = new RAOperationPanel( _info );
//                            this.rautilPanel = new RAUtilityPanel( _info );
//                        }
//                        jp.addTab("RA Operation", this.raopPanel);
//                        jp.addTab("RA Utilities", this.rautilPanel);
//                    }
//
//                }else{
//                    jp.remove( 4 );
//                    jp.remove(3);
//                }
//                WaitDialog.hideDialog();

//================///
                
            }else{
                if( jp.getTabCount() == 5 ){
                    jp.remove( 4 );
                    jp.remove(3);
                }
            }
        }
    }*/

    /*private void getCertPanelComponentShown(ComponentEvent evt) {
        String _property = SysProperty.getValue("uk.ngs.ca.immegration.password.property");
        String _passphrase = System.getProperty(_property);

        if (_passphrase == null) {
            getCertificatePanel.removeAll();
            getCertificatePanel.add(new ContactServerPanel(this), "ContactServer");

            //calling revalidate() will display the GUI properly.
            getCertificatePanel.repaint();
            getCertificatePanel.revalidate();
        } else {
            cardLayout.show(getCertificatePanel, "MainWindowPanel");
        }
    }*/

    private boolean isExistPemFiles() {
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

    public static void main(String[] args) {
        CertWizardMain run = new CertWizardMain();
    }
}
