/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.util;

import java.awt.Component;
import java.util.ResourceBundle;
import javax.swing.JOptionPane;
import net.sf.portecle.FPortecle;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;
import net.sf.portecle.gui.password.DGetNewPassword;
import net.sf.portecle.gui.password.DGetPassword;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * GUI helper class to change the keyStore protection password.
 *
 * @author David Meredith
 */
public class KeyStoreChangePasswordGuiHelper {

    private ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    private Component parentCompoent;
    //private char[] PASSPHRASE;

    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    /**
     * Portecle Resource bundle base name
     */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);

    public KeyStoreChangePasswordGuiHelper(Component parentCompoent, ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        this.parentCompoent = parentCompoent;
        this.caKeyStoreModel = caKeyStoreModel;
    }

    /**
     * Lead the user through the password change process.
     *
     * @return the new updated password or null if not changed or error.
     */
    public char[] changeKeyStorePassword() {
        //ask for the current password first.
        DGetPassword dGetPassword
                = new DGetPassword(null, "Enter the current Keystore Password");
        dGetPassword.setLocationRelativeTo(parentCompoent);
        SwingHelper.showAndWait(dGetPassword);

        char[] cPkcs12Password = dGetPassword.getPassword();

        if (cPkcs12Password == null) {
            return null; //user hit cancel button
        }

        String sPkcs12Password = new String(cPkcs12Password);
        String sCurrentPassword = new String(this.caKeyStoreModel.getPassword());

        if (!(sPkcs12Password.equals(sCurrentPassword))) {
            JOptionPane.showMessageDialog(parentCompoent, "The current keystore password you've entered is incorrect",
                    "Wrong Password", JOptionPane.ERROR_MESSAGE);
            return null;
        }

        // Get a new password for the new keystore password
        DGetNewPassword dGetNewPassword
                = new DGetNewPassword(null, RB.getString("FPortecle.SetKeyStorePassword.Title"));
        dGetNewPassword.setLocationRelativeTo(parentCompoent);
        SwingHelper.showAndWait(dGetNewPassword);

        char[] cPKCS12Password = dGetNewPassword.getPassword();

        if (cPKCS12Password == null) {
            return null; //user hit cancel button
        }

        if (new String(cPKCS12Password).trim().equals("")) {
            JOptionPane.showMessageDialog(parentCompoent, "Please enter a password for certificate keystore.",
                    "No Password Entered", JOptionPane.ERROR_MESSAGE);
            return null;
        }

        //set the new keystore password: set in passphrase.property as well as
        //the variable PASSPHRASE. Finally call the reStorePassword method in
        //ClientKeyStore to restore the keystore with the new password.
        String _pswdProperty = SysProperty.getValue("uk.ngs.ca.passphrase.property");
        String _pswd = new String(cPKCS12Password);
        System.setProperty(_pswdProperty, _pswd);
        try {
            this.caKeyStoreModel.getClientKeyStore().reStorePassword(cPKCS12Password);
            JOptionPane.showMessageDialog(parentCompoent, "Key Store password has successfully been changed",
                    "Password Change Successful", JOptionPane.INFORMATION_MESSAGE);
            return cPKCS12Password;

        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Password change error", ex);
            return null;
        }
    }
}
