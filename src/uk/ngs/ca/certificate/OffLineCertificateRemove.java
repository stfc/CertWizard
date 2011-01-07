/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate;

import java.security.PublicKey;

import uk.ngs.ca.common.ClientCertKeyStore;

/**
 * This class can remove any selected certificate under offline.
 * @author xw75
 */
public class OffLineCertificateRemove {

    private char[] PASSPHRASE;
    private PublicKey publicKey = null;

    public OffLineCertificateRemove( char[] passphrase, PublicKey publicKey ){
        PASSPHRASE = passphrase;
        this.publicKey = publicKey;
    }

    /**
     * Checks if the selected certificate is removed from client certificate keystore file.
     * @return true if successful, otherwise false.
     */
    public boolean removeCertificate(){
        ClientCertKeyStore certKeyStore = new ClientCertKeyStore( PASSPHRASE );
        if( publicKey != null ){
            String alias = certKeyStore.getAlias(publicKey);
            return certKeyStore.removeEntry(alias);
        }else{
            return false;
        }
    }
}
