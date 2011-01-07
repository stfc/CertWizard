/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate;

import java.security.PrivateKey;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import java.util.Date;

import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;

/**
 * This class exports pkcs12 certificate and restore in local disk.
 * @author xw75
 */
public class ExportCertificateToFile {

    private String Message = null;
    private PrivateKey privateKey = null;
    private X509Certificate certificate = null;
    private File outFile = null;
    private char[] passphrase = null;

    public ExportCertificateToFile( X509Certificate certificate, PrivateKey privateKey, File outFile, char[] passphrase ){
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.outFile = outFile;
        this.passphrase = passphrase;
    }

    /**
     * Checks if exporting certificate to file successful
     * @return true if certificate is exported in a file, otherwise false.
     */
    public boolean isSuccessExport(){
        if( outFile == null ){
            Message = "You should select a file to export.";
            return false;
        }

        try{
            KeyStore outStore = PKCS12KeyStoreUnlimited.getInstance();
            outStore.load(null, null);
            long _alias = new Date().getTime();
            String alias = new Long( _alias ).toString();

            X509Certificate[] certs = new X509Certificate[1];
            certs[ 0 ] = certificate;
            outStore.setKeyEntry(alias, privateKey, passphrase, certs);

            FileOutputStream fos = new FileOutputStream(outFile);
            outStore.store(fos, passphrase);
            fos.close();
            Message = null;
            return true;
        }catch( NoSuchAlgorithmException nse ){
            nse.printStackTrace();
            Message = "There is no PKCS12 type keystore. " + nse.getMessage();
            return false;
        }catch( IOException ioe ){
            ioe.printStackTrace();
            Message = "IOException happens. " + ioe.getMessage();
            return false;
        }catch( KeyStoreException kse ){
            kse.printStackTrace();
            Message = "KeyStoreException happens. " + kse.getMessage();
            return false;
        }catch( CertificateException ce ){
            ce.printStackTrace();
            Message = "CertificateException happens. " + ce.getMessage();
            return false;
        }catch( NoSuchProviderException npe ){
            npe.printStackTrace();
            Message = "No BouncyCastle provider. " + npe.getMessage();
            return false;
        }
    }

    /**
     * Gets any error message.
     * @return error message. It will be null if isSuccessExport() is true.
     */
    public String getMessage(){
        return Message;
    }

}
