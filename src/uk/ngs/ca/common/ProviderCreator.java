/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author xw75
 */
public class ProviderCreator {

    public static void launch() {
        Security.addProvider(new BouncyCastleProvider());
    }
}
