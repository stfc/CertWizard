/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.common;

/**
 *
 * @author xw75
 */
public class ClientHostName {
    public static String getHostName() {
        try {
            java.net.InetAddress localMachine = java.net.InetAddress.getLocalHost();
            return localMachine.getCanonicalHostName();
        } catch (java.net.UnknownHostException uhe) {
            //handle exception
            uhe.printStackTrace();
            return null;
        }
    }

}
