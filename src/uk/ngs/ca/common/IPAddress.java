/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.net.InetAddress;
import org.apache.log4j.Logger;

/**
 *
 * @author xw75
 */
public class IPAddress {

    static final Logger myLogger = Logger.getLogger(IPAddress.class);

    public static String getHostName() {
        try {
            myLogger.debug("[IPAddress]: getting host name");
            InetAddress addr = InetAddress.getLocalHost();
            return addr.getHostName();
        } catch (Exception e) {
            System.out.println("Exception = " + e.toString());
            myLogger.error("[IPAddress]: failed to get host name. " + e.toString());
            return null;
        }
    }

    public static String getIPAddress() {
        try {
            myLogger.debug("[IPAddress]: getting IP address");
            InetAddress addr = InetAddress.getLocalHost();
            return addr.getHostAddress();
        } catch (Exception e) {
            System.out.println("Exception = " + e.toString());
            myLogger.error("[IPAddress]: failed to get IP address. " + e.toString());
            return null;
        }
    }
}
