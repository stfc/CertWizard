/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.net.InetAddress;
import java.io.IOException;
import java.net.UnknownHostException;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ReachableServer {

     String serverURL = SysProperty.getValue("ngsca.base.http.url");
    public ReachableServer() {
    }

    public boolean isReachable( int secodes ) {
        boolean result = false;
        try {
            InetAddress address = InetAddress.getByName(serverURL);

            if( address.isReachable(secodes * 1000) ){
                result = true;
            }
        } catch (UnknownHostException e) {
            System.err.println("Unable to lookup " + serverURL);
        } catch (IOException e) {
            System.err.println("Unable to reach " + serverURL);
        } finally {
            return result;
        }
    }
    
}

