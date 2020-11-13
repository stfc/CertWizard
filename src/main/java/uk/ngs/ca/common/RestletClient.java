/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import org.restlet.Client;
import org.restlet.Context;
import org.restlet.data.Protocol;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Generate a new Restlet Client with some configuration already applied
 *
 * @author fou43474
 */
public class RestletClient {

    public static Client getClient() {
        Context context = new Context();
        context.getParameters().add("socketConnectTimeoutMs", String.valueOf(SysProperty.getTimeoutMilliSecs()));
        Client client = new Client(new Context(), Protocol.HTTPS);
        return client;
    }
}
