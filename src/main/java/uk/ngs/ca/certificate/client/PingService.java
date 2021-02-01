/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.certificate.client;

import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Header;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.data.Status;
import org.restlet.util.Series;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * Ping the server.
 *
 * @author xw75
 */
public final class PingService {

    private PingService() {  // force non-instantiation with private constructor.
    }

    /**
     * Get the shared, thread safe PingService instance.
     *
     * @return
     */
    public static PingService getPingService() {
        return PingServiceHolder.pingService;
    }

    /**
     * PingServiceHolder is loaded on the first execution of
     * PingService.getInstance() or the first access to
     * PingServiceHolder.pingService, not before.
     */
    private static class PingServiceHolder {

        public static final PingService pingService = new PingService();
    }

    /**
     * Ping the CA server with a ping request.
     *
     * @return true if successful ping otherwise false.
     */
    public boolean isPingService() {
        boolean isPing = false;
        Response response = null;
        try {
            String pingURL = SysProperty.getValue("uk.ngs.ca.request.pingservice.url");

            Client client = RestletClient.getClient();
            Request request = new Request(Method.GET, new Reference(pingURL));

            Series<Header> headers = request.getHeaders();
            headers.set("LocalHost", ClientHostName.getHostName());
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);
            System.out.println("pinging URL [" + pingURL + "]");

            response = client.handle(request);
            if (response.getStatus().equals(Status.SUCCESS_OK)) {
                isPing = true;
            }

            // change the systems online status and update any observers. 
            SystemStatus.getInstance().setIsOnline(isPing);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            // ensure that the response is fully read. 
            try {
                response.getEntity().getStream().close();
            } catch (Exception ex) {
            }
            return isPing;
        }

    }
}
