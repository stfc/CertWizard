/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
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
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.common.ClientHostName;
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
