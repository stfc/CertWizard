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
        return new Client(new Context(), Protocol.HTTPS);
    }
}
