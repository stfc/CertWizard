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
package uk.ngs.ca.certificate.management;

/**
 * @author xw75 (Xiao Wang)
 */
public class CertificateCSRInfo {

    private volatile String owner = null;
    private volatile String role = null;

    // The status returned by the server. TODO: 
    private volatile String status = null;
    private volatile String useremail = null;
    private volatile String id = null;
    private volatile String startdate = null;
    private volatile String enddate = null;
    private volatile String lifedays = null;
    private volatile String renew = null;
    private volatile String description = null;
    private volatile boolean isCSR = false;
    //private volatile String publickey = null;

    CertificateCSRInfo() {
        // package protected constructor
    }

    public void setIsCSR(boolean isCSR) {
        this.isCSR = isCSR;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setUserEmail(String useremail) {
        this.useremail = useremail;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setStartDate(String startdate) {
        this.startdate = startdate;
    }

    public void setEndDate(String enddate) {
        this.enddate = enddate;
    }

    public void setLifeDays(String lifedays) {
        this.lifedays = lifedays;
    }

    public void setRenew(String renew) {
        this.renew = renew;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getStatus() {
        return this.status;
    }

    public String getUserEmail() {
        return this.useremail;
    }

    public String getId() {
        return this.id;
    }

}
