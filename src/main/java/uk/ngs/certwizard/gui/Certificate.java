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
package uk.ngs.certwizard.gui;

/**
 *
 * @author hyz38924
 */
public class Certificate {

    private String dn;
    private String vFrom;
    private String vTo;
    private String status;
    private String dRemaining;
    private String renDue;
    private String email;

    public void setDN(String dn) {
        this.dn = dn;
    }

    public void setVFrom(String vFrom) {
        this.vFrom = vFrom;
    }

    public void setVTo(String vTo) {
        this.vTo = vTo;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setDRemaining(String dRemaining) {
        this.dRemaining = dRemaining;
    }

    public void setRenDue(String renDue) {
        this.renDue = renDue;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getDN() {
        return this.dn;
    }

    public String getVFrom() {
        return this.vFrom;
    }

    public String getVTo() {
        return this.vTo;
    }

    public String getStatus() {
        return this.status;
    }

    public String getDRemaining() {
        return this.dRemaining;
    }

    public String getRenDue() {
        return this.renDue;
    }

    public String getEmail() {
        return this.email;
    }

    public String getCN() {
        int index = dn.indexOf("/CN");
        String cn = dn.substring(index);
        return cn;

    }
}
