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

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * Utility class for certificate related functions. Stateless and thread safe.
 *
 * @author Xiao Wang
 * @author David Meredith (some modifications, javadoc)
 */
public class CertUtil {

    public enum DNAttributeType {
        CN, L, OU, O, C, E, EMAILADDRESS
    }

    /**
     * Return a version of the given DN that can be used with OpenCA e.g. for
     * issuing PKCS#10 certificate requests. The given distinguished name must
     * be separated using commas following RFC1779 or RFC 2253 and can also
     * contain the 'E' or 'EMAILADDRESS' attributes.
     * <p/>
     * The returned DN is in RFC2253 form, and may optionally prefix the DN with
     * the 'emailAddress=' attribute if addHostEmailAttributeIfPresent is true
     * and the given DN is considered a host cert (i.e. it contains a dot '.'
     * char).
     *
     * @param dn
     * @param addHostEmailAttributeIfPresent
     * @return A DN that is suitable for use with OpenCA.
     */
    public static String prepareDNforOpenCA(String dn, boolean addHostEmailAttributeIfPresent) {
        String ou = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.OU);
        String l = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.L);
        String cn = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.CN);
        String c = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.C);
        String o = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.O);
        String email = null;
        boolean hostcert = false;

        // Assuming 'toRenewCert' is a 'java.security.cert.X509Certificate'
        // the DN can be extracted using the following methods (with differing
        // results (note the E and EMAILADDRESS variations): 
        // 
        //System.out.println("subjectDN: "+toRenewCert.getSubjectDN().getName());
        //   subjectDN: C=UK,O=eScience,OU=CLRC,L=DL,CN=code-sign.ngs.dl.ac.uk,E=sct-certificates@stfc.ac.uk
        //System.out.println("x500.toString(): "+toRenewCert.getSubjectX500Principal().toString());
        //   x500.toString(): EMAILADDRESS=sct-certificates@stfc.ac.uk, CN=code-sign.ngs.dl.ac.uk, L=DL, OU=CLRC, O=eScience, C=UK
        //System.out.println("x500.getName(): "+toRenewCert.getSubjectX500Principal().getName());
        //   x500.getName(): 1.2.840.113549.1.9.1=#161b7363742d63657274696669636174657340737466632e61632e756b,CN=code-sign.ngs.dl.ac.uk,L=DL,OU=CLRC,O=eScience,C=UK
        //System.out.println("x500.getName(X500Principal.RFC2253)): "+toRenewCert.getSubjectX500Principal().getName(X500Principal.RFC2253));
        //   x500.getName(X500Principal.RFC2253)): 1.2.840.113549.1.9.1=#161b7363742d63657274696669636174657340737466632e61632e756b,CN=code-sign.ngs.dl.ac.uk,L=DL,OU=CLRC,O=eScience,C=UK
        //  if this is a host DN, then test to see if it contains an email attribute
        if (cn.contains(".")) {
            hostcert = true;
            if (addHostEmailAttributeIfPresent) {
                // if this is a host cert and the dn contains an email attribute, 
                // then include the email attribute in PKCS#10 dn. 
                String EMAILADDRESS = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.EMAILADDRESS);
                String E = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.E);
                if (EMAILADDRESS != null && !EMAILADDRESS.equals("")) {
                    email = EMAILADDRESS;
                } else if (E != null && !E.equals("")) {
                    email = E;
                }
            }
        }

        String attrDN;
        if (!hostcert) {
            // Should L be made optional ? 
            if (l == null || l.equals("")) {
                attrDN = ("CN=" + cn + ", OU=" + ou + ", O=" + o + ", C=" + c);
            } else {
                attrDN = ("CN=" + cn + ", L=" + l + ", OU=" + ou + ", O=" + o + ", C=" + c);
            }
        } else { //host certificate
            if (l == null || l.equals("")) {
                if (email != null) {
                    attrDN = ("emailAddress=" + email + ", CN=" + cn + ", OU=" + ou + ", O=" + o + ", C=" + c);
                } else {
                    attrDN = ("CN=" + cn + ", OU=" + ou + ", O=" + o + ", C=" + c);
                }
            } else {
                if (email != null) {
                    attrDN = ("emailAddress=" + email + ", CN=" + cn + ", L=" + l + ", OU=" + ou + ", O=" + o + ", C=" + c);
                } else {
                    attrDN = ("CN=" + cn + ", L=" + l + ", OU=" + ou + ", O=" + o + ", C=" + c);
                }
            }
        }
        return attrDN;
    }

    /**
     * Get the value of the specified DN attribute. The given dn must use the
     * comma char to separate attributes, ala RFC2253 or RFC1179.
     *
     * @param dn
     * @param attType
     * @return The value of the attribute, null if the attribute does not exist
     * or has an empty string value.
     */
    public static String extractDnAttribute(String dn, DNAttributeType attType) {
        //dn = dn.replace('/', ','); // consider host requests where CN=globusservice/host.dl.ac.uk
        String attribute = attType.name() + "=";

        int index = dn.indexOf(attribute);
        if (index == -1) {
            return null;
        }

        index = index + attribute.length();
        String result = dn.substring(index);
        int _index = result.indexOf(",");
        if (_index != -1) {
            result = result.substring(0, _index);
        }
        result = result.trim();
        if ("".equals(result)) {
            return null;
        }
        return result;
    }

    public static BigInteger getPrivateExponent(PrivateKey _privateKey) {
        RSAPrivateKey p = (RSAPrivateKey) _privateKey;
        return p.getPrivateExponent();
    }

    public static String asciiToHex(String ascii) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < ascii.length(); i++) {
            hex.append(Integer.toHexString(ascii.charAt(i)));
        }
        return hex.toString();
    }
}
