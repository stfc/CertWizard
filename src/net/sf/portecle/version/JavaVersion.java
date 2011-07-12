/*
 * JavaVersion.java
 * This file is part of Portecle, a multipurpose keystore and certificate tool.
 *
 * Copyright © 2004 Wayne Grant, waynedgrant@hotmail.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package net.sf.portecle.version;

import java.util.StringTokenizer;

/**
 * Immutable version class constructed from a Java version string (ir without for the current JREs version).
 * The Java version takes the form:
 * <p>
 * major.middle.minor[_update][-identifier]
 * <p>
 * Object's of this class can be used to compare Java different versions. Note that for the purposes of
 * comparison the identifier is considered only in so much as it is present or not - its actual value is
 * unimportant. Therefore for two otherwise identical versions the presence of an identifier in one will make
 * it a lower version than the other. This is because standard identifier values have not been identified by
 * Oracle.
 */
public class JavaVersion
    implements Comparable<JavaVersion>
{
	/** Java version string */
	private String m_sJavaVersion;

	/** Java version's major number */
	private int m_iMajor;

	/** Java version's middle number */
	private int m_iMiddle;

	/** Java version's minor number */
	private int m_iMinor;

	/** Java version's update number */
	private int m_iUpdate;

	/** Java version's identifier */
	private String m_sIdentifier;

	/** Version string delimiter */
	private static final char VERSION_DELIMITER = '.';

	/** Start update number */
	private static final char START_UPDATE = '_';

	/** Start identifier */
	private static final char START_IDENTIFIER = '-';

	/**
	 * Construct a JavaVersion object for the current Java environment.
	 * 
	 * @throws VersionException If the Java version string cannot be parsed
	 */
	public JavaVersion()
	    throws VersionException
	{
		this(System.getProperty("java.version"));
	}

	/**
	 * Construct a JavaVersion object from the supplied string.
	 * 
	 * @param sJavaVersion The Java version string
	 * @throws VersionException If the Java version string cannot be parsed
	 */
	public JavaVersion(String sJavaVersion)
	    throws VersionException
	{
		// Store version number
		m_sJavaVersion = sJavaVersion;

		// Get indexes of update and identifier
		int iIndexUpdate = m_sJavaVersion.indexOf(START_UPDATE);
		int iIndexIdentifier = m_sJavaVersion.indexOf(START_IDENTIFIER);

		// Defaults for version, update and identifier
		String sVersion = null;
		String sUpdate = "0";
		String sIdentifier = null;

		// No update nor identifier
		if (iIndexUpdate == -1 && iIndexIdentifier == -1)
		{
			sVersion = m_sJavaVersion; // Version as a string
		}
		// Update but no identifier
		else if (iIndexUpdate != -1 && iIndexIdentifier == -1)
		{
			// Version as a string
			sVersion = m_sJavaVersion.substring(0, iIndexUpdate);
			// Update as a string
			sUpdate = m_sJavaVersion.substring(iIndexUpdate + 1);
		}
		// Identifier but no update
		else if (iIndexUpdate == -1 && iIndexIdentifier != -1)
		{
			// Version as a string
			sVersion = m_sJavaVersion.substring(0, iIndexIdentifier);
			// Identifier as a string
			sIdentifier = m_sJavaVersion.substring(iIndexIdentifier + 1);
		}
		// Update and identifier
		else
		{
			// Version as a string
			sVersion = m_sJavaVersion.substring(0, iIndexUpdate);
			// Update as a string
			sUpdate = m_sJavaVersion.substring(iIndexUpdate + 1, iIndexIdentifier);
			// Identifier as a string
			sIdentifier = m_sJavaVersion.substring(iIndexIdentifier + 1);
		}

		// Parse version string for major, middle and minor version numbers
		StringTokenizer strTok = new StringTokenizer(sVersion, "" + VERSION_DELIMITER);

		if (strTok.countTokens() != 3)
		{
			throw new VersionException(); // Don't have all three versions
		}

		// Get major version as a string, convert it to an integer, store it
		String sMajor = strTok.nextToken();
		try
		{
			m_iMajor = Integer.parseInt(sMajor);
		}
		catch (NumberFormatException ex)
		{
			throw new VersionException(ex);
		}

		if (m_iMajor < 0)
		{
			throw new VersionException(); // Less then 0
		}

		// Get middle version as a string, convert it to an integer, store it
		String sMiddle = strTok.nextToken();
		try
		{
			m_iMiddle = Integer.parseInt(sMiddle);
		}
		catch (NumberFormatException ex)
		{
			throw new VersionException(ex);
		}

		if (m_iMiddle < 0)
		{
			throw new VersionException(); // Less then 0
		}

		// Get minor version as a string, convert it to an integer, store it
		String sMinor = strTok.nextToken();
		try
		{
			m_iMinor = Integer.parseInt(sMinor);
		}
		catch (NumberFormatException ex)
		{
			throw new VersionException(ex);
		}

		if (m_iMinor < 0)
		{
			throw new VersionException(); // Less then 0
		}

		// Convert update to integer and store
		try
		{
			m_iUpdate = Integer.parseInt(sUpdate);
		}
		catch (NumberFormatException ex)
		{
			throw new VersionException(ex); // Not an integer
		}

		if (m_iUpdate < 0)
		{
			throw new VersionException(); // Less then 0
		}

		// Store identifier (if any)
		m_sIdentifier = sIdentifier;
	}

	/**
	 * Get Java version's major number.
	 * 
	 * @return Minor number
	 */
	public int getMajor()
	{
		return m_iMajor;
	}

	/**
	 * Get Java version's middle number.
	 * 
	 * @return Minor number
	 */
	public int getMiddle()
	{
		return m_iMiddle;
	}

	/**
	 * Get Java version's minor number.
	 * 
	 * @return Minor number
	 */
	public int getMinor()
	{
		return m_iMinor;
	}

	/**
	 * Get Java version's update number.
	 * 
	 * @return Update number or 0 if none
	 */
	public int getUpdate()
	{
		return m_iUpdate;
	}

	/**
	 * Get Java version's identifier.
	 * 
	 * @return Identifier or null if none
	 */
	public String getIdentifier()
	{
		return m_sIdentifier;
	}

	/**
	 * Compare this JavaVersion object with another object.
	 * 
	 * @param cmpJavaVersion Object to compare JavaVersion with
	 * @return 0 if the equal, -1 if less, 1 if more
	 * @throws ClassCastException if the specified object's type prevents it from being compared to this
	 *             Object
	 */
	@Override
	public int compareTo(JavaVersion cmpJavaVersion)
	{
		// Compare major number
		if (m_iMajor > cmpJavaVersion.getMajor())
		{
			return 1;
		}
		else if (m_iMajor < cmpJavaVersion.getMajor())
		{
			return -1;
		}

		// Compare middle number
		if (m_iMiddle > cmpJavaVersion.getMiddle())
		{
			return 1;
		}
		else if (m_iMiddle < cmpJavaVersion.getMiddle())
		{
			return -1;
		}

		// Compare minor number
		if (m_iMinor > cmpJavaVersion.getMinor())
		{
			return 1;
		}
		else if (m_iMinor < cmpJavaVersion.getMinor())
		{
			return -1;
		}

		// Compare update number
		if (m_iUpdate > cmpJavaVersion.getUpdate())
		{
			return 1;
		}
		else if (m_iUpdate < cmpJavaVersion.getUpdate())
		{
			return -1;
		}

		// Compare identifier - not values - just whether they are present or not
		String sCmpIdentifier = cmpJavaVersion.getIdentifier();

		if (m_sIdentifier == null && sCmpIdentifier != null)
		{
			return 1;
		}
		else if (m_sIdentifier != null && sCmpIdentifier == null)
		{
			return -1;
		}

		// Versions are equal
		return 0;
	}

	/**
	 * Is this Version object equal to another object?
	 * 
	 * @param object Object to compare Version with
	 * @return true if the equal, false otherwise
	 */
	@Override
	public boolean equals(Object object)
	{
		if (object == this)
		{
			return true;
		}

		if (!(object instanceof JavaVersion))
		{
			return false;
		}

		return compareTo((JavaVersion) object) == 0;
	}

	/**
	 * Returns a hash code value for the object.
	 * 
	 * @return The hash code
	 */
	@Override
	public int hashCode()
	{
		// Initialize hash total to non-zero value
		int iResult = 27;

		// For each component of the version Multiply total by 53 (odd prime) and add section
		iResult = 53 * iResult + m_iMajor;
		iResult = 53 * iResult + m_iMiddle;
		iResult = 53 * iResult + m_iMinor;
		iResult = 53 * iResult + m_iUpdate;
		return 53 * iResult + (m_sIdentifier == null ? 0 : 1);
	}

	/**
	 * Get a string representation of the Java version.
	 * 
	 * @return A string representation of the Java version
	 */
	@Override
	public String toString()
	{
		return m_sJavaVersion;
	}
}
