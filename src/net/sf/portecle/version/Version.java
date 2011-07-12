/*
 * Version.java
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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.StringTokenizer;

/**
 * Immutable version class constructed from a version string. Used to compare versions. Only allows for simple
 * versions strings made up of >= 0 integers separated by dots or something similar.
 */
public class Version
    implements Comparable<Version>, Serializable
{
	/** Holds the version "sections" that make up the version number. */
	private int[] iSections;

	/**
	 * Construct a Version object from the supplied string assuming that the string delimiter used is '.'.
	 * 
	 * @param sVersion The version string.
	 * @throws VersionException If the version string cannot be parsed.
	 */
	public Version(String sVersion)
	    throws VersionException
	{
		this(sVersion, ".");
	}

	/**
	 * Construct a Version object from the supplied string and delimiters.
	 * 
	 * @param sVersion The version string.
	 * @param sDelimiters The delimiters.
	 * @throws VersionException If the version string cannot be parsed.
	 */
	public Version(String sVersion, String sDelimiters)
	    throws VersionException
	{
		StringTokenizer strTok = new StringTokenizer(sVersion, sDelimiters);

		ArrayList<Integer> vSections = new ArrayList<Integer>();

		while (strTok.hasMoreTokens())
		{
			try
			{
				int i = Integer.parseInt(strTok.nextToken());
				if (i < 0)
				{
					throw new VersionException();
				}
				vSections.add(i);
			}
			catch (NumberFormatException ex)
			{
				throw new VersionException(ex);
			}
		}

		if (vSections.size() == 0)
		{
			iSections = new int[] { 0 };
		}
		else
		{
			iSections = new int[vSections.size()];

			for (int iCnt = 0; iCnt < vSections.size(); iCnt++)
			{
				iSections[iCnt] = Math.abs(vSections.get(iCnt));
			}
		}
	}

	/**
	 * Get the sections that make up the version. Trailing 0's originally supplied on construction will be
	 * included.
	 * 
	 * @return The version's sections.
	 */
	private int[] getSections()
	{
		return iSections.clone();
	}

	/**
	 * Compare this Version object with another object.
	 * 
	 * @param cmpVersion Object to compare Version with.
	 * @return 0 if the equal, -1 if less, 1 if more.
	 */
	@Override
	public int compareTo(Version cmpVersion)
	{
		int[] iCmpSections = cmpVersion.getSections();

		for (int iCnt = 0; iCnt < iSections.length && iCnt < iCmpSections.length; iCnt++)
		{
			if (iSections[iCnt] > iCmpSections[iCnt])
			{
				return 1;
			}
			else if (iSections[iCnt] < iCmpSections[iCnt])
			{
				return -1;
			}
		}

		if (iCmpSections.length > iSections.length)
		{
			for (int iCnt = iSections.length; iCnt < iCmpSections.length; iCnt++)
			{
				if (iCmpSections[iCnt] != 0)
				{
					return -1;
				}
			}
		}

		if (iSections.length > iCmpSections.length)
		{
			for (int iCnt = iCmpSections.length; iCnt < iSections.length; iCnt++)
			{
				if (iSections[iCnt] != 0)
				{
					return 1;
				}
			}
		}

		return 0;
	}

	/**
	 * Is this Version object equal to another object?
	 * 
	 * @param object Object to compare Version with.
	 * @return true if the equal, false otherwise.
	 */
	@Override
	public boolean equals(Object object)
	{
		if (object == this)
		{
			return true;
		}

		if (!(object instanceof Version))
		{
			return false;
		}

		return compareTo((Version) object) == 0;
	}

	/**
	 * Returns a hash code value for the object.
	 * 
	 * @return The hash code.
	 */
	@Override
	public int hashCode()
	{
		// Initialize hash total to non-zero value
		int iResult = 27;

		// For each component of the version...
		for (int iCnt = 0; iCnt < iSections.length; iCnt++)
		{
			// Multiply total by 53 (odd prime) and add section
			iResult = 53 * iResult + iSections[iCnt];
		}

		return iResult;
	}

	/**
	 * Get a string representation of the version. This will always be '.' delimited. Trailing 0's originally
	 * supplied on construction will be included.
	 * 
	 * @return A string representation of the version.
	 */
	@Override
	public String toString()
	{
		StringBuilder strBuff = new StringBuilder();

		for (int iCnt = 0; iCnt < iSections.length; iCnt++)
		{
			strBuff.append(iSections[iCnt]);

			if ((iCnt + 1) < iSections.length)
			{
				strBuff.append('.');
			}
		}

		return strBuff.toString();
	}
}
