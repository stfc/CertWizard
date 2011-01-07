/* Copyright 2009 NGS
 * This file is part of NGS CA project.
 */
package uk.ngs.ca.common;

import java.io.InputStream;
import java.io.ByteArrayInputStream;

import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

/**
 *
 * @author xw75
 */
public class XMLValidation {

    /*
     * Validate if the xml is valide based on the xml schema
     *
     * @return true if the validation is successfully, otherwise false
     * @param schemaStream xml schema
     * @param xmlStream xml inputstream
     *
     */
    public static boolean isValidation(InputStream schemaStream, InputStream xmlStream) {
        try {
            String schemaLang = "http://www.w3.org/2001/XMLSchema";
            SchemaFactory factory = SchemaFactory.newInstance(schemaLang);

            Schema schema = factory.newSchema(new StreamSource(schemaStream));
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(xmlStream));
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            return false;
        }
    }

    public static InputStream getInputStream(String string) {
        try {
            InputStream is = new ByteArrayInputStream( string.getBytes( ) );
            return is;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
}
