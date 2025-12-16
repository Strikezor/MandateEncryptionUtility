package com.tcs.sbi.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.tcs.sbi.launcher.MandateLauncher;

public class MandateEncProperties {
	public static final Logger log = LogManager.getLogger(MandateLauncher.class);
//	E:\Akshay\MandateFilesStructure
//	private static final String PROPERTIES_FILE = "F:\\MandateEncryptionUtility\\MandateEncryptionFilesStructure\\PROPERTY_FILE\\ACHMandateEncProperties.properties";
	private static final String PROPERTIES_FILE = new File("../MandateEncryptionFilesStructure\\PROPERTY_FILE\\ACHMandateEncProperties.properties").getAbsolutePath();
//	private static final String PROPERTIES_FILE = new File("MandateEncryptionFilesStructure\\PROPERTY_FILE\\ACHMandateEncProperties.properties").getAbsolutePath();
	
	private static MandateEncProperties instance = new MandateEncProperties();
	private String propertyValue = null;
	Properties prop;
	
	InputStream bisCM = null;
	
	private MandateEncProperties() {
		loadProperties();
	}
	
	@Override
	protected void finalize() throws Throwable {
		super.finalize();
		unloadProperties();
	}
	
	private void unloadProperties() {
		log.info("Entering Method.");
		try {
			bisCM.close();
		}
		catch (Exception e) {
			log.error("Error in unloadProperties");
		}
		log.info("Exiting Method.");
	}
	
	private void loadProperties() {
		log.info("Entering Method.");
		
		try {
			bisCM = new FileInputStream(PROPERTIES_FILE);
		}
		catch (FileNotFoundException e1) {
			throw new RuntimeException(e1);
		}
		prop = new Properties();
		try {
			prop.load(bisCM);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		log.info("Exiting method.");
	}
	
	public String getProperty(String key) {
		propertyValue = prop.getProperty(key);
		if (null == propertyValue) {
			throw new RuntimeException("Missing the value of the key " + key + " in .properties file");
		}
		return propertyValue;
	}
	
	public static MandateEncProperties getInstance() {
		if (instance == null) {
			instance = new MandateEncProperties();
		}
		return instance;
	}
}
