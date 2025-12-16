package com.tcs.sbi.util;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.Certificate;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import com.tcs.sbi.launcher.MandateLauncher;

public class MandateUtility {
	private static final Logger log = LogManager.getLogger(MandateLauncher.class);

	public static PrivateKey getCertKeys(String cerFileStream, String password) throws Exception {

		KeyStore keyStore = KeyStore.getInstance("PKCS12"); // , "BC");
		try (FileInputStream fis = new FileInputStream(cerFileStream)) {
			keyStore.load(fis, password.toCharArray());
		}
		String aliase = keyStore.aliases().nextElement();
		java.security.Key key = keyStore.getKey(aliase, password.toCharArray());

		return (PrivateKey) key;
	}

	public static PublicKey getPubkeyfrompath(String pubkeypath) {
		PublicKey pubkey;
		try {
			CertificateFactory certfactory = CertificateFactory.getInstance("X.509");
			FileInputStream fis = new FileInputStream(pubkeypath);
			java.security.cert.Certificate certificate = certfactory.generateCertificate(fis);

			pubkey = certificate.getPublicKey();
			return pubkey;
		} catch (Exception e) {

			return null;
		}
	}

	public static String generateReferenceNumber() {
		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		String unique_no = "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);

		return unique_no;
	}

	public static int returnMaxDays(int calMonth) {

		int maxDays = 0;

		if (calMonth == 1) {
			maxDays = 31;
		} else if (calMonth == 2) {
			maxDays = 28;
		} else if (calMonth == 3) {
			maxDays = 31;
		} else if (calMonth == 4) {
			maxDays = 30;
		} else if (calMonth == 5) {
			maxDays = 31;
		} else if (calMonth == 6) {
			maxDays = 30;
		} else if (calMonth == 7) {
			maxDays = 31;
		} else if (calMonth == 8) {
			maxDays = 31;
		} else if (calMonth == 9) {
			maxDays = 30;
		} else if (calMonth == 10) {
			maxDays = 31;
		} else if (calMonth == 11) {
			maxDays = 30;
		} else {
			maxDays = 31;
		}
		return maxDays;
	}

	public static String generateRefrenceNumber() {

		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		String unique_no = "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);

		return unique_no;

	}

	public static Timestamp getTimestamp() {
		Timestamp timestamp = null;
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
			String strTime = sdf.format(new Date());
			timestamp = Timestamp.valueOf(strTime);
		} catch (Exception e) {
			e.getMessage();
		}
		return timestamp;
	}

	public static String readorgcontentfromfile(String path, HashMap<String, Object> encdmap) throws IOException {

		String orgcontent = null;
		StringBuilder str = new StringBuilder();
		BufferedReader br = new BufferedReader(new FileReader(path));
		int lineCount = 0;
		try {

			while ((orgcontent = br.readLine()) != null) {

				str.append(orgcontent);
				str.append("\r\n");
				lineCount++;
			}

			if (lineCount > 0) {
				lineCount = lineCount - 1;
			}
			encdmap.put("totalnoofRecords", lineCount);

		} catch (IOException e) {

			e.printStackTrace();

		} finally {
			br.close();

		}

		return str.toString();
		// return
		// Base64.getEncoder().encodeToString(str.toString().getBytes("UTF-8"));
	}

	public static void createToProcessFolder(String folderName, String type) {
//		File toProcessPath =  new File(MandateLauncher.getToProcessPath() + File.separator + type + File.separator + folderName);
		try {
			Path basePath = Paths.get(MandateLauncher.getToProcessPath());
			Path toProcessPath = basePath.resolve(type).resolve(folderName).toAbsolutePath();

			Files.createDirectories(toProcessPath);

//			if (Files.exists(toProcessPath) && Files.isDirectory(toProcessPath)) {
//				System.out.println("Directory Created : " + toProcessPath);
//			} else {
//				System.out.println("Failed to create directory : " + toProcessPath);
//			}
		} catch (IOException e) {
			System.err.println("Error while creating the toProcessPath : " + e.getMessage());
		}
//		if(toProcessPath.exists()) {
//			System.out.println(toProcessPath.getAbsolutePath());
//			boolean created = toProcessPath.mkdirs();
//			System.out.println("Successfully created the to process folder");
//			if(!created) {
//				System.out.println("Failed to create toProcessPath directory: " + toProcessPath.getAbsolutePath());
//			}
//		}
	}

	public static void deleteDirectory(Path dir) throws IOException {
		if (!Files.exists(dir)) {
			System.out.println("File does not exists");
		} else {
			Files.walk(dir).sorted(Comparator.reverseOrder()).forEach(path -> {
				try {
					Files.delete(path);
				} catch (IOException e) {
					e.printStackTrace();
				}
			});
		}
	}

	public static void zipFolder(Path sourceFolderPath, Path zippedPath) throws IOException {
		try (ZipOutputStream zs = new ZipOutputStream(Files.newOutputStream(zippedPath))) {
			Files.walk(sourceFolderPath).filter(path -> !Files.isDirectory(path)).forEach(path -> {
				ZipEntry zipEntry = new ZipEntry(sourceFolderPath.relativize(path).toString());
				try {
					zs.putNextEntry(zipEntry);
					Files.copy(path, zs);
					zs.closeEntry();
//	                    System.out.println("Successfully Zipped");
				} catch (IOException e) {
					System.err.println(e);
				}
			});
		}
	}

	public static void createBackUp(String source, String backup) {
		try {
			Files.copy(Paths.get(source), Paths.get(backup), StandardCopyOption.REPLACE_EXISTING);
		} catch (Exception e) {
			System.out.println("Error while creating backup : " + e);
		}
	}

	public static boolean rsaEncryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor,
			boolean withIntegrityCheck) throws IOException {

		boolean encrypted = false;

		Security.addProvider(new BouncyCastleProvider());

		ArmoredOutputStream armoredOut = null;
		if (armor) {
			armoredOut = new ArmoredOutputStream(out);
			out = armoredOut;
		}

		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		OutputStream compressedOut = comData.open(bOut); // MUST be closed!

		PGPUtil.writeFileToLiteralData(compressedOut, PGPLiteralData.BINARY, new File(fileName));
		compressedOut.close(); // ❗ REQUIRED: finalizes ZIP structure

		JcePGPDataEncryptorBuilder encryptor = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
				.setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptor);

		encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC")
				.setSecureRandom(new SecureRandom()));

		byte[] bytes = bOut.toByteArray();

		OutputStream encryptedOut = null;
		try {
			encryptedOut = encGen.open(out, bytes.length);
		} catch (IOException e) {
			log.info("Exception in encryption (IO): " + e.getMessage());
			encrypted = false;
			return encrypted;
		} catch (PGPException e) {
			log.info("Exception in encryption (PGP): " + e.getMessage());
			encrypted = false;
			return encrypted;
		}

		encryptedOut.write(bytes);
		encryptedOut.close(); // close encrypted block

		if (armor) {
			armoredOut.close(); // finalize ascii armor
		}

		out.close();

		comData.close(); // safe to close AFTER compressedOut closed

		encrypted = true;
		return encrypted;
	}
}
