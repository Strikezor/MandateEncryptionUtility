package com.tcs.sbi.util;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
//import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import com.tcs.sbi.launcher.ACHEncryptionLuncher;

public class ACHEncryptionUtility {

	@SuppressWarnings("unused")
	private static final Logger log = LogManager.getLogger(ACHEncryptionLuncher.class);

	public static String Filesize(File file) {
		float c = file.length();
		int a = Math.round(c);
		return a + "bytes";
	}

	public static boolean extensionValidation(String input) {

		String fileExtension = FilenameUtils.getExtension(input);
		boolean extensionValidated = true;
		if (fileExtension.equals("txt")) {
			extensionValidated = true;
		} else {
			extensionValidated = false;
		}
		return extensionValidated;

	}

	public static String createAlphaNumericString(int keyLength) {

		SecureRandom rnd = new SecureRandom();
		StringBuilder sb = new StringBuilder(keyLength);
		for (int i = 0; i < keyLength; i++) {
			sb.append(ACHEncryptionLuncher.getALLOWED_CHARS()
					.charAt(rnd.nextInt(ACHEncryptionLuncher.getALLOWED_CHARS().length())));
		}
		return (sb.toString());

	}
	
	
	
	
	
	public static String generateRefrenceNumber() {

		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		String unique_no = "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);

		return unique_no;

	}
	

	public static String rmTrailSpace(String Data) {
		Data = Data.trim().replaceAll(" +", " ");

		if (Data.equalsIgnoreCase("")) {
			Data = "-";
		}
		Data = Data.toUpperCase();
		return Data;
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

	public static String unzip(String zipfilepath, String desDir) throws IOException {
		try (ZipFile zipFile = new ZipFile(zipfilepath)) {
			Enumeration<? extends ZipEntry> entries = zipFile.entries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				File file = new File(desDir, entry.getName());
				if (entry.isDirectory()) {
					file.mkdirs();
				} else {
					file.getParentFile().mkdirs();
					try (InputStream in = zipFile.getInputStream(entry);
							OutputStream out = new FileOutputStream(file)) {
						byte[] buffer = new byte[1024];
						int len;
						while ((len = in.read(buffer)) > 0) {
							out.write(buffer, 0, len);
						}
					}

				}
			}
		}
		return desDir;
	}

	public static boolean VerifyZipSign(File signedZip) throws Exception {
		boolean isSignValid = false;
		@SuppressWarnings("resource")
		ZipFile zipFile = new ZipFile(signedZip);
		ZipEntry manifestEntry = zipFile.getEntry("META-INF/MANIFEST.MF");
		ZipEntry signatureFileEntry = zipFile.getEntry("META-INF/CERT.SF");
		ZipEntry SignatureBlockEntry = zipFile.getEntry("META-INF/CERT.RSA");
		if (manifestEntry == null || signatureFileEntry == null || SignatureBlockEntry == null) {
			throw new SecurityException("Signature or manifest files are missing");

		}
		// Read the signature block file
		InputStream signBlockStream = zipFile.getInputStream(SignatureBlockEntry);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(signBlockStream);
		PublicKey publickey = cert.getPublicKey();

		java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
		signature.initVerify(publickey);
		InputStream sigFileStream = zipFile.getInputStream(signatureFileEntry);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = sigFileStream.read(buffer)) != -1) {
			signature.update(buffer, 0, len);

		}
		byte[] signToVerify = readAllBytes(signBlockStream);
		// Verify the signature
		isSignValid = signature.verify(signToVerify);
		if (isSignValid) {
			System.out.println("The Signature is valid");

		} else {
			System.out.println("The Signatue is invalid");
		}

		return isSignValid;

	}

	public static byte[] readAllBytes(InputStream inputsteam) throws IOException {

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		byte[] tempBuffer = new byte[1024];
		int bytesRead;
		while ((bytesRead = inputsteam.read(tempBuffer, 0, tempBuffer.length)) != -1) {
			buffer.write(tempBuffer, 0, bytesRead);
		}
		return buffer.toByteArray();
	}

	public static HashMap<String, String> rsaDecryptFile(InputStream in, PGPPrivateKey priK, String filename,
			File decfilePath) {
		HashMap<String, String> dMap = new HashMap<String, String>();

		dMap.put("FileName", filename);
		try {
			Security.addProvider(new BouncyCastleProvider());

			in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
			PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
			PGPEncryptedDataList enc;
			Object o = pgpF.nextObject();

			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();

			}

//			@SuppressWarnings("unchecked")
//			Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
//			PGPPrivateKey sKey = null;
//			PGPPublicKeyEncryptedData pbe = null;
//
//			while (sKey == null && it.hasNext()) {
//				pbe = it.next();
//				sKey = priK;
//
//			}
			@SuppressWarnings("unchecked")
			Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;

			while (sKey == null && it.hasNext()) {
				pbe = (PGPPublicKeyEncryptedData) it.next();
				sKey = priK;

			}

			if (sKey == null) {
				throw new IllegalArgumentException("Secret key for message not found.");
			}

			PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC")
					.setContentProvider("BC").build(sKey);

			InputStream clear = pbe.getDataStream(b);
			PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());

			Object message = plainFact.nextObject();

			if (message instanceof PGPCompressedData) {
				PGPCompressedData cData = (PGPCompressedData) message;
				PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(),  
						new JcaKeyFingerprintCalculator());

				message = pgpFact.nextObject();
			}

			if (message instanceof PGPLiteralData) {
				PGPLiteralData ld = (PGPLiteralData) message;
				InputStream unc = ld.getInputStream();
				// int ch;

				FileUtils.copyInputStreamToFile(unc, new File(decfilePath + File.separator + filename));

				in.close();

			} else if (message instanceof PGPOnePassSignatureList) {
				throw new PGPException("Encrypted message contains a signed message - not literal data.");
			} else {
				throw new PGPException("Message is not a simple encrypted file - type unknown.");
			}

			if (pbe.isIntegrityProtected()) {
				if (!pbe.verify()) {
					throw new PGPException("Message failed integrity check");
				}
			}

		} catch (PGPException e) {
			dMap.put("Error", "PGPDecryptionError");
		} catch (Exception e) {
			dMap.put("Error", "DecryptionError-File not exactly encrypted");
		}
		return dMap;

	}

	public static PrivateKey getCertKeys(String cerFileStream, String password) throws Exception {

		KeyStore keyStore = KeyStore.getInstance("PKCS12"); // , "BC");
		try (FileInputStream fis = new FileInputStream(cerFileStream)) {
			keyStore.load(fis, password.toCharArray());
		}
		String aliase = keyStore.aliases().nextElement();
		java.security.Key key = keyStore.getKey(aliase, password.toCharArray());

		return (PrivateKey) key;
	}

	public static PublicKey getPubkeyfrompath(String pupkeypath) {
		PublicKey pubkey;
		try {
			CertificateFactory certfactory = CertificateFactory.getInstance("X.509");
			FileInputStream fis = new FileInputStream(pupkeypath);
			Certificate certificate = certfactory.generateCertificate(fis);

			pubkey = certificate.getPublicKey();
			return pubkey;
		} catch (Exception e) {

			return null;
		}

	}

//	public static boolean verifysign(String siggnature, X509Certificate cert, String orgcontent)
//			throws CertificateException, Exception {
//		boolean isSignvalid = false;
//		byte[] digisignrecieved = null;
//		byte[] orginalContent = null;
//
//		try {
//
//			try {
//				digisignrecieved = Base64.getDecoder().decode(siggnature);
//				orginalContent = Base64.getDecoder().decode(orgcontent);
//
//			} catch (Exception e) {
//				e.getMessage();
//				isSignvalid = false;
//			}
//			CMSProcessableByteArray cmscontet = new CMSProcessableByteArray(orginalContent);
//			CMSSignedData signeddata = new CMSSignedData(digisignrecieved);
//			
//			SignerInformationStore singer = signeddata.getSignerInfos();
//			Collection<SignerInformation> signerinfo = singer.getSigners();
//
//			for (SignerInformation signerInformation : signerinfo) {
//				if (signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {
//
//					isSignvalid = true;
//				} else {
//
//					isSignvalid = false;
//				}
//			}
//
//		} catch (CMSException e) {
//			isSignvalid = false;
//		}
//
//		return isSignvalid;
//
//	}

	@SuppressWarnings("unused")
	public static String[] extractalldata(String decfile) {
		String[] extractedData = new String[3];
		try {
			File inputfile = new File(decfile);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docx = factory.newDocumentBuilder();
			Document doc = docx.parse(inputfile);
			doc.getDocumentElement().normalize();
			Element Rootelement = doc.getDocumentElement();

			Node orgContent = doc.getElementsByTagName("OrgContent").item(0);
			if (orgContent != null) {
				extractedData[0] = orgContent.getTextContent();
			}

			Node signature = doc.getElementsByTagName("Signature").item(0);
			if (signature != null) {
				extractedData[1] = signature.getTextContent();
			}

			Node certificate = doc.getElementsByTagName("Certificate").item(0);
			if (certificate != null) {
				extractedData[2] = certificate.getTextContent();
			}

		} catch (Exception e) {
			e.getMessage();
		}
		return extractedData;
	}

	public static X509Certificate getX509Certificate(byte[] cert) throws CertificateException, IOException {
		X509Certificate certificate = null;

		try {
			InputStream stream = new ByteArrayInputStream(cert);
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			certificate = (X509Certificate) certificateFactory.generateCertificate(stream);
			stream.close();
		} catch (Exception e) {
			e.getMessage();
		}

		return certificate;
	}

	public static X509Certificate LoadX509Certificate(String nPCICertPath) throws CertificateException, IOException {
		X509Certificate certificate = null;
		InputStream stream = new BufferedInputStream(new FileInputStream(nPCICertPath));
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory.generateCertificate(stream);
		stream.close();
		return certificate;
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

			if(lineCount>0){
				lineCount=lineCount-1;
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

	public static String signfilecontent(String file, PGPPrivateKey pgpPrivKey, String string)
			throws PGPException, UnsupportedEncodingException {
		Security.addProvider(new BouncyCastleProvider());
		ByteArrayOutputStream os = null;
		PGPContentSignerBuilder signerbuilder = new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, PGPUtil.SHA256);
		PGPSignatureGenerator signgenrator = new PGPSignatureGenerator(signerbuilder);
		signgenrator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
		try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
			os = new ByteArrayOutputStream();
			try (ArmoredOutputStream amos = new ArmoredOutputStream(os)) {
				byte[] buffer = new byte[4096];
				int byteread;
				while ((byteread = in.read(buffer)) != -1) {
					signgenrator.update(buffer, 0, byteread);

				}
				signgenrator.generate().encode(amos);

				return os.toString("UTF-8");
			}
		} catch (Exception e) {
			// TODO: handle exception
		}
		// TODO Auto-generated method stub
		return os.toString("UTF-8");
	}

	public static String SignedFilegenrator(String orgcontent, String signature, String certificate, String Filename)
			throws IOException {
		StringWriter writer = null;
		try {
			DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
			Document document = documentBuilder.newDocument();
			Element root = document.createElement("Envelope");
			document.appendChild(root);
			Element originalContentElement = document.createElement("OrgContent");
			originalContentElement.appendChild(document.createTextNode(orgcontent));
			root.appendChild(originalContentElement);
			Element signaturelement = document.createElement("Signature");
			signaturelement.appendChild(document.createTextNode(signature));
			root.appendChild(signaturelement);
			Element certificatelement = document.createElement("Certificate");
			certificatelement.appendChild(document.createTextNode(certificate));
			root.appendChild(certificatelement);
			TransformerFactory transformfact = TransformerFactory.newInstance();
			Transformer transform = transformfact.newTransformer();

			transform.setOutputProperty(OutputKeys.INDENT, "no");
			DOMSource domsource = new DOMSource(document);
			writer = new StringWriter();
			StreamResult streamresult = new StreamResult(writer);
			transform.transform(domsource, streamresult);
			String xmlWriter = writer.toString();

			FileUtils.writeStringToFile(new File(ACHEncryptionLuncher.getSignedFilePath() + File.separator + Filename),
					xmlWriter);

		} catch (Exception e) {
			e.printStackTrace();

		} finally {
			writer.close();

		}

		return Filename;
	}

	public static String base64Certificate(X509Certificate channelPubCert) {
		String base64encodedCert = "";
		try {
			byte[] certificateByte = channelPubCert.getEncoded();
			base64encodedCert = Base64.getEncoder().encodeToString(certificateByte);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return base64encodedCert;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static byte[] signfileContent(String orgcontent, PrivateKey privateKey, X509Certificate cert)
			throws CertificateEncodingException, OperatorCreationException, CMSException, IOException,
			InvalidKeyException, SignatureException {
		Security.addProvider(new BouncyCastleProvider());
		byte[] contentBytes = orgcontent.getBytes(StandardCharsets.UTF_8);

		CMSSignedDataGenerator cmsgenerator = new CMSSignedDataGenerator();
		ContentSigner contSign = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);

		cmsgenerator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(contSign,
						cert));
		List<Certificate> certList = new ArrayList();
		certList.add(cert);
		org.bouncycastle.util.Store certs = new JcaCertStore(certList);
		cmsgenerator.addCertificates(certs);
		CMSProcessableByteArray cmsdata = new CMSProcessableByteArray(contentBytes);
		CMSSignedData cmssignData = cmsgenerator.generate(cmsdata, true);

		try {
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(privateKey);
			sign.update(contentBytes);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		byte[] signdata = cmssignData.getEncoded();

		// String base64Sign = Base64.getEncoder().encodeToString(signdata);

		// System.out.println("Signature : "+base64Sign);
		return signdata;
	}

	public static X509Certificate x509certget(String privCerPath, String password) throws KeyStoreException {
		// TODO Auto-generated method stub
		Certificate cert = null;
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (FileInputStream ksfile = new FileInputStream(privCerPath)) {
			ks.load(ksfile, password.toCharArray());
			String Alias = ks.aliases().nextElement();
			cert = ks.getCertificate(Alias);
			if (cert instanceof X509Certificate) {
				return (X509Certificate) cert;
			} else {

			}
		} catch (Exception e) {
			e.printStackTrace();

		}
		return (X509Certificate) cert;
	}

	public static byte[] signedWithjavaSignature(String orgcontent, PrivateKey privkey)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		byte[] contentTosign = orgcontent.getBytes(StandardCharsets.UTF_8);

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privkey);
		sign.update(contentTosign);

		return sign.sign();
	}

	@SuppressWarnings("rawtypes")
	public static HashMap<String, Object> createCMSsign(String orgcontent, X509Certificate privCert, PrivateKey privKey,
			HashMap<String, Object> encdmap)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
		byte[] contentTosign = orgcontent.getBytes(StandardCharsets.UTF_8);
		CMSProcessableByteArray cmsdata = new CMSProcessableByteArray(contentTosign);
		CMSSignedDataGenerator cmsgenerator = new CMSSignedDataGenerator();
		ContentSigner contentsigner = null;
		try {
			contentsigner = new JcaContentSignerBuilder("SHA256withRSA").build((privKey));

		} catch (Exception e) {
			encdmap.put("SignError", e.getMessage());

		}

		List<X509Certificate> certList = new ArrayList<>();
		certList.add(privCert);
		org.bouncycastle.util.Store certs = new JcaCertStore(certList);
		cmsgenerator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(contentsigner,
						privCert));
		cmsgenerator.addCertificates(certs);
		CMSSignedData cmssigndata = cmsgenerator.generate(cmsdata, false);

		byte[] signeddatabytes = cmssigndata.getEncoded();
		String signed = org.bouncycastle.util.encoders.Base64.toBase64String(signeddatabytes);

		encdmap.put("Sign", signed);

		return encdmap;
	}

	public static String signWithCMSSignedDataGenerator(String orgcontent, CMSSignedDataGenerator cmsSignedData) {
		// TODO Auto-generated method stub
		byte[] orgconbyte = orgcontent.getBytes();
		CMSSignedData cmsdataaa = null;
		byte[] signedcontent = null;
		CMSProcessableByteArray cmsData = new CMSProcessableByteArray(orgconbyte);
		try {
			cmsdataaa = cmsSignedData.generate(cmsData, false);
		} catch (CMSException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			signedcontent = cmsdataaa.getEncoded();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String base64Signedcontent = Base64.getEncoder().encodeToString(signedcontent);
		System.out.println(base64Signedcontent);
		return base64Signedcontent;
	}

	public static boolean rsaEncryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor,
			boolean withIntegrityCheck) throws IOException {

		boolean encrypted = false;
		OutputStream cOut = null;
		PGPCompressedDataGenerator comData = null;

		try {
			Security.addProvider(new BouncyCastleProvider());

			if (armor) {
				out = new ArmoredOutputStream(out);

			}

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

			PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));

			JcePGPDataEncryptorBuilder c = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
					.setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC");

			PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(c);

			JcePublicKeyKeyEncryptionMethodGenerator d = new JcePublicKeyKeyEncryptionMethodGenerator(encKey)
					.setProvider(new BouncyCastleProvider()).setSecureRandom(new SecureRandom());

			cPk.addMethod(d);

			byte[] bytes = bOut.toByteArray();

			cOut = cPk.open(out, bytes.length);

			cOut.write((bytes));

			// Writer outputStreamWriter = new
			// OutputStreamWriter(cOut,"D:\\Development_Docs\\PGP\\Bulk\\"+fileName);

			// bout.write(cOut);
			// FileUtils.copyFile(new
			// File("D:\\Development_Docs\\PGP\\Bulk\\plain-text-common.pgp"),
			// cOut);

			encrypted = true;

		} catch (Exception e) {
			encrypted = false;
			e.printStackTrace();
		} finally {
			cOut.close();
			out.close();
			comData.close();
		}

		return encrypted;

	}

	public static String aesDecrypt(String key, String initVector, String encrypted)
			throws UnsupportedEncodingException {
		byte[] keyb = keyToB(key);
		byte[] ivb = keyToB(initVector);
		String dec = decrypt1(keyb, ivb, encrypted);
		return dec;

	}

	public static byte[] keyToB(String key) throws UnsupportedEncodingException {

		byte[] keybyte = Base64.getDecoder().decode(key.getBytes("UTF-8"));

		return keybyte;
	}

	public static String decrypt1(byte[] key, byte[] initVector, String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
	        return new String(original, "UTF-8");
		} catch (NoSuchAlgorithmException e) {
		    log.error("Algorithm not found: {}", e);
		} catch (NoSuchPaddingException e) {
		    log.error("Padding not found: {}",  e);
		} catch (InvalidKeyException e) {
		    log.error("Invalid key: {}", e);
		} catch (InvalidAlgorithmParameterException e) {
		    log.error("Invalid algorithm parameter: {}",  e);
		} catch (IllegalBlockSizeException e) {
		    log.error("Illegal block size: {}", e);
		} catch (BadPaddingException e) {
		    log.error("Bad padding: {}", e);
		} catch (UnsupportedEncodingException e) {
		    log.error("Unsupported encoding: {}", e);
		} catch (Exception e) {
		    log.error("An unexpected error occurred: {}", e);
		}

		return null;
	}

}
