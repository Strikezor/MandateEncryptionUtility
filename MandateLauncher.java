package com.tcs.sbi.launcher;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import com.tcs.sbi.constants.ErrorConstants;
import com.tcs.sbi.constants.MandateConstants;
import com.tcs.sbi.main.MandateMain;
import com.tcs.sbi.util.MandateEncProperties;
import com.tcs.sbi.util.MandateUtility;

public class MandateLauncher {
	private static final Logger log = LogManager.getLogger(MandateLauncher.class);
	private static String loggerPath;
	private static String srcPath;
	private static String destPath;
	private static String zippedPath;
	private static String signedPath;
	private static String encryptedPath;
	private static String failedFilesPath;
	private static String backUpPath;
	public static String password = "PASSWORD@1";
	public static PrivateKey privateKey;
	public static PublicKey publicKey;
	public static PGPPublicKey pgpPublicKey;
	private static String threadSleepTimeString;
	private static int threadSleepTime;
	private static String publicKeyPath;
	private static String privateKeyPath;
	private static String tailName;
	private static String zippingFailedPath;
	private static String signingFailedPath;
	private static String encryptingFailedPath;
	private static String fileProcessLimitString;
	private static int fileProcessLimit;
	private static String toProcessPath;
	private static String nameStart;
	private static String nameEnd;
	private static String fileNameLengthString;
	private static int fileNameLength;
	private static String noOfDays;
	private static String sbiSrNo;
	

	public static String getSbiSrNo() {
		return sbiSrNo;
	}

	public static void setSbiSrNo(String sbiSrNo) {
		MandateLauncher.sbiSrNo = sbiSrNo;
	}

	public static String getNoOfDays() {
		return noOfDays;
	}

	public static void setNoOfDays(String noOfDays) {
		MandateLauncher.noOfDays = noOfDays;
	}

	public static String getFileNameLengthString() {
		return fileNameLengthString;
	}

	public static void setFileNameLengthString(String fileNameLengthString) {
		MandateLauncher.fileNameLengthString = fileNameLengthString;
	}

	public static String getNameStart() {
		return nameStart;
	}

	public static void setNameStart(String nameStart) {
		MandateLauncher.nameStart = nameStart;
	}

	public static String getNameEnd() {
		return nameEnd;
	}

	public static void setNameEnd(String nameEnd) {
		MandateLauncher.nameEnd = nameEnd;
	}

	public static String getToProcessPath() {
		return toProcessPath;
	}

	public static void setToProcessPath(String toProcessPath) {
		MandateLauncher.toProcessPath = toProcessPath;
	}

	public static int getFileProcesslimit() {
		return fileProcessLimit;
	}

	public static void setFileProcesslimit(int fileProcessLimit) {
		MandateLauncher.fileProcessLimit = fileProcessLimit;
	}

	public static String getEncryptingFailedPath() {
		return encryptingFailedPath;
	}

	public static void setEncryptingFailedPath(String encryptingFailedPath) {
		MandateLauncher.encryptingFailedPath = encryptingFailedPath;
	}

	public static String getSigningFailedPath() {
		return signingFailedPath;
	}

	public static void setSigningFailedPath(String signingFailedPath) {
		MandateLauncher.signingFailedPath = signingFailedPath;
	}

	public static String getZippingFailedPath() {
		return zippingFailedPath;
	}

	public static void setZippingFailedPath(String zippingFailedPath) {
		MandateLauncher.zippingFailedPath = zippingFailedPath;
	}

	public static String getTailName() {
		return tailName;
	}

	public static void setTailName(String tailName) {
		MandateLauncher.tailName = tailName;
	}

	public static String getPublicKeyPath() {
		return publicKeyPath;
	}

	public static void setPublicKeyPath(String publicKeyPath) {
		MandateLauncher.publicKeyPath = publicKeyPath;
	}

	public static String getPrivateKeyPath() {
		return privateKeyPath;
	}

	public static void setPrivateKeyPath(String privateKeyPath) {
		MandateLauncher.privateKeyPath = privateKeyPath;
	}

	public static String getLoggerPath() {
		return loggerPath;
	}

	public static String getBackUpPath() {
		return backUpPath;
	}

	public static void setBackUpPath(String backUpPath) {
		MandateLauncher.backUpPath = backUpPath;
	}

	public static void setLoggerPath(String loggerPath) {
		MandateLauncher.loggerPath = loggerPath;
	}

	public static String getSrcPath() {
		return srcPath;
	}

	public static void setSrcPath(String srcPath) {
		MandateLauncher.srcPath = srcPath;
	}

	public static String getDestPath() {
		return destPath;
	}

	public static void setDestPath(String destPath) {
		MandateLauncher.destPath = destPath;
	}

	public static String getZippedPath() {
		return zippedPath;
	}

	public static void setZippedPath(String zippedPath) {
		MandateLauncher.zippedPath = zippedPath;
	}

	public static String getSignedPath() {
		return signedPath;
	}

	public static void setSignedPath(String signedPath) {
		MandateLauncher.signedPath = signedPath;
	}

	public static PrivateKey getPrivateKey() {
		return privateKey;
	}

	public static void setPrivateKey(PrivateKey privateKey) {
		MandateLauncher.privateKey = privateKey;
	}

	public static PublicKey getPublicKey() {
		return publicKey;
	}

	public static void setPublicKey(PublicKey publicKey) {
		MandateLauncher.publicKey = publicKey;
	}

	public static PGPPublicKey getPgpPublicKey() {
		return pgpPublicKey;
	}

	public static void setPgpPublicKey(PGPPublicKey pgpPublicKey) {
		MandateLauncher.pgpPublicKey = pgpPublicKey;
	}

	public static String getFailedFilesPath() {
		return failedFilesPath;
	}

	public static void setFailedFilesPath(String failedFilesPath) {
		MandateLauncher.failedFilesPath = failedFilesPath;
	}

	static {
		try {
			loggerPath = MandateEncProperties.getInstance().getProperty(MandateConstants.LOGGER_FILEPATH.toString());
			Configurator.initialize(null, loggerPath + MandateConstants.LOGGER_FILENAME.toString() + ".properties");
			srcPath = MandateEncProperties.getInstance().getProperty("SOURCE_PATH");
			destPath = MandateEncProperties.getInstance().getProperty("DESTINATION_PATH");
			zippedPath = MandateEncProperties.getInstance().getProperty("ZIPPED_PATH");
			signedPath = MandateEncProperties.getInstance().getProperty("SIGNED_PATH");
			failedFilesPath = MandateEncProperties.getInstance().getProperty("FAILED_FILES_PATH");
			backUpPath = MandateEncProperties.getInstance().getProperty("BACKUP_PATH");
			zippingFailedPath = MandateEncProperties.getInstance().getProperty("ZIPPING_FAILED_PATH");
			signingFailedPath = MandateEncProperties.getInstance().getProperty("SIGNING_FAILED_PATH");
			encryptingFailedPath = MandateEncProperties.getInstance().getProperty("ENCRYPTING_FAILED_PATH");
			threadSleepTimeString = MandateEncProperties.getInstance().getProperty("THREAD_SLEEP_TIME");
			fileProcessLimitString = MandateEncProperties.getInstance().getProperty("FILE_PROCESS_LIMIT");
			fileProcessLimit = Integer.parseInt(fileProcessLimitString);
			publicKeyPath = MandateEncProperties.getInstance().getProperty("PUBLIC_KEY_PATH");
			privateKeyPath = MandateEncProperties.getInstance().getProperty("PRIVATE_KEY_PATH");
			toProcessPath = MandateEncProperties.getInstance().getProperty("TO_PROCESS_PATH");
			nameStart = MandateEncProperties.getInstance().getProperty("NAME_STARTS_WITH");
			nameEnd = MandateEncProperties.getInstance().getProperty("NAME_ENDS_WITH");
			fileNameLengthString = MandateEncProperties.getInstance().getProperty("FILE_NAME_LENGTH");
			noOfDays = MandateEncProperties.getInstance().getProperty("NO_OF_DAYS");
			sbiSrNo = MandateEncProperties.getInstance().getProperty("USER_ID");

			threadSleepTime = Integer.parseInt(threadSleepTimeString);
			fileNameLength = Integer.parseInt(fileNameLengthString);
			tailName = MandateEncProperties.getInstance().getProperty("TAIL_NAME");
			Security.addProvider(new BouncyCastleProvider());
			String password = "PASSWORD@1";
//			privateKey = MandateUtility.getCertKeys("E:\\Akshay\\I61076H2HSVR_20122022B61076.pfx", password);
			privateKey = MandateUtility.getCertKeys(privateKeyPath, password);
//			publicKey = MandateUtility.getPubkeyfrompath("E:\\Akshay\\I61076H2HSVR_20122022B61076_PUB.cer");
			publicKey = MandateUtility.getPubkeyfrompath(publicKeyPath);
			pgpPublicKey = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey,
					new java.util.Date()));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		while (true) {
			HashMap<String, Object> decdmap = new HashMap<String, Object>();
			String referenceNumber = "";
			log.info(
					"********************************  || AADESH_MANDATE_ENC UTILITY STARTED ||  ***********************************\n");

			try {
				boolean EODReached = true;
				Calendar cal = Calendar.getInstance();
				int dTm = Integer.parseInt(MandateLauncher.getNoOfDays());
				cal.add(Calendar.DATE, -dTm);
				String currMonth = "";
				String currentDate = "";
				int prevCalMonth = cal.get(Calendar.MONTH) + 1;
				int prevCalYear = cal.get(Calendar.YEAR);
				int prevCalDate = cal.get(Calendar.DATE);
				
				cal.add(Calendar.DATE, dTm);
				int currCalMonth = cal.get(Calendar.MONTH) + 1;
				int currCalYear = cal.get(Calendar.YEAR);
				int currCalDate = cal.get(Calendar.DATE);
				
				LocalDate startDate = LocalDate.of(prevCalYear, prevCalMonth, prevCalDate);
				LocalDate endDate = LocalDate.of(currCalYear, currCalMonth, currCalDate);

				File sourceFolder = new File(srcPath);
				File[] listOfFolders = sourceFolder.listFiles(File::isDirectory);

				for (File folder : listOfFolders) {
					String folderName = folder.getName();
					File[] files = folder.listFiles();

					if (files != null && files.length > 0) {
						log.info("Number of files found in " + folder.getName() + " is : " + files.length
								+ ", now starting the processing.");
						try {
							int cnt = 1;
							List<Path> batchFiles = new ArrayList<>();
							String toProcessFolderName = null;
							String currDate = new java.text.SimpleDateFormat("ddMMyyyy").format(new java.util.Date());

							for (File file : files) {
								referenceNumber = MandateUtility.generateReferenceNumber();
								decdmap.put("FileName", file.getName());
								decdmap.put("fileCopiedTime", MandateUtility.getTimestamp());
								decdmap.put("RefrenceNumber", referenceNumber);
								
								String[] parts = file.getName().split("-");
								String dateStr = parts[5];
								String finalName="";
								if(parts.length==8) {
									finalName = parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[4].substring(0,4) + MandateLauncher.getSbiSrNo() + "-" + currDate + "-" + parts[6] + "-" + parts[7];
								}
								
								DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyyyy");
								boolean flag = false;
								try {
									if (file.getName().length() == fileNameLength) {
										LocalDate fileDate = LocalDate.parse(dateStr, formatter);
										if ((fileDate.isEqual(startDate) || fileDate.isAfter(startDate)) && (fileDate.isEqual(endDate) || fileDate.isBefore(endDate))) {
											if (file.getName().contains(nameStart)
													&& file.getName().contains(nameEnd)) {
												flag = true;
											} else {
//												System.out.println("Filename validation failed");
												decdmap.put("Status", ErrorConstants.VALIDATION_FAILED.toString());
												decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
												decdmap.put("statusDEC", ErrorConstants.VALIDATION_FAILED.name().toString());
												decdmap.put("totalnoofRecords", "");
												decdmap.put("EncryptionType", "");
												decdmap.put("ERROR_CODE", ErrorConstants.ER001.name());
												log.info("FileName validation failed, Moving to path : " + Paths
														.get(failedFilesPath + File.separator + "NameValidationFailed"
																+ File.separator + folderName));
												Files.move(file.toPath(),
														Paths.get(failedFilesPath + File.separator
																+ "NameValidationFailed" + File.separator + folderName
																+ File.separator + file.getName()),
														StandardCopyOption.REPLACE_EXISTING);
											}
										} else {
//											System.out.println("Date Validation failed");
											log.info("Date validation failed, Moving to path : "
													+ Paths.get(failedFilesPath + File.separator
															+ "DateValidationFailed" + File.separator + folderName));
											Files.move(file.toPath(),
													Paths.get(failedFilesPath + File.separator + "DateValidationFailed"
															+ File.separator + folderName + File.separator
															+ file.getName()),
													StandardCopyOption.REPLACE_EXISTING);
										}
									} else {
										System.out.println("File Name length validation failed");
										log.info("File name length validation failed, Moving to path : "
												+ Paths.get(failedFilesPath + File.separator
														+ "NameLengthValidationFailed" + File.separator + folderName));
										Files.move(file.toPath(),
												Paths.get(failedFilesPath + File.separator
														+ "NameLengthValidationFailed" + File.separator + folderName
														+ File.separator + file.getName()),
												StandardCopyOption.REPLACE_EXISTING);
									}

								} catch (Exception e) {
//									System.out.println("Failed to do Filename validation, Moving to path : "
//											+ Paths.get(failedFilesPath + File.separator + "NameValidationFailed"
//													+ File.separator + folderName));
									log.info("Failed to validate the filename, Moving to path : "
											+ Paths.get(failedFilesPath + File.separator + "NameValidationFailed"
													+ File.separator + folderName));
									Files.move(file.toPath(),
											Paths.get(failedFilesPath + File.separator + "NameLengthValidationFailed"
													+ File.separator + folderName + File.separator + file.getName()),
											StandardCopyOption.REPLACE_EXISTING);
								}

								if (flag) {
									if (batchFiles.isEmpty()) {
										String tailName = getTailName();
										String srNo = String.format("%06d", cnt);
										toProcessFolderName = "MMS-" + folder.getName() + "-SBIN-SBIN" + tailName + "-"
												+ currDate + "-" + srNo + "-ACCEPT";
										MandateUtility.createToProcessFolder(toProcessFolderName, folder.getName());
										cnt++;
									}
									Path source = Paths.get(getSrcPath(), folder.getName(), file.getName());
									Path destDir = Paths.get(getToProcessPath(), folder.getName(), toProcessFolderName);
									Path dest = destDir.resolve(finalName);

									Files.createDirectories(destDir);
									if (Files.exists(source)) {
										Files.move(source, dest, StandardCopyOption.REPLACE_EXISTING);
										batchFiles.add(dest);
									} else {
										System.err.println("Source not found , skipping : " + source.toAbsolutePath());
									}

									if (batchFiles.size() == fileProcessLimit) {
										log.info("Batch ready (" + batchFiles.size()
												+ " files). Launching mandateMain for : " + destDir);
										ExecutorService service = Executors.newSingleThreadExecutor();
										Runnable aadeshMain = new MandateMain(destDir.toFile(), folder.getName());
										service.execute(aadeshMain);
										service.shutdown();

										batchFiles.clear();
										toProcessFolderName = null;
									}
								} else {
//										System.out.println("Failed to validate the filename, hence unable to add to batch");
									log.info("Failed to validate the filename, hence unable to add to batch");

								}
							}

							if (!batchFiles.isEmpty() && EODReached) {
								Path finalDir = batchFiles.get(0).getParent();
								log.info("Final batch (" + batchFiles.size()
										+ " files). Launching MandateMain for final dir : " + finalDir);

								ExecutorService service = Executors.newSingleThreadExecutor();
								Runnable aadeshMain = new MandateMain(finalDir.toFile(), folder.getName());
								service.execute(aadeshMain);
								service.shutdown();
								batchFiles.clear();
							}
						} catch (Exception e) {
//								System.out.println("Error executing the encryption task : " + e);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
							log.info("Error executing the encryption task : " + e.getMessage());
						}
					} else {
						files = folder.listFiles();
					}
				}
				log.info("There are no files available to process, hence thread is going to sleep for "
						+ threadSleepTime);
				System.out.println("There are no files available to process, hence thread is going to sleep for : "
						+ threadSleepTime);
				Thread.sleep(threadSleepTime);

			} catch (Exception e) {
				System.out.print("Error occured during validation :" + e);
			} finally {
				log.info(
						"********************************  || MANDATE_ENC UTILITY ENDED ||  ***********************************\n");
			}
		}
	}
}
