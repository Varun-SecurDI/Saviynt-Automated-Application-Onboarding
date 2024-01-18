package com.methods.apponboarding;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HttpsURLConnection;
import org.apache.poi.ss.usermodel.DataFormatter;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.json.JSONObject;

public class connection {
	
	
//method for retrieving access token
	public static String accesstoken(String pasword) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    keyPairGen.initialize(2048);
    KeyPair pair = keyPairGen.generateKeyPair();   
    PublicKey publicKey = pair.getPublic();  
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] input = pasword.getBytes();    
    cipher.update(input);
    byte[] cipherText = cipher.doFinal();  
    cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
    byte[] decipheredText = cipher.doFinal(cipherText);
    String decyrptpassword=new String(decipheredText);
    URL url = new URL("https://securdi-partner.saviyntcloud.com/ECM/api/login");
    HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
    connection.setRequestMethod("POST");
    connection.setDoOutput(true);
    connection.setRequestProperty("Content-Type", "application/json");
    String body = "{\"username\":\"apiuser\",\"password\":\""+decyrptpassword+"\"}";  
    DataOutputStream outputStream = new DataOutputStream(connection.getOutputStream());
    outputStream.writeBytes(body);
    outputStream.flush();
    outputStream.close();
    int responseCode = connection.getResponseCode();
    System.out.println("Response code for Access Token Generation : " + responseCode);
    InputStream inputStream = connection.getInputStream();
    Scanner scanner = new Scanner(inputStream);
    String responseBody = scanner.useDelimiter("\\A").next();
    System.out.println("Response body: " + responseBody);
    JSONObject jsonObject = new JSONObject(responseBody);
    String accessToken = jsonObject.getString("access_token");
    System.out.println("Access Token: " + accessToken);
    scanner.close();
    connection.disconnect();   
     
    return accessToken;
	}
//method for database connector
	public static String dbconnector(String accessToken, Sheet sheet1) throws IOException {
		
		
		
		DataFormatter dataFormatter = new DataFormatter();
		
		//Loop for reading data from excel file and creating security system
        for (int rowNum = 1; rowNum <= sheet1.getLastRowNum(); rowNum++) {
            Row row1 = sheet1.getRow(rowNum); 
            
            String Connectiontype = dataFormatter.formatCellValue(row1.getCell(0));
            String ConnectionName = dataFormatter.formatCellValue(row1.getCell(1));
            String DriverName = dataFormatter.formatCellValue(row1.getCell(2));
            String UserName = dataFormatter.formatCellValue(row1.getCell(3));
            String Password = dataFormatter.formatCellValue(row1.getCell(4));
            String URL = dataFormatter.formatCellValue(row1.getCell(5));
            String ACCOUNTSIMPORT = dataFormatter.formatCellValue(row1.getCell(6));
            String CREATEACCOUNTJSON = dataFormatter.formatCellValue(row1.getCell(7));
            String CONNECTIONPROPERTIES = dataFormatter.formatCellValue(row1.getCell(8));
            String PASSWORD_MIN_LENGTH = dataFormatter.formatCellValue(row1.getCell(9));
            String PASSWORD_MAX_LENGTH = dataFormatter.formatCellValue(row1.getCell(10));
            String PASSWORD_NOOFCAPSALPHA = dataFormatter.formatCellValue(row1.getCell(11));
            String PASSWORD_NOOFDIGITS = dataFormatter.formatCellValue(row1.getCell(12));
            String PASSWORD_NOOFSPLCHARS = dataFormatter.formatCellValue(row1.getCell(13));
            String UPDATEACCOUNTJSON = dataFormatter.formatCellValue(row1.getCell(14));
            String GRANTACCESSJSON = dataFormatter.formatCellValue(row1.getCell(15));
            String REVOKEACCESSJSON = dataFormatter.formatCellValue(row1.getCell(16));
            String CHANGEPASSJSON = dataFormatter.formatCellValue(row1.getCell(17));
            String DELETEACCOUNTJSON = dataFormatter.formatCellValue(row1.getCell(18));
            String ENABLEACCOUNTJSON = dataFormatter.formatCellValue(row1.getCell(19));
            String DISABLEACCOUNTJSON = dataFormatter.formatCellValue(row1.getCell(20));
            String ACCOUNTEXISTSJSON = dataFormatter.formatCellValue(row1.getCell(21));
            String UPDATEUSERJSON = dataFormatter.formatCellValue(row1.getCell(22));
            String ENTITLEMENTVALUEIMPORT = dataFormatter.formatCellValue(row1.getCell(23));
            String ROLEOWNERIMPORT = dataFormatter.formatCellValue(row1.getCell(24));
            String ROLESIMPORT = dataFormatter.formatCellValue(row1.getCell(25));
            String SYSTEMIMPORT = dataFormatter.formatCellValue(row1.getCell(26));
            String USERIMPORT = dataFormatter.formatCellValue(row1.getCell(27));
            String MODIFYUSERDATAJSON = dataFormatter.formatCellValue(row1.getCell(28));
            String STATUS_THRESHOLD_CONFIG = dataFormatter.formatCellValue(row1.getCell(29));
            String MAX_PAGINATION_SIZE = dataFormatter.formatCellValue(row1.getCell(30));
            String CLI_COMMAND_JSON = dataFormatter.formatCellValue(row1.getCell(31));
        
        
        System.out.println("Connectiontype: " + Connectiontype);
        System.out.println("ConnectionName: " + ConnectionName);
        System.out.println("DriverName: " + DriverName);
        System.out.println("UserName: " + UserName);
        System.out.println("Password: " + Password);
        System.out.println("URL: " + URL);
        System.out.println("ACCOUNTSIMPORT: " + ACCOUNTSIMPORT);
        System.out.println("CREATEACCOUNTJSON: " + CREATEACCOUNTJSON);
        System.out.println("CONNECTIONPROPERTIES: " + CONNECTIONPROPERTIES);
        System.out.println("PASSWORD_MIN_LENGTH: " + PASSWORD_MIN_LENGTH);
        System.out.println("PASSWORD_MAX_LENGTH: " + PASSWORD_MAX_LENGTH);
        System.out.println("PASSWORD_NOOFCAPSALPHA: " + PASSWORD_NOOFCAPSALPHA);
        System.out.println("PASSWORD_NOOFDIGITS: " + PASSWORD_NOOFDIGITS);
        System.out.println("PASSWORD_NOOFSPLCHARS: " + PASSWORD_NOOFSPLCHARS);
        System.out.println("UPDATEACCOUNTJSON: " + UPDATEACCOUNTJSON);
        System.out.println("GRANTACCESSJSON: " + GRANTACCESSJSON);
        System.out.println("REVOKEACCESSJSON: " + REVOKEACCESSJSON);
        System.out.println("CHANGEPASSJSON: " + CHANGEPASSJSON);
        System.out.println("DELETEACCOUNTJSON: " + DELETEACCOUNTJSON);
        System.out.println("ENABLEACCOUNTJSON: " + ENABLEACCOUNTJSON);
        System.out.println("DISABLEACCOUNTJSON: " + DISABLEACCOUNTJSON);
        System.out.println("ACCOUNTEXISTSJSON: " + ACCOUNTEXISTSJSON);
        System.out.println("UPDATEUSERJSON: " + UPDATEUSERJSON);
        System.out.println("ENTITLEMENTVALUEIMPORT: " + ENTITLEMENTVALUEIMPORT);
        System.out.println("ROLEOWNERIMPORT: " + ROLEOWNERIMPORT);
        System.out.println("ROLESIMPORT: " + ROLESIMPORT);
        System.out.println("SYSTEMIMPORT: " + SYSTEMIMPORT);
        System.out.println("USERIMPORT: " + USERIMPORT);
        System.out.println("MODIFYUSERDATAJSON: " + MODIFYUSERDATAJSON);
        System.out.println("STATUS_THRESHOLD_CONFIG: " + STATUS_THRESHOLD_CONFIG);
        System.out.println("MAX_PAGINATION_SIZE: " + MAX_PAGINATION_SIZE);
        System.out.println("CLI_COMMAND_JSON: " + CLI_COMMAND_JSON);
        //not working 
		
	                    URL url1 = new URL("https://securdi-partner.saviyntcloud.com/ECM/api/v5/testConnection");
	                    Map<String, Object> param = new LinkedHashMap<>();
	                    param.put("connectiontype", Connectiontype);
	                    param.put("connectionName", ConnectionName);
	                    param.put("URL", URL);
	                    param.put("USERNAME", UserName);
	                    param.put("PASSWORD", Password);
	                    param.put("DRIVERNAME", DriverName);
	                    param.put("CONNECTIONPROPERTIES", CONNECTIONPROPERTIES);
	                    param.put("PASSWORD_MIN_LENGTH", PASSWORD_MIN_LENGTH);
	                    param.put("PASSWORD_MAX_LENGTH", PASSWORD_MAX_LENGTH);
	                    param.put("PASSWORD_NOOFCAPSALPHA", PASSWORD_NOOFCAPSALPHA);
	                    param.put("PASSWORD_NOOFDIGITS", PASSWORD_NOOFDIGITS);
	                    param.put("PASSWORD_NOOFSPLCHARS", PASSWORD_NOOFSPLCHARS);
	                    param.put("CREATEACCOUNTJSON", CREATEACCOUNTJSON);
	                    param.put("UPDATEACCOUNTJSON", UPDATEACCOUNTJSON);
	                    param.put("GRANTACCESSJSON", GRANTACCESSJSON);
	                    param.put("REVOKEACCESSJSON", REVOKEACCESSJSON);
	                    param.put("CHANGEPASSJSON", CHANGEPASSJSON);
	                    param.put("DELETEACCOUNTJSON", DELETEACCOUNTJSON);
	                    param.put("ENABLEACCOUNTJSON", ENABLEACCOUNTJSON);
	                    param.put("DISABLEACCOUNTJSON", DISABLEACCOUNTJSON);
	                    param.put("ACCOUNTEXISTSJSON", ACCOUNTEXISTSJSON);
	                    param.put("UPDATEUSERJSON", UPDATEUSERJSON);
	                    param.put("ACCOUNTSIMPORT", ACCOUNTSIMPORT);
	                    param.put("ENTITLEMENTVALUEIMPORT", ENTITLEMENTVALUEIMPORT);
	                    param.put("ROLEOWNERIMPORT", ROLEOWNERIMPORT);
	                    param.put("ROLESIMPORT", ROLESIMPORT);
	                    param.put("SYSTEMIMPORT", SYSTEMIMPORT);
	                    param.put("USERIMPORT", USERIMPORT);
	                    param.put("MODIFYUSERDATAJSON", MODIFYUSERDATAJSON);
	                    param.put("STATUS_THRESHOLD_CONFIG", STATUS_THRESHOLD_CONFIG);
	                    param.put("MAX_PAGINATION_SIZE", MAX_PAGINATION_SIZE);
	                    param.put("CLI_COMMAND_JSON", CLI_COMMAND_JSON);
        
	                    StringBuilder postData = new StringBuilder();

	                    for (Map.Entry<String, Object> para : param.entrySet()) {
	                        if (postData.length() != 0) postData.append('&');
	                        postData.append(URLEncoder.encode(para.getKey(), "UTF-8"));
	                        postData.append('=');
	                        postData.append(URLEncoder.encode(String.valueOf(para.getValue()), "UTF-8"));
	                    }

	                    byte[] postDataBytes = postData.toString().getBytes("UTF-8");
	                    HttpsURLConnection connection1 = (HttpsURLConnection) url1.openConnection();
	                    connection1.setRequestMethod("POST");
	                    connection1.setDoOutput(true);
	                    connection1.setRequestProperty("Authorization","Bearer " + accessToken);
	                    connection1.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded");
	                    connection1.setRequestProperty( "charset", "utf-8");
	                    connection1.setUseCaches( true );
	                    connection1.getOutputStream().write(postDataBytes);

	                    int responseCode2 = connection1.getResponseCode();
	                    System.out.println("Connection Creation Response : " + responseCode2); 

	                    BufferedReader in = new BufferedReader(new InputStreamReader(connection1.getInputStream()));
	                    String inputLine;
	                    StringBuilder response = new StringBuilder();
	                    
	                    while ((inputLine = in.readLine()) != null) {
	                        response.append(inputLine);
	                    }
	                    
	                    System.out.println("Details of Connection: " + response);
	                    in.close();
	                    connection1.disconnect();
	                             
        }
		return null;
	}		
	
//method for salesforce connector

	public static String sfconnector(String accessToken, Sheet sheet2) throws IOException{
		DataFormatter dataFormatter1 = new DataFormatter();
		
        for (int rowNum = 1; rowNum <= sheet2.getLastRowNum(); rowNum++) {
            Row row2 = sheet2.getRow(rowNum);
            
            String Connectiontype = dataFormatter1.formatCellValue(row2.getCell(0));
            String ConnectionName = dataFormatter1.formatCellValue(row2.getCell(1));
            String CLIENTID = dataFormatter1.formatCellValue(row2.getCell(2));
            String CLIENTSECRET = dataFormatter1.formatCellValue(row2.getCell(3));
            String REFRESHTOKEN = dataFormatter1.formatCellValue(row2.getCell(4));
            String REDIRECT_URI = dataFormatter1.formatCellValue(row2.getCell(5));
            String INSTANCE_URL = dataFormatter1.formatCellValue(row2.getCell(6));
            String OBJECT_TO_BE_IMPORTED = dataFormatter1.formatCellValue(row2.getCell(7));
            String FEATURE_LICENSE_JSON = dataFormatter1.formatCellValue(row2.getCell(8));
            String CUSTOM_CREATEACCOUNT_URL = dataFormatter1.formatCellValue(row2.getCell(9));
            String CREATEACCOUNTJSON = dataFormatter1.formatCellValue(row2.getCell(10));
            String ACCOUNT_FILTER_QUERY = dataFormatter1.formatCellValue(row2.getCell(11));
            String FIELD_MAPPING_JSON = dataFormatter1.formatCellValue(row2.getCell(12));
            String MODIFYACCOUNTJSON = dataFormatter1.formatCellValue(row2.getCell(13));
            String STATUS_THRESHOLD_CONFIG = dataFormatter1.formatCellValue(row2.getCell(14));
            String CUSTOMCONFIGJSON = dataFormatter1.formatCellValue(row2.getCell(15));
            String PAM_CONFIG = dataFormatter1.formatCellValue(row2.getCell(16));
        
		
        System.out.println("Connectiontype: " + Connectiontype);
        System.out.println("ConnectionName: " + ConnectionName);
        System.out.println("CLIENTID: " + CLIENTID);
        System.out.println("CLIENTSECRET: " + CLIENTSECRET);
        System.out.println("REFRESHTOKEN: " + REFRESHTOKEN);
        System.out.println("REDIRECT_URI: " + REDIRECT_URI);
        System.out.println("INSTANCE_URL: " + INSTANCE_URL);
        System.out.println("OBJECT_TO_BE_IMPORTED: " + OBJECT_TO_BE_IMPORTED);
        System.out.println("FEATURE_LICENSE_JSON: " + FEATURE_LICENSE_JSON);
        System.out.println("CUSTOM_CREATEACCOUNT_URL: " + CUSTOM_CREATEACCOUNT_URL);
        System.out.println("CREATEACCOUNTJSON: " + CREATEACCOUNTJSON);
        System.out.println("ACCOUNT_FILTER_QUERY: " + ACCOUNT_FILTER_QUERY);
        System.out.println("FIELD_MAPPING_JSON: " + FIELD_MAPPING_JSON);
        System.out.println("MODIFYACCOUNTJSON: " + MODIFYACCOUNTJSON);
        System.out.println("STATUS_THRESHOLD_CONFIG: " + STATUS_THRESHOLD_CONFIG);
        System.out.println("CUSTOMCONFIGJSON: " + CUSTOMCONFIGJSON);
        System.out.println("PAM_CONFIG: " + PAM_CONFIG);
        
	                	URL url2 = new URL("https://securdi-partner.saviyntcloud.com/ECM/api/v5/testConnection");
	                    Map<String, Object> param1 = new LinkedHashMap<>();
	                    param1.put("connectiontype", Connectiontype);
	                    param1.put("connectionName", ConnectionName);
	                    param1.put("CLIENTID", CLIENTID);
	                    param1.put("CLIENTSECRET", CLIENTSECRET);
	                    param1.put("REFRESHTOKEN", REFRESHTOKEN);
	                    param1.put("REDIRECT_URI", REDIRECT_URI);
	                    param1.put("INSTANCE_URL", INSTANCE_URL);
	                    param1.put("OBJECT_TO_BE_IMPORTED", OBJECT_TO_BE_IMPORTED);
	                    param1.put("FEATURE_LICENSE_JSON", FEATURE_LICENSE_JSON);
	                    param1.put("CUSTOM_CREATEACCOUNT_URL", CUSTOM_CREATEACCOUNT_URL);
	                    param1.put("CREATEACCOUNTJSON", CREATEACCOUNTJSON);
	                    param1.put("ACCOUNT_FILTER_QUERY", ACCOUNT_FILTER_QUERY);
	                    param1.put("FIELD_MAPPING_JSON", FIELD_MAPPING_JSON);
	                    param1.put("MODIFYACCOUNTJSON", MODIFYACCOUNTJSON);
	                    param1.put("STATUS_THRESHOLD_CONFIG", STATUS_THRESHOLD_CONFIG);
	                    param1.put("CUSTOMCONFIGJSON", CUSTOMCONFIGJSON);
	                    param1.put("PAM_CONFIG", PAM_CONFIG);
        
	                    StringBuilder postData1 = new StringBuilder();

	                    for (Map.Entry<String, Object> para1 : param1.entrySet()) {
	                        if (postData1.length() != 0) postData1.append('&');
	                        postData1.append(URLEncoder.encode(para1.getKey(), "UTF-8"));
	                        postData1.append('=');
	                        postData1.append(URLEncoder.encode(String.valueOf(para1.getValue()), "UTF-8"));
	                    }

	                    byte[] postDataBytes1 = postData1.toString().getBytes("UTF-8");
	                    HttpsURLConnection connection2 = (HttpsURLConnection) url2.openConnection();
	                    connection2.setRequestMethod("POST");
	                    connection2.setDoOutput(true);
	                    connection2.setRequestProperty("Authorization","Bearer " + accessToken);
	                    connection2.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded");
	                    connection2.setRequestProperty( "charset", "utf-8");
	                    connection2.setUseCaches( true );
	                    connection2.getOutputStream().write(postDataBytes1);

	                    int responseCode3 = connection2.getResponseCode();
	                    System.out.println("Connection Creation Response : " + responseCode3); 

	                    BufferedReader in1 = new BufferedReader(new InputStreamReader(connection2.getInputStream()));
	                    String inputLine1;
	                    StringBuilder response1 = new StringBuilder();
	                    
	                    while ((inputLine1 = in1.readLine()) != null) {
	                        response1.append(inputLine1);
	                    }
	                    
	                    System.out.println("Details of Connection: " + response1);
	                    in1.close();
	                    connection2.disconnect();     
        }
	                    return null;
	}
		
//method for rest connector
	public static String restconnector(String accessToken, Sheet sheet3) throws IOException{
		DataFormatter dataFormatter2 = new DataFormatter();
		
        for (int rowNum = 1; rowNum <= sheet3.getLastRowNum(); rowNum++) {
            Row row3 = sheet3.getRow(rowNum);
            
            String Connectiontype = dataFormatter2.formatCellValue(row3.getCell(0));
            String ConnectionName = dataFormatter2.formatCellValue(row3.getCell(1));
            String ConnectionJSON = dataFormatter2.formatCellValue(row3.getCell(2));
            String ImportUserJSON = dataFormatter2.formatCellValue(row3.getCell(3));
            String ImportAccountEntJSON = dataFormatter2.formatCellValue(row3.getCell(4));
            String STATUS_THRESHOLD_CONFIG = dataFormatter2.formatCellValue(row3.getCell(5));
            String CreateAccountJSON = dataFormatter2.formatCellValue(row3.getCell(6));
            String UpdateAccountJSON = dataFormatter2.formatCellValue(row3.getCell(7));
            String EnableAccountJSON = dataFormatter2.formatCellValue(row3.getCell(8));
            String DisableAccountJSON = dataFormatter2.formatCellValue(row3.getCell(9));
            String AddAccessJSON = dataFormatter2.formatCellValue(row3.getCell(10));
            String RemoveAccessJSON = dataFormatter2.formatCellValue(row3.getCell(11));
            String UpdateUserJSON = dataFormatter2.formatCellValue(row3.getCell(12));
            String ChangePassJSON = dataFormatter2.formatCellValue(row3.getCell(13));
            String RemoveAccountJSON = dataFormatter2.formatCellValue(row3.getCell(14));
            String TicketStatusJSON = dataFormatter2.formatCellValue(row3.getCell(15));
            String CreateTicketJSON = dataFormatter2.formatCellValue(row3.getCell(16));
            String ENDPOINTS_FILTER = dataFormatter2.formatCellValue(row3.getCell(17));
            String PasswdPolicyJSON = dataFormatter2.formatCellValue(row3.getCell(18));
            String ConfigJSON = dataFormatter2.formatCellValue(row3.getCell(19));
            String AddFFIDAccessJSON = dataFormatter2.formatCellValue(row3.getCell(20));
            String RemoveFFIDAccessJSON = dataFormatter2.formatCellValue(row3.getCell(21));
            String MODIFYUSERDATAJSON = dataFormatter2.formatCellValue(row3.getCell(22));
            String SendOtpJSON = dataFormatter2.formatCellValue(row3.getCell(23));
            String ValidateOtpJSON = dataFormatter2.formatCellValue(row3.getCell(24));
            String PAM_CONFIG = dataFormatter2.formatCellValue(row3.getCell(25));
        
        System.out.println("Connectiontype: " + Connectiontype);
        System.out.println("ConnectionName: " + ConnectionName);
        System.out.println("ConnectionJSON: " + ConnectionJSON);
        System.out.println("ImportUserJSON: " + ImportUserJSON);
        System.out.println("ImportAccountEntJSON: " + ImportAccountEntJSON);
        System.out.println("STATUS_THRESHOLD_CONFIG: " + STATUS_THRESHOLD_CONFIG);
        System.out.println("CreateAccountJSON: " + CreateAccountJSON);
        System.out.println("UpdateAccountJSON: " + UpdateAccountJSON);
        System.out.println("EnableAccountJSON: " + EnableAccountJSON);
        System.out.println("DisableAccountJSON: " + DisableAccountJSON);
        System.out.println("AddAccessJSON: " + AddAccessJSON);
        System.out.println("RemoveAccessJSON: " + RemoveAccessJSON);
        System.out.println("UpdateUserJSON: " + UpdateUserJSON);
        System.out.println("ChangePassJSON: " + ChangePassJSON);
        System.out.println("RemoveAccountJSON: " + RemoveAccountJSON);
        System.out.println("TicketStatusJSON: " + TicketStatusJSON);
        System.out.println("CreateTicketJSON: " + CreateTicketJSON);
        System.out.println("ENDPOINTS_FILTER: " + ENDPOINTS_FILTER);
        System.out.println("PasswdPolicyJSON: " + PasswdPolicyJSON);
        System.out.println("ConfigJSON: " + ConfigJSON);
        System.out.println("AddFFIDAccessJSON: " + AddFFIDAccessJSON);
        System.out.println("RemoveFFIDAccessJSON: " + RemoveFFIDAccessJSON);
        System.out.println("MODIFYUSERDATAJSON: " + MODIFYUSERDATAJSON);
        System.out.println("SendOtpJSON: " + SendOtpJSON);
        System.out.println("ValidateOtpJSON: " + ValidateOtpJSON);
        System.out.println("PAM_CONFIG: " + PAM_CONFIG);
		
	                	URL url3 = new URL("https://securdi-partner.saviyntcloud.com/ECM/api/v5/testConnection");
	                    Map<String, Object> param2 = new LinkedHashMap<>();
	                    param2.put("connectiontype", Connectiontype);
	                    param2.put("connectionName", ConnectionName);
	                    param2.put("ConnectionJSON", ConnectionJSON);
//	                    param2.put("ImportUserJSON", ImportUserJSON);
//	                    param2.put("ImportAccountEntJSON", ImportAccountEntJSON);
//	                    param2.put("STATUS_THRESHOLD_CONFIG", STATUS_THRESHOLD_CONFIG);
//	                    param2.put("CreateAccountJSON", CreateAccountJSON);
//	                    param2.put("UpdateAccountJSON", UpdateAccountJSON);
//	                    param2.put("EnableAccountJSON", EnableAccountJSON);
//	                    param2.put("DisableAccountJSON", DisableAccountJSON);
//	                    param2.put("AddAccessJSON", AddAccessJSON);
//	                    param2.put("RemoveAccessJSON", RemoveAccessJSON);
//	                    param2.put("UpdateUserJSON", UpdateUserJSON);
//	                    param2.put("ChangePassJSON", ChangePassJSON);
//	                    param2.put("RemoveAccountJSON", RemoveAccountJSON);
//	                    param2.put("TicketStatusJSON", TicketStatusJSON);
//	                    param2.put("CreateTicketJSON", CreateTicketJSON);
//	                    param2.put("ENDPOINTS_FILTER", ENDPOINTS_FILTER);
//	                    param2.put("PasswdPolicyJSON", PasswdPolicyJSON);
//	                    param2.put("ConfigJSON", ConfigJSON);
//	                    param2.put("AddFFIDAccessJSON", AddFFIDAccessJSON);
//	                    param2.put("RemoveFFIDAccessJSON", RemoveFFIDAccessJSON);
//	                    param2.put("MODIFYUSERDATAJSON", MODIFYUSERDATAJSON);
//	                    param2.put("SendOtpJSON", SendOtpJSON);
//	                    param2.put("ValidateOtpJSON", ValidateOtpJSON);
//	                    param2.put("PAM_CONFIG", PAM_CONFIG);

	                    StringBuilder postData2 = new StringBuilder();

	                    for (Map.Entry<String, Object> para2 : param2.entrySet()) {
	                        if (postData2.length() != 0) postData2.append('&');
	                        postData2.append(URLEncoder.encode(para2.getKey(), "UTF-8"));
	                        postData2.append('=');
	                        postData2.append(URLEncoder.encode(String.valueOf(para2.getValue()), "UTF-8"));
	                    }

	                    byte[] postDataBytes2 = postData2.toString().getBytes("UTF-8");
	                    HttpsURLConnection connection3 = (HttpsURLConnection) url3.openConnection();
	                    connection3.setRequestMethod("POST");
	                    connection3.setDoOutput(true);
	                    connection3.setRequestProperty("Authorization","Bearer " + accessToken);
	                    connection3.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded");
	                    connection3.setRequestProperty( "charset", "utf-8");
	                    connection3.setUseCaches( true );
	                    connection3.getOutputStream().write(postDataBytes2);

	                    int responseCode4 = connection3.getResponseCode();
	                    System.out.println("Connection Creation Response : " + responseCode4); 

	                    BufferedReader in2 = new BufferedReader(new InputStreamReader(connection3.getInputStream()));
	                    String inputLine2;
	                    StringBuilder response2 = new StringBuilder();
	                    
	                    while ((inputLine2 = in2.readLine()) != null) {
	                        response2.append(inputLine2);
	                    }
	                    
	                    System.out.println("Details of Connection: " + response2);
	                    in2.close();
	                    connection3.disconnect();      
	                   
	}
        return null;
}
	}
