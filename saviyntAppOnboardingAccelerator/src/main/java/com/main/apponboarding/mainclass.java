package com.main.apponboarding;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import com.methods.apponboarding.connection;

public class mainclass {

	

    public String accessToken;
    private static final String pasword="SecurDI@123";
    static FileInputStream DBconnection;
    static FileInputStream SFconnection;
    static FileInputStream RESTconnection;  
    static Sheet sheet1;
    static Sheet sheet2;
    static Sheet sheet3;
    
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		// Read from file and process data in connection method
		String accessToken=connection.accesstoken(pasword);
		DBconnection = new FileInputStream(new File("C:\\Users\\varun\\OneDrive\\Desktop\\DBConnection.xlsx"));
        Workbook workbook1 = WorkbookFactory.create(DBconnection);
        sheet1 = workbook1.getSheetAt(0);
	    connection.dbconnector(accessToken, sheet1);	
	    SFconnection = new FileInputStream(new File("C:\\Users\\varun\\OneDrive\\Desktop\\SFConnection.xlsx"));
        Workbook workbook2 = WorkbookFactory.create(SFconnection);
        sheet2 = workbook2.getSheetAt(0);
	    connection.sfconnector(accessToken, sheet2);
	    RESTconnection = new FileInputStream(new File("C:\\Users\\varun\\OneDrive\\Desktop\\RESTConnection.xlsx"));
        Workbook workbook3 = WorkbookFactory.create(RESTconnection);
        sheet3 = workbook3.getSheetAt(0);
	    connection.restconnector(accessToken, sheet3);
	}
	

}
