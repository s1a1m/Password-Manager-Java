package passwordmanager;

import java.io.*;
import java.util.*;
import java.nio.file.*;

import java.security.spec.*;
import java.security.*;
import java.security.NoSuchAlgorithmException;

import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
     
public class PassMan{
    
    //---Class Variables---//
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray(); //Used in bytesToHex()
    private static final Random r = new SecureRandom(); //Used in generateSalt()
    
    //---Auxilary Methods---//
    //Brings up menu UI.
    public static void menu(){
        int exitFlag = 0;
        while(exitFlag == 0){
            System.out.println("*---------------------*");
            System.out.println("|    PassMan.java     |");
            System.out.println("|---------------------|");
            System.out.println("| 1. Check Integrity  |");
            System.out.println("| 2. Register Account |");
            System.out.println("| 3. Delete Account   |");
            System.out.println("| 4. Change Account   |");
            System.out.println("| 5. Get Password     |");
            System.out.println("| 6. Exit             |");
            System.out.println("*---------------------*");
            
            Scanner user_input = new Scanner(System.in);
            String text = user_input.next(); 
            byte[] b = loadFileIntoMemory("passwd_file");
            AES machine = new AES();
            byte[] iv;
            IvParameterSpec IVspec;
            
            
            switch(text){
                case "1": 
                    System.out.println("Check Integrity");
                    betterIntegrityCheck();
                    
                    break;
                case "2": 
                    System.out.println("Register Account");
                    b = loadFileIntoMemory("passwd_file");
                    iv = getIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.decrypt(b, IVspec);
                    b = register_account(b);
                    iv = machine.genIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.encrypt(b, IVspec);
                    writeFileFromMemory("passwd_file", b);
                    addIV(iv);
                    betterIntegrityCheck();
                    break;
                case "3": 
                    System.out.println("Delete Account");
                    b = loadFileIntoMemory("passwd_file");
                    iv = getIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.decrypt(b, IVspec);
                    b = delete_account(b);
                    iv = machine.genIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.encrypt(b, IVspec);
                    writeFileFromMemory("passwd_file", b);
                    addIV(iv);
                    betterIntegrityCheck();
                    break;
                case "4": 
                    System.out.println("Change Account");              
                    b = loadFileIntoMemory("passwd_file");
                    iv = getIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.decrypt(b, IVspec);
                    b = change_account(b);
                    iv = machine.genIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.encrypt(b, IVspec);
                    writeFileFromMemory("passwd_file", b);
                    addIV(iv);
                    betterIntegrityCheck();
                    break;
                case "5": 
                    System.out.println("Get Password");
                    b = loadFileIntoMemory("passwd_file");
                    iv = getIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.decrypt(b, IVspec);
                    b = get_password(b);
                    iv = machine.genIV();
                    IVspec = machine.GenerateIVSpec(iv);
                    b = machine.encrypt(b, IVspec);
                    writeFileFromMemory("passwd_file", b);
                    addIV(iv);
                    betterIntegrityCheck();
                    
                    break;
                case "6": 
                    System.out.println("Exit");
                    exitFlag = 1;
                    break;
                default: break;              
            } 
        }
        System.exit(0);
    }   
    //Used in check_integrity() to aknowledge MAC: lines in the passwd_file.
    public static boolean isMacLine(String input){
        if(input.length() >= 4){
            if(input.charAt(0) == 'M' && input.charAt(1) == 'A' && input.charAt(2) == 'C' && input.charAt(3) == ':'){
                return true;   
            }
        }
        return false;
    } 
    //Returns hex string to be used as salt.
    public static String generateSalt(){
        byte[] salt = new byte[16];
        r.nextBytes(salt);
        return bytesToHex(salt);
    }
    // reads in the file then parses backwards through the file
    // adds each byte to a byte[] in reverse order
    // after it then adds the file up to before the iv to a new byte array and writes to the file, deleting the iv from the file
    // returns the byte[] of the iv.
    public static byte[] getIV(){
    	byte[] iv = new byte[16];
		byte[] data = null;
		
		try{
			Path p = Paths.get("passwd_file");
            data = Files.readAllBytes(p);
		}catch(IOException e){
			e.printStackTrace();
		}
		int location = 15;
        for(int i = data.length-1 ; i > data.length - 17; i--){
        	iv[location] = data[i];
        	location--;
        }
        byte[] newfile = new byte[data.length-16];
        for(int i = 0; i < data.length -16; i++){
        	newfile[i] = data[i];
        }
        //System.out.println("removed iv");
        writeFileFromMemory("passwd_file", newfile);
        return iv;
    }
    // takes in a byte[] that is the iv and appends it to the end of the passwd_file
    public static void addIV(byte[] iv){
		try{
			Files.write(Paths.get("passwd_file"), iv, StandardOpenOption.APPEND);
			//System.out.println("added iv");
		}catch(IOException e){
			e.printStackTrace();
		}
	}
    
    //Converts byte[] to hex String. Used in hash() and generateSalt().
    public static String bytesToHex(byte[] bytes){
        char[] hexChars = new char[bytes.length * 2];
        for(int i = 0; i < bytes.length; i++){
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = hexArray[v >>> 4];
            hexChars[i * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    //Converts an arrayList to a byte[]
    public static byte[] arrayListToBytes(List<String> arrayList){
        int length = arrayList.size();
        String hold = "";
        for(int i = 0; i < arrayList.size(); i++){
            if(isMacLine(arrayList.get(i))){
                //Skip
            }else{
                hold = hold + arrayList.get(i) + "\n";
            }
        }
        byte[] returnBytes = hold.getBytes();
        return(returnBytes);
    }
    //Checks if account exists.
    public static boolean accountExists(String account, List<String> myList){
        boolean flag = false;
        for(int i = 0; i < myList.size(); i++){
            if(myList.get(i).equals(account)){
                flag = true;
            } 
        } 
        return(flag);
    }
    
    //---Functional Methods---//

    //Checks for the existence of files passwd_file and master_passwd.
    public static boolean fileCheck(){   
        File passwd_file = new File("passwd_file");
        File master_passwd = new File("master_passwd"); 
        boolean pfb = passwd_file.exists();
        boolean mfb = master_passwd.exists();
        if(pfb == true && mfb == true){
            //System.out.println("Success!");
            return(true);
        }
        else if(pfb == false && mfb == true){
            System.out.println("Did not find file passwd_file!");
            return(false);
        }
        else if(pfb == true && mfb == false){
            System.out.println("Did not find file master_passwd!");
            return(false);
        }
        else{
            System.out.println("Did not find file passwd_file or file master_passwd!");
            return(false);
        }
    }
    //Compares user input to master_passwd file. Returns boolean.
    public static boolean promptForPassword(){               
        //Grabs info from master_passwd
        Pair info = getMasterPassInfo();
        String hashedPassAndSaltCompare = (String)info.getHashValue();
        String salt = (String)info.getSaltValue();
        Scanner user_input = new Scanner(System.in);
        System.out.print("Password: ");
        String text = user_input.next();
        String hashedPassAndSalt = hash(text, salt);
        //System.out.println("hashedPassAndSaltCompare: " + hashedPassAndSaltCompare);
        //System.out.println("hashedPassAndSalt: " + hashedPassAndSalt);
        if(hashedPassAndSalt.equals(hashedPassAndSaltCompare)){
            return true;
        }else{
            return false;
        }
    }
    //Returns Pair containing info from master_passwd.
    public static Pair getMasterPassInfo(){
        try{
            FileReader fr = new FileReader("master_passwd");
            BufferedReader br = new BufferedReader(fr);
            String hold = br.readLine();
            //System.out.println()
            String[] stringArray = hold.split(":");     
            Pair returnPair = new Pair(stringArray[1], stringArray[0]);
            return returnPair;    
        }catch(FileNotFoundException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(IOException ex){
            System.err.println("Exception " + ex + " thrown!");  
        }
        return(null);
    }
    //Returns string of hashedPassAndSalt.
    public static String hash(String Input, String Salt){
        try{       
            String text = Salt + Input; 
            //Creates digest of master_passwd and salt.
            MessageDigest md = MessageDigest.getInstance("SHA-512", "BC");
            md.update(text.getBytes("UTF-8"));
            byte[] digest = md.digest();
            //Converts byte[] digest to hex string for storage in master_passwd.
            String hashedPassAndSalt = bytesToHex(digest);
            return(hashedPassAndSalt);
        }catch(NoSuchAlgorithmException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(UnsupportedEncodingException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(IOException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(NoSuchProviderException ex){
            System.err.println("Exception " + ex + " thrown!");
        }   
        return(null); 
    }   
    //Creates passwd_file and master_passwd.
    public static void initialReg(){
        Scanner user_input = new Scanner(System.in);
        System.out.print("Register a master password: ");        
            String text = user_input.next(); 
            String salt = generateSalt();
            String hashedPassAndSalt = hash(text, salt);    
        try{
            PrintWriter pw1 = new PrintWriter("passwd_file");
            PrintWriter pw2 = new PrintWriter("master_passwd");              
            pw2.println(salt + ":" + hashedPassAndSalt);          
            pw1.close();
            pw2.close();
        	AES machine = new AES();
        	byte[] iv = machine.genIV();
        	IvParameterSpec IVspec = machine.GenerateIVSpec(iv);
            check_integrity();
           byte[] b = loadFileIntoMemory("passwd_file");
            b = machine.encrypt(b, IVspec);
            writeFileFromMemory("passwd_file", b);
            addIV(iv);
            System.out.println("Files Created!");   
        }catch(FileNotFoundException ex){
            System.err.println("Exception " + ex + " thrown!");
        }
    }
    
    //---Menu Methods---//
    
    //Used to create a MAC value that is stored at the bottom of the passwd_file.
    //If first time establishes MAC.
    public static String check_integrity(){
        try{
            FileReader fr = new FileReader("passwd_file");
            BufferedReader br = new BufferedReader(fr);
            boolean macFlag = false;
            String hold = "";
            String intValueCompare = "";
            String s = br.readLine();
            
            	while(s != null){
            		if(isMacLine(s)){
            			intValueCompare = s;
            			macFlag = true;	
            		}else{
            			hold = hold.concat(s);
            		}
            		s = br.readLine();
            	}
            String intValue = hash(hold, "");
            if(macFlag){
                if(("MAC:" + intValue).equals(intValueCompare)){
                    System.out.println("INEGRITY CHECK OF PASSWORD FILE PASSED!");
                }else{
                    System.out.println("INEGRITY CHECK OF PASSWORD FILE FAILED!");
                    System.exit(0);      
                }
            }else{               
                FileWriter fw = new FileWriter("passwd_file", true);
                BufferedWriter bw = new BufferedWriter(fw);
                PrintWriter pw = new PrintWriter(bw);               
                pw.print("MAC:" + intValue);
                pw.close();
            }
            br.close();
            return(intValue);
        }catch(FileNotFoundException ex){
            System.err.println("Exception " + ex + " thrown!"); 
        }catch(IOException ex){
            System.err.println("Exception " + ex + " thrown!"); 
        }
        return null;
    }   
    //helps with checking integrity.
    public static byte[] check_integrity2(byte[] byteArray){
    	//System.out.println("enter integrity check");
    	byte[] b = null;
        String str = new String(byteArray);
		List<String> myList = new ArrayList<String>(Arrays.asList(str.split("\n")));
		   
		boolean macFlag = false;
		String hold = "";
		String mac = "";
		String intValueCompare = "";
		int listsize = myList.size() -1;
	
		for(int i = 0; i < myList.size(); i++){
			//System.out.println("enter loop");
			if(isMacLine(myList.get(i))){
				//System.out.println("found MAC line");
				intValueCompare = myList.get(i);
				macFlag = true;
				mac = (myList.get(i) + "\n");	
			}else{
				hold = hold.concat(myList.get(i) + "\n");
			}
		}
		String intValue = hash(hold, "");
		if(macFlag){
		    if(("MAC:" + intValue).equals(intValueCompare)){
		        System.out.println("INEGRITY CHECK OF PASSWORD FILE PASSED!");
		        hold = hold.concat(mac + "\n");
		        b = hold.getBytes();	       
		    }else{
		        System.out.println("INEGRITY CHECK OF PASSWORD FILE FAILED!");
                        
                        //Deleting master_passwd and passwd_file.
                        File file1 = new File("passwd_file");
                        File file2 = new File("master_passwd");
                        file1.delete();
                        file2.delete();
		        System.exit(0);      
		    }
		}else{            
			hold = hold.concat("MAC:" + intValue);
			b = hold.getBytes();
		}
		return b;
		
    }
    //helps with checking integrity.
    public static void betterIntegrityCheck(){
        AES machine = new AES();
        byte[] b = null;
        byte[] iv = null;
        IvParameterSpec IVspec;  
        iv = getIV();
       // System.out.println("grabbed iv");
        b = loadFileIntoMemory("passwd_file");
        //System.out.println("leaded file");
        IVspec = machine.GenerateIVSpec(iv);
        //System.out.println("generated iv spec");
        b = machine.decrypt(b, IVspec);
        //System.out.println("decrypted");
        b = check_integrity2(b);
        iv = machine.genIV();
        //System.out.println("generated new iv");
        IVspec = machine.GenerateIVSpec(iv);
        //System.out.println("generated iv spec");
        b = machine.encrypt(b, IVspec);
        //System.out.println("encrypted");
        writeFileFromMemory("passwd_file", b);  
        //System.out.println("wrote to file");
        addIV(iv);
        //System.out.println("added iv to file");
    }
    //register_account()
    public static byte[] register_account(byte[] byteArray){
        Scanner scan = new Scanner(System.in);
        String domain, username, password, account;
        
        String s = new String(byteArray);
        List<String> myList = new ArrayList<String>(Arrays.asList(s.split("\n")));
     
        System.out.println("Please enter the domain");
        domain = scan.next().toLowerCase();
        System.out.println("Please enter your username");
        username = scan.next();
        System.out.println("Please enter your password");
        password = scan.next();
        
        account = domain + " " + username + " " + password;
        if(accountExists(account, myList)){
            System.out.println("Account already exists!");
        }else{
            myList.add(account);
            byte[] returnBytes = arrayListToBytes(myList);
            return(returnBytes);
        }
        byte[] returnBytes = arrayListToBytes(myList);
        return(returnBytes);
    }   
    //delete_account()
    public static byte[] delete_account(byte[] byteArray){
        Scanner scan = new Scanner(System.in);
        String domain, username, password, account;
        
        String s = new String(byteArray);
        List<String> myList = new ArrayList<String>(Arrays.asList(s.split("\n")));
        
        System.out.println("Please enter the domain");
        domain = scan.next().toLowerCase();
        System.out.println("Please enter your username");
        username = scan.next();
        System.out.println("Please enter your password");
        password = scan.next();
        
        account = domain + " " + username + " " + password;
        if(accountExists(account, myList)){
            System.out.println("Account found!");  
            for(int i = 0; i < myList.size(); i++){
                if(myList.get(i).equals(account)){
                    myList.remove(myList.get(i));
                    System.out.println("Account deleted!");
                }else{
                    //Empty
                }   
            } 
        }else{
            System.out.println("Account does not exist!");
        }
        byte[] returnBytes = arrayListToBytes(myList);
        return(returnBytes);
    }
    //change_account()
    public static byte[] change_account(byte[] byteArray){
        Scanner scan = new Scanner(System.in);
        String domain, username, passwordOld, passwordNew, accountOld, accountNew;

         String s = new String(byteArray);
        List<String> myList = new ArrayList<String>(Arrays.asList(s.split("\n")));
        
        System.out.println("Please enter the domain");
        domain = scan.next().toLowerCase();
        System.out.println("Please enter your username");
        username = scan.next();
        System.out.println("Please enter your old password");
        passwordOld = scan.next();
        System.out.println("Please enter your new password");
        passwordNew = scan.next();
        
        accountOld = domain + " " + username + " " + passwordOld;
        accountNew = domain + " " + username + " " + passwordNew;
        
        if(accountExists(accountOld, myList)){
            if(accountExists(accountNew, myList)){
                System.out.println("New account already exists!");
            }else{
                for(int i = 0; i < myList.size(); i++){
                    if(myList.get(i).equals(accountOld)){
                        //System.out.println("Removing old account!");
                        myList.remove(myList.get(i));
                    }
                }
                myList.add(accountNew);
                System.out.println("Changed password!");
                byte[] returnBytes = arrayListToBytes(myList);
                return(returnBytes);     
            }   
        }else{
            System.out.println("Old account doesn't exists!");
        }
        byte[] returnBytes = arrayListToBytes(myList);
        return(returnBytes);      
    }
    //get_password() 
    // takes in the byte[] of the file
    //converts to list
    // parses through the list adding each line to a new list
    // while checking that the line contains the domain
    // converts the new list to a byte array then returns it, removing the mac line
    public static byte[] get_password(byte[] byteArray){
    	Scanner scan = new Scanner(System.in);
        String domain;
        System.out.println("Please enter the domain");
        domain = scan.next().toLowerCase();
		 String s = new String(byteArray);
	     List<String> myList = new ArrayList<String>(Arrays.asList(s.split("\n")));
	     List<String> newlist = new ArrayList<String>();
	     int check = 0;
	     for(int i = 0; i < myList.size(); i++){
				if(isMacLine(myList.get(i)) == false){
						newlist.add(myList.get(i));
						String[] attributes = myList.get(i).split(" ");
			            if(domain.equals(attributes[0])){
			            	System.out.println("username " + attributes[1] + " password " + attributes[2]);
			                check = 1;
			            }
				}
			}
	     if(check == 0){
	            System.out.println("USER ACCOUNT DOES NOT EXIST!");
	        }
	     byte[] returnBytes = arrayListToBytes(newlist);
	     return returnBytes;
    } 
    
    public static byte[] loadFileIntoMemory(String filename){
        try{
            Path p = Paths.get(filename);
            byte[] data = Files.readAllBytes(p);
            return data;
        }catch(IOException ex){
            System.err.println("Exception " + ex + " thrown!");  
        }
        return null;
    }
    
    public static void writeFileFromMemory(String filename, byte[] byteArray){
        try{
            FileOutputStream fos = new FileOutputStream(filename);
            fos.write(byteArray);
            fos.close();
        }catch(FileNotFoundException ex){
            System.err.println("Exception " + ex + " thrown!");  
        }catch(IOException ex){
            System.err.println("Exception " + ex + " thrown!"); 
        }
    }
           
     //---Main Method---//
    
    public static void main(String[] args){
        
        System.out.println("Main Start!");
        Security.addProvider(new BouncyCastleProvider());
        if(Security.getProvider("BC") == null){
            System.out.println("Bouncy Castle is NOT avalible!");
        }else{
            System.out.println("Bouncy Castle is avalible!");
        }    
        
        //Code Trial area.
        //End.

        if(fileCheck()){//Both files exist.
            System.out.println("Files found! Welcome Back!");
            boolean auth = promptForPassword();   
            if(auth){
                System.out.println("CORRECT MASTER PASSWORD!");
                betterIntegrityCheck();
                menu();
            }else{
                System.out.println("WRONG MASTER PASSWORD!");
                System.exit(0);
            }
        }else{//Either one or neither files exist.
            System.out.println("Files not found! Please Register!");
            initialReg();    
            boolean auth = promptForPassword();   
            if(auth){
                System.out.println("CORRECT MASTER PASSWORD!");
                betterIntegrityCheck();
                menu();
            }else{
                System.out.println("WRONG MASTER PASSWORD!");
                System.exit(0);
            }                 
        }
    }
}
     //---Additional Classes---//

//Pair class using generics, used to return hashed password and salt
class Pair<S, H>{       
    public H hashValue;
    public S saltValue;

    public Pair(H hashValue, S saltValue){
        this.hashValue = hashValue;
        this.saltValue = saltValue;
    }
    public H getHashValue(){
        return hashValue;
    }
    public S getSaltValue(){
        return saltValue;
    }
}

class AES{
    Key k;
    byte[] IV = null;
    
    
    public AES(){
            this.k = generateSK();
            //this.C = Cipher.getInstance("AES", "BC");
   }
    
    public static Key generateSK(){
    	String test1 = gethashsalt();
		byte[] passkey = test1.getBytes();
        byte[] seed = new byte[16];
        for(int i = 0; i < 16; i++){
                seed[i] = passkey[i];
        }
        SecretKeySpec key = new SecretKeySpec(seed, "AES");
        return key;
    }
    
    public byte[] encrypt(byte[] byteText, IvParameterSpec iVspec){
        try{
        	Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, k, iVspec);
            byte[] byteCipherText = cipher.doFinal(byteText);
            String value = new String(byteCipherText, "UTF-8");
            //System.out.println("ENCRYPTED TO \r\n: " + value);
            return(byteCipherText);
            
        }catch(InvalidKeyException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(IllegalBlockSizeException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(BadPaddingException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(UnsupportedEncodingException ex){
            System.err.println("Exception " + ex + " thrown!");
        } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }
    
    public byte[] decrypt(byte[] byteText, IvParameterSpec iVspec){
        try{
        	Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, k, iVspec);
            byte[] bytePlainText = cipher.doFinal(byteText);
            String value = new String(bytePlainText, "UTF-8");
           // System.out.println("DECRYPTED TO \r\n" + value); 
            
            return(bytePlainText);           
        }catch(InvalidKeyException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(IllegalBlockSizeException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(BadPaddingException ex){
            System.err.println("Exception " + ex + " thrown!");
        }catch(UnsupportedEncodingException ex){
            System.err.println("Exception " + ex + " thrown!");
        } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }
    
    public static String gethashsalt(){
		 String hashsaltpass = null;
		 File pass = new File("master_passwd");
		 try{
				FileReader fr = new FileReader(pass);
				BufferedReader br = new BufferedReader(fr);
				String line;
				while((line = br.readLine()) != null){
					//System.out.println("enter while loop");
					String[] attributes = line.split(":");
					hashsaltpass = attributes[1];
				}	
				br.close();
				
			}catch(IOException e){
				e.printStackTrace();
			}
		 return hashsaltpass;
	 }
    public byte[] genIV(){
    	byte[] iv = new byte[16];
    	SecureRandom random = new SecureRandom();
    	random.nextBytes(iv);
    	return iv;
    }
    public IvParameterSpec GenerateIVSpec(byte[] iv){
    	byte[] IV = iv;
    	AlgorithmParameterSpec IVspec = new IvParameterSpec(IV);
    	return (IvParameterSpec) IVspec;
    }
}