/* SENG 2250 - ASSIGNMENT 3
 * Author: Harrison Rebesco 
 * Student Number: c3237487  
 * Date: 01/11/19
 * Description: This is a helper class - used to enforce the required encryption protocols adhering to assignment 3 specs 
 */

import java.math.*;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
	
public class EncryptionManager 
{
	private BigInteger zero = new BigInteger("0");
	private BigInteger one = new BigInteger("1");
	private KeyGenerator keyGenerator;
	private SecretKey secretKey;
	
	//PRE: n/a 
	//POST: calculates RSA modulus, publicKey & privateKey by utilizing the BigInteger.probablePrime function
	public BigInteger [] rsaValues()
	{
		SecureRandom rand = new SecureRandom();
		
		BigInteger p = BigInteger.probablePrime(2048, rand); //create random p value 
		BigInteger q = BigInteger.probablePrime(2048, rand); //create random q value 
		BigInteger phi = (p.subtract(one)).multiply(q.subtract(one)); //calculate phi 
		
		BigInteger modulus = p.multiply(q); //calculate modulus 
		BigInteger publicKey = new BigInteger("65537"); //set publicKey to value specified in assignment specs 
		BigInteger privateKey = publicKey.modInverse(phi); //set privateKey to mod inverse of phi 
		BigInteger [] values = {modulus, publicKey, privateKey}; //return mod, public key and private key in array 
		
		return values;
	}
	
	//PRE: takes a secret message, public key and modulus 
	//POST: encrypts a message using my implementation of fastModExp to RSA standards 
	public BigInteger rsaEncrypt(BigInteger secret, BigInteger publicKey, BigInteger modulus)
	{
		BigInteger encryption = fastModExp(secret, publicKey, modulus); //encrypt, typically using public key 
		return encryption;
	}

	//PRE: takes a secret message, public key and modulus 
	//POST: decrypts a message using my implementation of fastModExp to RSA standards 
	public BigInteger rsaDecrypt(BigInteger secret, BigInteger privateKey, BigInteger modulus)
	{
		BigInteger decryption = fastModExp(secret, privateKey, modulus); //encrypt, typically using private key 
		return decryption;
	}
	
	//PRE: takes a base, exponent and modulus 
	//POST: performs a fast modular exponentiation which is used in rsa encryption/decryption as per assignment specs
	public BigInteger fastModExp(BigInteger base, BigInteger exponent, BigInteger modulus)
	{
		if (modulus.equals(zero))
			return zero; //return 0 if mod is 0
		
		BigInteger value = one;
		
		while(exponent.compareTo(zero) == 1) //while exponent > 0 
		{
			if ((exponent.and(one)).equals(one))
				value = (value.multiply(base)).mod(modulus); //(value * base) % modulus 
			exponent = exponent.shiftRight(1); //bit shift right 
			base = (base.multiply(base)).mod(modulus); //(base * base) % modulus 
		}
		return value;
	}
	
	//PRE: n/a
	//POST: returns a 256 byte random value 
	public BigInteger randomValue()
	{
		SecureRandom r = new SecureRandom(); 
		BigInteger value = BigInteger.probablePrime(256, r); //get a random value of specified size 
		return value;
	}
	
	//PRE: n/a
	//POST: returns the mod value specified in assignment3 - used for DHE 
	public BigInteger getModDHE()
	{
		return new BigInteger("178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
	}
	
	//PRE: n/a
	//POST: returns the base value specified in assignment3 - used for DHE 
	public BigInteger getBaseDHE()
	{
		return new BigInteger("174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");
	}
	
	//PRE: takes a byteArray 
	//POST: converts byte to hexadecimal 
	public String bytesToHex(byte[] byteArray)
	{
		StringBuffer hex = new StringBuffer();
		
		for (int i = 0; i < byteArray.length; i++) 
		{
			String hexString = Integer.toHexString(0xff & byteArray[i]); //get hex value of byte 
			if(hexString.length() == 1) 
				hex.append('0'); //add 0 if 1 char long 
			hex.append(hexString); //otherwise add both chars 
		}
		
		return hex.toString(); //return converted string 
	}
   	
	//PRE: takes a hexidecimal string 
	//POST: converts hexadecimal to ascii
	public String hexToAscii(String hexString) 
	{
		StringBuilder output = new StringBuilder("");
     
		for (int i = 0; i < hexString.length(); i += 2) 
		{
			String str = hexString.substring(i, i + 2); //get substring 
			output.append((char) Integer.parseInt(str, 16)); //convert to ascii and add to string 
		}
     
		return output.toString(); //return converted string 
	}
	
	//PRE: takes a secret message to be hashed
	//POST: formats a message returning a big integer with SHA-256 hashed message 
	public BigInteger SHA256(BigInteger message) throws Exception
	{
		String messageString = message.toString(); //convert biginteger to string 
		MessageDigest digest = MessageDigest.getInstance("SHA-256"); //get sha256 format 
		byte[] hashedMessage = digest.digest(messageString.getBytes(StandardCharsets.UTF_8)); //hash string 

		return new BigInteger(1, hashedMessage); //return hashed message as big integer 
	}
	
	//PRE: takes two strings, x and y and the size of the byte array being xor'd
	//POST: returns the xor of x and y 
	public String xor(String x, String y, int size)
	{
		byte[] b1 = x.getBytes(); //convert x to byte array 
		byte[] b2 = y.getBytes(); //conver y to byte array 
		byte[] xor = new byte[size]; //create byte container of specified size 
		
		for (int i = 0; i < size; i++)
			xor[i] = (byte)(b1[i] ^ b2[i]); //xor x and y 
		
		return new String(xor); //return xor value 
	}
	
	//PRE: takes message and key 
	//POST: uses cipher class to encrypt a message using the AES encryption protocol returning a base64 encrypted message
	public String encrypt(String message, SecretKey key) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key); //initialize as encryption mode 
		
		return new String(Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")))); //return encrypted message 
	}
	
	//PRE: takes message and key 
	//POST: uses cipher class to decrypt a message using the AES encryption protocol returning a base64 decrypted message 
	public String decrypt(String encryptedMessage, SecretKey key) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key); //initialize decryption mode 
        
		return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedMessage.getBytes()))); //return decrypted message 
	}
}