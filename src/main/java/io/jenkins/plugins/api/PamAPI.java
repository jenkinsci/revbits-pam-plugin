package io.jenkins.plugins.api;

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;

import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.util.Secret;

public class PamAPI {

	public static boolean initialized = false;

	public static class PamAuthnInfo {
		String applianceUrl;
		Secret apiKey;
		Secret publicKey;

        public PamAuthnInfo(String applianceUrl, Secret apiKey, Secret publicKey) {
            this.applianceUrl = applianceUrl;
            this.apiKey = apiKey;
            this.publicKey = publicKey;
        }
	}

	public static class SecretResponse {
		public byte[] value;
		public String errorMessage;
	}

	private static final Logger LOGGER = Logger.getLogger(PamAPI.class.getName());

	private static void defaultToEnvironment(PamAuthnInfo pamAuthn) {
		Map<String, String> env = System.getenv();
		if (pamAuthn.applianceUrl == null && env.containsKey("REVBITS_APPLIANCE_URL"))
			pamAuthn.applianceUrl = env.get("REVBITS_APPLIANCE_URL");
		if (pamAuthn.apiKey == null && env.containsKey("REVBITS_AUTHN_API_KEY"))
			pamAuthn.apiKey = Secret.fromString(env.get("REVBITS_AUTHN_API_KEY"));
		if (pamAuthn.publicKey == null && env.containsKey("REVBITS_AUTHN_PUBLIC_KEY"))
			pamAuthn.publicKey = Secret.fromString(env.get("REVBITS_AUTHN_PUBLIC_KEY"));
	}

	public static String getSecretFromApi(PamAuthnInfo pamAuthn, String variable) throws Exception {
//		Declarations
		URL url;
		int status;
		byte[] pk;
		byte[] plainText;

//		URL formation
		String urlString = String.format("%s/api/v1/secretman/getJenkinsSecret/%s", pamAuthn.applianceUrl, variable);
		url = new URL(urlString);

//		Connection
		HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

		con.setRequestMethod("GET");
		con.setRequestProperty("apiKey", Secret.toString(pamAuthn.apiKey));
		LOGGER.log(Level.WARNING, "Connection opened");

//		Response and Data Mapping
		status = con.getResponseCode();

		InputStream responseStream = con.getInputStream();
		ObjectMapper mapper = new ObjectMapper();

		SecretResponse sr = mapper.readValue(responseStream, SecretResponse.class);

//		Verification
		if (status !=  200) {
			String error = "Error fetching secret from PAM ";
			if(sr.errorMessage != null){
				error += "[ Status: " + status + ", Message: " + sr.errorMessage + " ]";
				LOGGER.log(Level.WARNING, error);
			} else {
				error += "[ Status: " + status + " ]";
				LOGGER.log(Level.WARNING, error);
			}
			throw new Exception(error);
		}
		if (sr.value.length == 0) {
			LOGGER.log(Level.WARNING, "Incomplete data or No secret received against variable: " + variable);
			throw new Exception("Incomplete data or No secret received against variable: " + variable);
		}

//		Decryption
		Cipher asymmetricCipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		String publicKey = Secret.toString(pamAuthn.publicKey)
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\r\n", "");

		pk = Base64.getMimeDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
		RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

		asymmetricCipher.init(Cipher.DECRYPT_MODE, key);

		plainText = asymmetricCipher.doFinal(sr.value);

		LOGGER.log(Level.INFO, "Received secret from PAM and decrypted successfully.");

		String str = new String(plainText)
				.replaceAll("�", "")
				.replaceAll(" ", "")
				.replaceAll(String.valueOf((char)0), "")
				.replaceAll(String.valueOf((char)1), "");
		LOGGER.log(Level.INFO, str);

		return str;
	}

	private PamAPI() {
		super();
	}
}
