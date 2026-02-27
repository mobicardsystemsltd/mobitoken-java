import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Random;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class MobicardTokenization {
    
    private final String mobicardVersion = "2.0";
    private final String mobicardMode = "LIVE";
    private final String mobicardMerchantId;
    private final String mobicardApiKey;
    private final String mobicardSecretKey;
    private final String mobicardServiceId = "20000";
    private final String mobicardServiceType = "TOKENIZATION";
    
    private final String mobicardTokenId;
    private final String mobicardTxnReference;
    
    private final Gson gson = new Gson();
    
    public MobicardTokenization(String merchantId, String apiKey, String secretKey) {
        this.mobicardMerchantId = merchantId;
        this.mobicardApiKey = apiKey;
        this.mobicardSecretKey = secretKey;
        
        Random random = new Random();
        this.mobicardTokenId = String.valueOf(random.nextInt(900000000) + 1000000);
        this.mobicardTxnReference = String.valueOf(random.nextInt(900000000) + 1000000);
    }
    
    public String generateJWT(String cardNumber, String expiryMonth, String expiryYear, 
                             boolean singleUseToken, Map customData) throws Exception {
        
        Map jwtHeader = new HashMap<>();
        jwtHeader.put("typ", "JWT");
        jwtHeader.put("alg", "HS256");
        String encodedHeader = base64UrlEncode(gson.toJson(jwtHeader));
        
        Map jwtPayload = new HashMap<>();
        jwtPayload.put("mobicard_version", mobicardVersion);
        jwtPayload.put("mobicard_mode", mobicardMode);
        jwtPayload.put("mobicard_merchant_id", mobicardMerchantId);
        jwtPayload.put("mobicard_api_key", mobicardApiKey);
        jwtPayload.put("mobicard_service_id", mobicardServiceId);
        jwtPayload.put("mobicard_service_type", mobicardServiceType);
        jwtPayload.put("mobicard_token_id", mobicardTokenId);
        jwtPayload.put("mobicard_txn_reference", mobicardTxnReference);
        jwtPayload.put("mobicard_single_use_token_flag", singleUseToken ? "1" : "0");
        jwtPayload.put("mobicard_card_number", cardNumber);
        jwtPayload.put("mobicard_card_expiry_month", expiryMonth);
        jwtPayload.put("mobicard_card_expiry_year", expiryYear);
        jwtPayload.put("mobicard_custom_one", customData.getOrDefault("customOne", "mobicard_custom_one"));
        jwtPayload.put("mobicard_custom_two", customData.getOrDefault("customTwo", "mobicard_custom_two"));
        jwtPayload.put("mobicard_custom_three", customData.getOrDefault("customThree", "mobicard_custom_three"));
        jwtPayload.put("mobicard_extra_data", customData.getOrDefault("extraData", "your_custom_data_here_will_be_returned_as_is"));
        
        String encodedPayload = base64UrlEncode(gson.toJson(jwtPayload));
        
        String headerPayload = encodedHeader + "." + encodedPayload;
        String signature = generateHMAC(headerPayload, mobicardSecretKey);
        
        return encodedHeader + "." + encodedPayload + "." + signature;
    }
    
    public JsonObject tokenizeCard(String cardNumber, String expiryMonth, String expiryYear, 
                                  boolean singleUseToken) throws Exception {
        
        Map customData = new HashMap<>();
        customData.put("customOne", "mobicard_custom_one");
        customData.put("customTwo", "mobicard_custom_two");
        customData.put("customThree", "mobicard_custom_three");
        customData.put("extraData", "your_custom_data_here_will_be_returned_as_is");
        
        String jwtToken = generateJWT(cardNumber, expiryMonth, expiryYear, singleUseToken, customData);
        
        HttpClient client = HttpClient.newHttpClient();
        
        Map requestBody = new HashMap<>();
        requestBody.put("mobicard_auth_jwt", jwtToken);
        
        String jsonBody = gson.toJson(requestBody);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://mobicardsystems.com/api/v1/card_tokenization"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        
        HttpResponse response = client.send(request, HttpResponse.BodyHandlers.ofString());
        
        return gson.fromJson(response.body(), JsonObject.class);
    }
    
    private String base64UrlEncode(String data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data.getBytes());
    }
    
    private String generateHMAC(String data, String key) throws Exception {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
        sha256Hmac.init(secretKey);
        byte[] hmacBytes = sha256Hmac.doFinal(data.getBytes());
        return base64UrlEncode(new String(hmacBytes));
    }
    
    public static void main(String[] args) {
        try {
            MobicardTokenization tokenizer = new MobicardTokenization(
                "4",
                "YmJkOGY0OTZhMTU2ZjVjYTIyYzFhZGQyOWRiMmZjMmE2ZWU3NGIxZWM3ZTBiZSJ9",
                "NjIwYzEyMDRjNjNjMTdkZTZkMjZhOWNiYjIxNzI2NDQwYzVmNWNiMzRhMzBjYSJ9"
            );
            
            JsonObject result = tokenizer.tokenizeCard(
                "4242424242424242",
                "02",
                "28",
                false
            );
            
            if (result.has("status")) {
                String status = result.get("status").getAsString();
                
                if ("SUCCESS".equals(status)) {
                    System.out.println("Tokenization Successful!");
                    
                    if (result.has("card_information")) {
                        JsonObject cardInfo = result.getAsJsonObject("card_information");
                        
                        System.out.println("Card Token: " + 
                            cardInfo.get("card_token").getAsString());
                        System.out.println("Masked Card: " + 
                            cardInfo.get("card_number_masked").getAsString());
                        System.out.println("\nStore these values in your database.");
                    }
                } else {
                    System.out.println("Tokenization Failed!");
                    if (result.has("status_message")) {
                        System.out.println("Error: " + result.get("status_message").getAsString());
                    }
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
