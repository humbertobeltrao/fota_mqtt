#include <SPIFFS.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/aes.h>
#include <mbedtls/platform.h>
#include <string.h>
#include <Arduino.h>
#include "cert.h"

// MQTT and WiFi configuration
const char* mqtt_server = "test.mosquitto.org"; // MQTT server
const char* ssid = "";
const char* password = "";
String updateUrl;
String updateVersionCheck;

WiFiClientSecure espClient;
PubSubClient client(espClient); // MQTT client

// AES decryption setup
unsigned char aes_key[16]; // 128-bit AES key (16 bytes)
unsigned char aes_iv[16];  // 128-bit AES IV (16 bytes)

String encrypted_url_hex = "";
String downloadUrl = "";
bool has_key = false;
bool has_iv = false;
bool has_encrypted_url = false;
bool has_pad = false;
File file;
size_t padded_length = 0; // Initialize padded_length to 0
unsigned char padded_input[128] = {0}; // Initialize with zeros to avoid undefined behavior
unsigned char encrypted[128] = {0};     // Initialize with zeros
unsigned char decrypted[128] = {0};     // Initialize with zeros
size_t decrypted_url_len = 0; // Initialize decrypted_url_len to 0


// Function to perform AES decryption
void aes_decrypt(unsigned char *key, unsigned char *iv, unsigned char *input, unsigned char *output, size_t input_len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    // Set up AES context for decryption
    mbedtls_aes_setkey_dec(&aes, key, 128);

    // Perform AES decryption in CBC mode
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len, iv, input, output);
    
    mbedtls_aes_free(&aes);
}

// Function to convert hex string to byte array
void hexStringToByteArray(String hex, byte* byteArray, int length) {
    for (int i = 0; i < length * 2; i += 2) {
        byteArray[i / 2] = strtol(hex.substring(i, i + 2).c_str(), NULL, 16);
    }
}

// Function to decode the encrypted URL
bool decryptAndDownloadFirmware() {
   
    hexStringToByteArray(encrypted_url_hex, encrypted, encrypted_url_hex.length() / 2);
    Serial.println(encrypted_url_hex);
    Serial.println("Encrypted Data:");
    for (size_t i = 0; i < encrypted_url_hex.length() / 2; i++) {
        Serial.printf("%02X ", encrypted[i]);
    }
    Serial.println();
    
    Serial.print("AES Key: ");
    for (int i = 0; i < sizeof(aes_key); i++) {
        Serial.printf("%02X ", aes_key[i]);
    }
    Serial.println();

    Serial.print("AES IV: ");
    for (int i = 0; i < sizeof(aes_iv); i++) {
        Serial.printf("%02X ", aes_iv[i]);
    }
    
    // Decrypt the URL
    aes_decrypt(aes_key, aes_iv, encrypted, decrypted, padded_length);
    
    
    // Unpad the decrypted URL (removes PKCS#7 padding)
    decrypted_url_len = unpad_input(decrypted, padded_length, decrypted);
    decrypted[decrypted_url_len] = '\0';  // Null-terminate the string
    
    Serial.println("Decrypted:");
    //Serial.println((char *)decrypted);
    // Download the firmware
    delay(3000);
    return downloadFirmware((char *)decrypted);
}

// Function to unpad input data according to PKCS#7
size_t unpad_input(const unsigned char *input, size_t input_len, unsigned char *output) {
    // Get the padding length from the last byte
    size_t pad_len = input[input_len - 1];
    // Copy the data up to the padding length
    memcpy(output, input, input_len - pad_len);
    return input_len - pad_len;
}

void callback(char* topic, byte* payload, unsigned int length) {
    String message;
    for (int i = 0; i < length; i++) {
        message += (char)payload[i];
    }

    if (String(topic) == "esp32/key") {
        message.getBytes(aes_key, 16 + 1);
        has_key = true;
        Serial.println(message);
    } else if (String(topic) == "esp32/iv") {
        message.getBytes(aes_iv, 16 + 1);
        has_iv = true;
        Serial.println(message);
    } else if (String(topic) == "esp32/pad") {
          //hexStringToByteArray(message, aes_iv, 16);
        Serial.println(message);
        padded_length = (size_t)message.toInt();
        has_pad = true;
    } else if (String(topic) == "inTopic") {
        encrypted_url_hex = message;
        //Serial.println(message);
        has_encrypted_url = true;
    }

    // Proceed if all data is received
    if (has_key && has_iv && has_encrypted_url && has_pad) {
        if (decryptAndDownloadFirmware()) {
             flashESP32();
        } else {
            Serial.println("Decryption failed. Check key, IV, and encrypted data.");
        }
        resetFlags();
    }
}

void reconnect() {
    while (!client.connected()) {
        Serial.println("Attempting MQTT connection...");
        if (client.connect("ESP32_clientID")) {
            Serial.println("connected");
            client.subscribe("inTopic");
            client.subscribe("esp32/iv");
            client.subscribe("esp32/key");
            client.subscribe("esp32/pad");
        } else {
            Serial.print("failed, rc=");
            Serial.print(client.state());
            Serial.println(" try again in 5 seconds");
            delay(5000);
        }
    }
}

void setup() {
    Serial.begin(115200);
     if (!SPIFFS.begin(true)) {
        Serial.println("SPIFFS Mount Failed");
        return;
    }
    WiFi.begin(ssid, password);
    espClient.setCACert(mosquittoCertificate);
    client.setServer(mqtt_server, 8883); // Secure MQTT port (8883)
    client.setCallback(callback);
    connectmqtt();
}

void loop() {
    if (!client.connected()) {
        reconnect();
    }
    client.loop();
}

void connectmqtt() {
    if (client.connect("ESP32_clientID")) {
        Serial.println("connected to MQTT");
        client.subscribe("inTopic");
        client.subscribe("esp32/iv");
        client.subscribe("esp32/key");
        client.subscribe("esp32/pad");
    } else {
        reconnect();
    }
}

bool downloadFirmware(const char* url) {
    Serial.println(url);
    WiFiClientSecure * client = new WiFiClientSecure;

    if (client) {
        client->setCACert(rootCACertificate);  // Set root CA certificate for HTTPS

        HTTPClient https;
        if (https.begin( * client, url)) {
            Serial.print("[HTTPS] GET...\n");
            delay(100);
            int httpCode = https.GET();
            if (httpCode == HTTP_CODE_MOVED_PERMANENTLY || httpCode == HTTP_CODE_FOUND || httpCode == HTTP_CODE_SEE_OTHER) {
              String redirectURL = https.getLocation();  // Get the new URL from the Location header
              Serial.print("Redirecting to: ");
              Serial.println(redirectURL);
              https.end();  // Close the initial connection
          
              // Begin a new connection with the redirect URL
              https.begin(* client, redirectURL);
              httpCode = https.GET();  // Make the new request
            }
            delay(100);
            if (httpCode == HTTP_CODE_OK) {
              
                Serial.println("Downloading file...");

                file = SPIFFS.open("/update.bin", FILE_WRITE);

                WiFiClient* stream = https.getStreamPtr();
                
                int totalDownloaded = 0;
                unsigned long startTime = millis();
                while (https.connected() && (https.getSize() > 0 || https.getSize() == -1)) {
                  static uint8_t buffer[16384];
                    size_t size = stream->available();
                    if (size) {
                        int bytesRead = stream->readBytes(buffer, ((size > sizeof(buffer)) ? sizeof(buffer) : size));
                        file.write(buffer, bytesRead);
                        totalDownloaded += bytesRead;
                        Serial.print("Downloaded: ");
                        Serial.print(totalDownloaded);
                        Serial.println(" bytes");
                    }
                     // Break the loop when all data has been downloaded
                    if (https.getSize() != -1 && totalDownloaded >= https.getSize()) {
                        break;
                    }
                    
                }

                file.close();
                Serial.print("Download completed in ");
                Serial.print(millis() - startTime);
                Serial.println(" ms");
                //writtenToSD = true;
                //Serial.println("Start to transfer firmware via UDS...");
                //sendUDSExtendedDiagnosticSessionRequest();
                //delay(1000);
            } else {
                Serial.print("Error Occurred During Download: ");
                Serial.println(httpCode);
                
            }
            https.end();
        }
        delete client;
        return true;
    }
    return false;
}

void flashESP32() {
    File updateBin = SPIFFS.open("/update.bin", FILE_READ);
    if (!updateBin) return;
    if (!Update.begin(updateBin.size())) {
        updateBin.close();
        return;
    }
    size_t written = Update.writeStream(updateBin);
    if (Update.end() && Update.isFinished()) {
        Serial.println("Update successfully completed. Rebooting.");
        ESP.restart();
    }
    updateBin.close();
}

void resetFlags() {
    has_key = false;
    has_iv = false;
    has_encrypted_url = false;
    memset(aes_key, 0, sizeof(aes_key));  // Clears the aes_key array
    memset(aes_iv, 0, sizeof(aes_iv));    // Clears the aes_iv array
    encrypted_url_hex = "";
}
