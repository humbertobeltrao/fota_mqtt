#include <WiFi.h>
#include <PubSubClient.h>


const char* mqtt_server = "test.mosquitto.org"; //mqtt server
const char* ssid = "Humberto_ETECH_ULTRA";
const char* password = "astronauta3005";
String updateUrl;

WiFiClient espClient;
PubSubClient client(espClient); //lib required for mqtt


void setup()
{
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  Serial.println("connected");
  client.setServer(mqtt_server, 1883);//connecting to mqtt server
  client.setCallback(callback);
  //delay(5000);
  connectmqtt();
}

void callback(char* topic, byte* payload, unsigned int length) {   //callback includes topic and payload ( from which (topic) the payload is comming)
  for (int i = 0; i < length; i++)
  {
    updateUrl += (char)payload[i];
    //Serial.print((char)payload[i]);
  }
  Serial.println(updateUrl);
  Serial.println();
}

void reconnect() {
  while (!client.connected()) {
    Serial.println("Attempting MQTT connection...");
    if (client.connect("ESP32_clientID")) {
      Serial.println("connected");
      client.subscribe("inTopic");

    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void loop()
{
  // put your main code here, to run repeatedly:
  if (!client.connected())
  {
    reconnect();
  }

  client.loop();
}


void connectmqtt()
{
  client.connect("ESP32_clientID");  // ESP will connect to mqtt broker with clientID
  {
    Serial.println("connected to MQTT");
    // Once connected, publish an announcement...

    // ... and resubscribe
    client.subscribe("inTopic"); //topic=Demo
    //client.publish("outTopic",  "connected to MQTT");

    if (!client.connected())
    {
      reconnect();
    }
  }
}
