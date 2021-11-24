# Airbnk lock MQTT-based HomeAssistant integration

MQTT-based control of Airbnk smart locks that are supported by Airbnk (now WeHere) app.

Supported devices (using the gateway W100):
- M300
- M500
- M510 (only device tested so far)

# Installation:

Copy the airbnk folder and all of its contents into your Home Assistant's custom_components folder. This is often located inside of your /config folder. If you are running Hass.io, use SAMBA to copy the folder over. If you are running Home Assistant Supervised, the custom_components folder might be located at /usr/share/hassio/homeassistant. It is possible that your custom_components folder does not exist. If that is the case, create the folder in the proper location, and then copy the airbnk folder and all of its contents inside the newly created custom_components folder.

Alternatively, you can install airbnk through HACS by adding this repository.

# Usage:

The integration can be configured in the following way (YAML config files are NOT supported):

# Installation using config flow

Start by going to Configuration - Integration and pressing the "+ ADD INTEGRATION" button to create a new Integration, then select "Airbnk lock" in the drop-down menu.

Follow the instructions: in the first dialog, you just have to type the email used in the Airbnk/WeHere App. 

**_Note: Airbnk cloud allows to have each user logged in only one device. So, if you use the same email used in the Airbnk app, the user on the app will be logged out. As a consequence, it is suggested to create a new user with full permissions with a different email to be used in the HomeAssistant integration._**  

After pressing the "Submit" button, you will receive a verification code via email that has to be typed into the second dialog. After pressing Submit, the integration will download the info of your device(s) from the cloud, including the necessary keys for encrypting the commands for the lock. Then, for each registered lock device you'll be prompted to input its MQTT topic (see Prerequisites, #3) and MAC address (see Prerequisites, #4). It is also possible to skip the device in order to avoid adding it to HA:

![config_device](https://user-images.githubusercontent.com/49229287/143319300-26071cf6-84f4-4cb6-a6f5-f9b53bef0330.png)

Once you press submit and confirm, the Integration will be added, and the Airbnk locks successfully configured will be created. For each lock, 2 entities are created:
- a Cover entity, that allows to operate the lock
- a Sensor entity, that provides the status of the lock (actually, the outcome of the last command attempt). If the command times out, the sensor will present the "Timed out" status.

# Note:

**The locks are added using Cover entities instead of Lock entities**. This choice is due to the fact that Lock entities only provide one available command (Unlock or Lock), depending on the status of the entity. But, since it can be operated also manually, it is impossible to have an actual knowledge of the real status of the lock. Moreover, most users could desire to give double Lock or Unlock commands. 

As a consequence, the Cover entity is used being deemed more suitable, because it allows to have both commands always available.

# To-do list:

* Figure out whether it's possible to have information about the battery status.

# Thanks to:

This code is based on @nourmehdi 's great work, in finding a way to sniff the traffic and retrieve the token and understand the API calls to be used.
