Instructions to operate Airbnk locks using the nRF Connect App:
1) download and install nRF Connect App

2) open the app, scan for devices and select the lock. Press the RAW button, and export the "Raw data" values. Edit generate_payloads.py and copy the value in the lockAdv parameter (line 35)

3) enable debug for airbnk, by adding the following line to configuration.yaml, in the "logs:" part
    custom_components.airbnk: debug

4) relaunch homeassistant and search the logs for the following output:
	2021-11-16 23:37:47 DEBUG (MainThread) [custom_components.airbnk.airbnk_api] GetCloudDevices succeeded (200): {
		"code":200,
		"data":[
			{
				"sn":"...",
				"deviceName":"...",
				[...],
				"appKey":"...",
				"newSninfo":"HTWsm...aTj2w==",
				[...]
			}
		],
		"info":"OK",
		"totalNum":0,
		"totalPage":0
	}

5) copy the values of "appKey" and "newSninfo" in the related fields into generate_payloads.py script (lines 31, 32)

6) now launch the script with "./generate_payloads.py [1,2]"  (1 is for opening, 2 is for closing)
The output should be something like
DECRYPTED KEYS: {'lockSn': '1234567', 'lockType': 'M510', 'manufacturerKey': b'69...20', 'bindingKey': b'bc...35'}
TIME IS 1637101770
LOCKEVENTS b'0201061BFFBABA...' 138
OPCODE FOR CLOSING IS b'AA101A035A3EA4A5CA7FA4DDD007BBE4E7A9A2A6FE84BCE5EAFED9553500000000000000'
PACKET 1 IS FF00AA101A035A3EA4A5CA7FA4DDD007BBE4E7A9
PACKET 2 IS FF01A2A6FE84BCE5EAFED9553500000000000000

7) transfer the values for PACKET 1 and 2 to your phone

8) go back to nRF Connect app, select the lock and press "Connect", click on the 3 dots on the top right and "Read characteristics". Then, click on the "Unknown Service (UUID 0xFFF0) and you'll see the current values of the characteristics 0xFFF1, 0xFFF2 and 0xFFF3. Press the first "Up-arrow" next to the title "Unknown Characteristic" for UUID 0xFFF2, and paste the value of PACKET 1 in the field New Value (leave BYTEARRAY as value type), and press "SEND". Then press again the "Up-arrow" and paste the VALUE of PACKET 2. Finally, click "SEND"... and the lock should open/close!

9) to operate it again, you need to repeat step 2), because a part of the value has changed (in detail, the bytes 26 and 27)
