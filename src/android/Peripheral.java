// (c) ,2104 Don Coleman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.megster.cordova.ble.central;

import android.app.Activity;

import android.bluetooth.*;
import android.os.Build;
import android.util.Base64;
import android.os.Handler;
import android.os.Looper;
import android.content.Intent;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.LOG;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.io.IOException;

import com.rigado.rigablue.IRigFirmwareUpdateManagerObserver;
import com.rigado.rigablue.RigFirmwareUpdateManager;
import com.rigado.rigablue.RigLeBaseDevice;
import com.rigado.rigablue.RigDfuError;
import com.rigado.rigablue.RigBluetoothGattCallback;
import com.rigado.rigablue.RigService;
import com.rigado.rigablue.RigCoreBluetooth;

import java.net.URL;

/**
 * Peripheral wraps the BluetoothDevice and provides methods to convert to JSON.
 */
public class Peripheral extends RigBluetoothGattCallback implements IRigFirmwareUpdateManagerObserver{

    // 0x2902 org.bluetooth.descriptor.gatt.client_characteristic_configuration.xml
    //public final static UUID CLIENT_CHARACTERISTIC_CONFIGURATION_UUID = UUID.fromString("00002902-0000-1000-8000-00805F9B34FB");
    public final static UUID CLIENT_CHARACTERISTIC_CONFIGURATION_UUID = UUIDHelper.uuidFromString("2902");
    static final String BLUETOOTH_ADMIN_PERM = android.Manifest.permission.BLUETOOTH_ADMIN;
    private static final String TAG = "Peripheral";

    private BluetoothDevice device;
    private byte[] advertisingData;
    private int advertisingRSSI;
    private boolean connected = false;
    private boolean connecting = false;
    private boolean badDisconnect = false;
    private ConcurrentLinkedQueue<BLECommand> commandQueue = new ConcurrentLinkedQueue<BLECommand>();
    private boolean bleProcessing;

    BluetoothGatt gatt;

    private CallbackContext connectCallback;
    private CallbackContext disconnectCallback;
    private CallbackContext readCallback;
    private CallbackContext writeCallback;
    private CallbackContext firmwareCallback;
    private Activity activity;

    private RigFirmwareUpdateManager mFirmwareManager;

    private Map<String, CallbackContext> notificationCallbacks = new HashMap<String, CallbackContext>();

    public Peripheral(BluetoothDevice device, int advertisingRSSI, byte[] scanRecord) {
        super(RigCoreBluetooth.getInstance().getBluetoothLeService().getRigCoreListener(),RigCoreBluetooth.getInstance().getBluetoothLeService().getBluetoothGattHashMap(),RigCoreBluetooth.getInstance().getBluetoothLeService().getBluetoothGattCallbackHashMap());

        this.device = device;
        this.advertisingRSSI = advertisingRSSI;
        this.advertisingData = scanRecord;

    }

    public void connect(CallbackContext callbackContext, Activity activity) {
        this.activity = activity;

        BluetoothDevice device = getDevice();
        if (connected == false && connecting == false){
            connecting = true;

            connectCallback = callbackContext;
            if (this.gatt != null) {
                this.gatt.close();
            }
            LOG.d(TAG, "Trying to connect ( " + String.valueOf(this.badDisconnect) + ")");
            if (Build.VERSION.SDK_INT < 23) {
                gatt = device.connectGatt(activity, false, this);
            } else {
                gatt = device.connectGatt(activity, false, this, BluetoothDevice.TRANSPORT_LE);
            }
            // if (this.gatt != null) {
            //     this.gatt.requestConnectionPriority(1);
            // }
            PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
            result.setKeepCallback(true);
            // callbackContext.sendPluginResult(result);
        }
    }

    public void disconnect(CallbackContext callbackContext) {
        connectCallback = null;

        if (connecting == true || connected == true){
            if (gatt != null) {
                disconnectCallback = callbackContext;
                gatt.disconnect();
            }

            if (connecting == true && connected == false) {
                if (disconnectCallback != null) {
                    disconnectCallback.success();
                }
                this.badDisconnect = true;

                LOG.d(TAG, "Cancelling connection before full connected");
                this.cleanUp(true);
            }
        }
    }

    public JSONObject asJSONObject()  {

        JSONObject json = new JSONObject();

        try {
            json.put("name", device.getName());
            json.put("id", device.getAddress()); // mac address
            json.put("advertising", byteArrayToJSON(advertisingData));
            // TODO real RSSI if we have it, else
            json.put("rssi", advertisingRSSI);
        } catch (JSONException e) { // this shouldn't happen
            e.printStackTrace();
        }

        return json;
    }

    public JSONObject asJSONObject(String errorMessage)  {

        JSONObject json = new JSONObject();

        try {
            json.put("name", device.getName());
            json.put("id", device.getAddress()); // mac address
            json.put("errorMessage", errorMessage);
        } catch (JSONException e) { // this shouldn't happen
            e.printStackTrace();
        }

        return json;
    }

    public JSONObject asJSONObject(BluetoothGatt gatt) {

        JSONObject json = asJSONObject();

        try {
            JSONArray servicesArray = new JSONArray();
            JSONArray characteristicsArray = new JSONArray();
            json.put("services", servicesArray);
            json.put("characteristics", characteristicsArray);

            if (connected && gatt != null) {
                for (BluetoothGattService service : gatt.getServices()) {
                    servicesArray.put(UUIDHelper.uuidToString(service.getUuid()));

                    List<BluetoothGattCharacteristic> characteristics;
                    if (service != null) {
                        characteristics = service.getCharacteristics();
                    } else {
                        characteristics = new ArrayList<BluetoothGattCharacteristic>();
                    }
                    for (BluetoothGattCharacteristic characteristic : characteristics) {
                        JSONObject characteristicsJSON = new JSONObject();
                        characteristicsArray.put(characteristicsJSON);

                        characteristicsJSON.put("service", UUIDHelper.uuidToString(service.getUuid()));
                        characteristicsJSON.put("characteristic", UUIDHelper.uuidToString(characteristic.getUuid()));
                        //characteristicsJSON.put("instanceId", characteristic.getInstanceId());

                        characteristicsJSON.put("properties", Helper.decodeProperties(characteristic));
                            // characteristicsJSON.put("propertiesValue", characteristic.getProperties());

                        if (characteristic.getPermissions() > 0) {
                            characteristicsJSON.put("permissions", Helper.decodePermissions(characteristic));
                            // characteristicsJSON.put("permissionsValue", characteristic.getPermissions());
                        }

                        JSONArray descriptorsArray = new JSONArray();

                        for (BluetoothGattDescriptor descriptor: characteristic.getDescriptors()) {
                            JSONObject descriptorJSON = new JSONObject();
                            descriptorJSON.put("uuid", UUIDHelper.uuidToString(descriptor.getUuid()));
                            descriptorJSON.put("value", descriptor.getValue()); // always blank

                            if (descriptor.getPermissions() > 0) {
                                descriptorJSON.put("permissions", Helper.decodePermissions(descriptor));
                                // descriptorJSON.put("permissionsValue", descriptor.getPermissions());
                            }
                            descriptorsArray.put(descriptorJSON);
                        }
                        if (descriptorsArray.length() > 0) {
                            characteristicsJSON.put("descriptors", descriptorsArray);
                        }
                    }
                }
            }
        } catch (JSONException e) { // TODO better error handling
            e.printStackTrace();
        }

        return json;
    }

    static JSONObject byteArrayToJSON(byte[] bytes) throws JSONException {
        JSONObject object = new JSONObject();
        object.put("CDVType", "ArrayBuffer");
        object.put("data", Base64.encodeToString(bytes, Base64.NO_WRAP));
        return object;
    }

    public boolean isConnected() {
        return connected;
    }

    public boolean isConnecting() {
        return connecting;
    }

    public BluetoothDevice getDevice() {
        return device;
    }

    @Override
    public void onServicesDiscovered(BluetoothGatt gatt, int status) {
        super.onServicesDiscovered(gatt, status);

        connected = true;
        connecting = false;
        if (status == BluetoothGatt.GATT_SUCCESS) {
            LOG.d(TAG, "Received service discovered state");
            PluginResult result = new PluginResult(PluginResult.Status.OK, this.asJSONObject(gatt));
            result.setKeepCallback(true);
            connectCallback.sendPluginResult(result);
        } else {
            LOG.e(TAG, "Service discovery failed. status = " + status);
            connectCallback.error(this.asJSONObject("Service discovery failed"));
            disconnect(null);
        }
    }

    @Override
    public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
        super.onConnectionStateChange(gatt, status, newState);
        this.gatt = gatt;

        if (status == 133) {
            LOG.d(TAG, "Received error 133 (" + newState + ")");
            this.badDisconnect = true;
            if (disconnectCallback != null) {
                disconnectCallback.error(this.asJSONObject("Error status 133 (State:" + String.valueOf(newState) + ")"));
            }

            if (connectCallback != null) {
                connectCallback.error(this.asJSONObject("Error status 133 (State:" + String.valueOf(newState) + ")"));
            }
            this.disconnect(null);

            // this.cleanUp(false);
        } else if (newState == BluetoothGatt.STATE_CONNECTED) {

            LOG.d(TAG, "Received connected state");
            if (connected == false && connecting == false) {
                // It should be a disconnect
                LOG.d(TAG, "Received connected state while connecting is false");
                this.disconnect(null);
            } else {

                // Handler handler = new Handler(Looper.getMainLooper());
                // handler.postDelayed(new Runnable() {
                //     @Override
                //     public void run() {
                //         LOG.d(TAG, "Going to discover services");
                //         if (connected == false && connecting == false) {
                //             // It should be a disconnect
                //             LOG.d(TAG, "Received connected state while connecting is false");
                //             Peripheral.this.disconnect(null);
                //             // this.disconnect(null);
                //         } else {

                //             Peripheral.this.gatt.discoverServices();
                //             // this.gatt.discoverServices();
                //         }
                //     }
                // }, 300);
                this.gatt.requestConnectionPriority(1);
                this.gatt.discoverServices();
            }
            // try {
            //     Thread.sleep(500);
            //     // Do some stuff
            // } catch (Exception e) {
            //     e.getLocalizedMessage();
            // }
            // gatt.discoverServices();

        } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
            LOG.d(TAG, "Received disconnected state");
            this.badDisconnect = false;
            if (disconnectCallback != null) {
                disconnectCallback.success();
            }

            if (connectCallback != null) {
                connectCallback.error(this.asJSONObject("Peripheral Disconnected"));
            }

            this.cleanUp(true);
        } else {

            this.badDisconnect = true;
            if (disconnectCallback != null) {
                disconnectCallback.error(this.asJSONObject("Peripheral received status " + String.valueOf(status) + " and state" + String.valueOf(newState) ));
            }

            if (connectCallback != null) {
                connectCallback.error(this.asJSONObject("Peripheral changed to status " + String.valueOf(status) + " and state" + String.valueOf(newState) ));
            }

            LOG.d(TAG, "Received weird status " + String.valueOf(status));
            this.cleanUp(true);
        }

    }

    public void cleanUp(boolean close) {

        this.connected = false;
        this.connecting = false;
        this.commandQueue.clear();
        this.bleProcessing = false;
        if (close) {
            // try {
            //     Thread.sleep(500);
            //     // Do some stuff
            // } catch (Exception e) {
            //     e.getLocalizedMessage();
            // }
            this.gatt.close();
            this.gatt = null;
            // this.gatt = null;
            // Handler handler = new Handler(Looper.getMainLooper());
            // handler.postDelayed(new Runnable() {
            //     @Override
            //     public void run() {
            //         LOG.d(TAG, "Closing Gatt");
            //         Peripheral.;
            //         Peripheral.this.gatt = null;
            //     }
            // }, 500);
        }
        // We try to force it down we this:
        // if (activity != null){
        //     Intent intent = new Intent(BluetoothDevice.ACTION_ACL_DISCONNECT_REQUESTED);
        //     intent.putExtra(BluetoothDevice.EXTRA_DEVICE, getDevice().getAddress());
        //     activity.getApplicationContext().sendBroadcast(intent, BLUETOOTH_ADMIN_PERM);
        // }
    }

    @Override
    public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
        super.onCharacteristicChanged(gatt, characteristic);
        LOG.d(TAG, "onCharacteristicChanged " + characteristic);

        CallbackContext callback = notificationCallbacks.get(generateHashKey(characteristic));

        if (callback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, characteristic.getValue());
            result.setKeepCallback(true);
            callback.sendPluginResult(result);
        }
    }

    @Override
    public void onCharacteristicRead(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
        super.onCharacteristicRead(gatt, characteristic, status);
        LOG.d(TAG, "onCharacteristicRead " + characteristic);

        if (readCallback != null) {

            if (status == BluetoothGatt.GATT_SUCCESS) {
                readCallback.success(characteristic.getValue());
            } else {
                readCallback.error("Error reading " + characteristic.getUuid() + " status=" + status);
            }

            readCallback = null;

        }

        commandCompleted();
    }

    @Override
    public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
        super.onCharacteristicWrite(gatt, characteristic, status);
        LOG.d(TAG, "onCharacteristicWrite " + characteristic);

        if (writeCallback != null) {

            if (status == BluetoothGatt.GATT_SUCCESS) {
                writeCallback.success();
            } else {
                writeCallback.error(status);
            }

            writeCallback = null;
        }

        commandCompleted();
    }

    @Override
    public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
        super.onDescriptorWrite(gatt, descriptor, status);
        LOG.d(TAG, "onDescriptorWrite " + descriptor);
        commandCompleted();
    }


    @Override
    public void onReadRemoteRssi(BluetoothGatt gatt, int rssi, int status) {
        super.onReadRemoteRssi(gatt, rssi, status);

        LOG.d(TAG, "Received remote RSSI" + rssi);
        if (readCallback != null) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                updateRssi(rssi);
                readCallback.success(rssi);
            } else {
                readCallback.error("Error reading RSSI status=" + status);
            }

            readCallback = null;
        }
        commandCompleted();
    }

    // Update rssi and scanRecord.
    public void update(int rssi, byte[] scanRecord) {
        this.advertisingRSSI = rssi;
        this.advertisingData = scanRecord;
    }

    public void updateRssi(int rssi) {
        advertisingRSSI = rssi;
    }

    // This seems way too complicated
    private void registerNotifyCallback(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID) {

        boolean success = false;

        if (gatt == null) {
            callbackContext.error("BluetoothGatt is null");
            return;
        }

        BluetoothGattService service = gatt.getService(serviceUUID);
        BluetoothGattCharacteristic characteristic = findNotifyCharacteristic(service, characteristicUUID);
        String key = generateHashKey(serviceUUID, characteristic);

        if (characteristic != null) {

            notificationCallbacks.put(key, callbackContext);

            if (gatt.setCharacteristicNotification(characteristic, true)) {

                // Why doesn't setCharacteristicNotification write the descriptor?
                BluetoothGattDescriptor descriptor = characteristic.getDescriptor(CLIENT_CHARACTERISTIC_CONFIGURATION_UUID);
                if (descriptor != null) {

                    // prefer notify over indicate
                    if ((characteristic.getProperties() & BluetoothGattCharacteristic.PROPERTY_NOTIFY) != 0) {
                        descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    } else if ((characteristic.getProperties() & BluetoothGattCharacteristic.PROPERTY_INDICATE) != 0) {
                        descriptor.setValue(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE);
                    } else {
                        LOG.w(TAG, "Characteristic " + characteristicUUID + " does not have NOTIFY or INDICATE property set");
                    }

                    if (gatt.writeDescriptor(descriptor)) {
                        success = true;
                    } else {
                        callbackContext.error("Failed to set client characteristic notification for " + characteristicUUID);
                    }

                } else {
                    callbackContext.error("Set notification failed for " + characteristicUUID);
                }

            } else {
                callbackContext.error("Failed to register notification for " + characteristicUUID);
            }

        } else {
            callbackContext.error("Characteristic " + characteristicUUID + " not found");
        }

        if (!success) {
            commandCompleted();
        }
    }

    private void removeNotifyCallback(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID) {

        if (gatt == null) {
            callbackContext.error("BluetoothGatt is null");
            return;
        }

        BluetoothGattService service = gatt.getService(serviceUUID);
        BluetoothGattCharacteristic characteristic = findNotifyCharacteristic(service, characteristicUUID);
        String key = generateHashKey(serviceUUID, characteristic);

        if (characteristic != null) {

            notificationCallbacks.remove(key);

            if (gatt.setCharacteristicNotification(characteristic, false)) {
                BluetoothGattDescriptor descriptor = characteristic.getDescriptor(CLIENT_CHARACTERISTIC_CONFIGURATION_UUID);
                if (descriptor != null) {
                    descriptor.setValue(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE);
                    gatt.writeDescriptor(descriptor);
                }
                callbackContext.success();
            } else {
                // TODO we can probably ignore and return success anyway since we removed the notification callback
                callbackContext.error("Failed to stop notification for " + characteristicUUID);
            }

        } else {
            callbackContext.error("Characteristic " + characteristicUUID + " not found");
        }

        commandCompleted();

    }

    // Some devices reuse UUIDs across characteristics, so we can't use service.getCharacteristic(characteristicUUID)
    // instead check the UUID and properties for each characteristic in the service until we find the best match
    // This function prefers Notify over Indicate
    private BluetoothGattCharacteristic findNotifyCharacteristic(BluetoothGattService service, UUID characteristicUUID) {
        BluetoothGattCharacteristic characteristic = null;

        // Check for Notify first
        List<BluetoothGattCharacteristic> characteristics = service.getCharacteristics();
        for (BluetoothGattCharacteristic c : characteristics) {
            if ((c.getProperties() & BluetoothGattCharacteristic.PROPERTY_NOTIFY) != 0 && characteristicUUID.equals(c.getUuid())) {
                characteristic = c;
                break;
            }
        }

        if (characteristic != null) return characteristic;

        // If there wasn't Notify Characteristic, check for Indicate
        for (BluetoothGattCharacteristic c : characteristics) {
            if ((c.getProperties() & BluetoothGattCharacteristic.PROPERTY_INDICATE) != 0 && characteristicUUID.equals(c.getUuid())) {
                characteristic = c;
                break;
            }
        }

        // As a last resort, try and find ANY characteristic with this UUID, even if it doesn't have the correct properties
        if (characteristic == null) {
            characteristic = service.getCharacteristic(characteristicUUID);
        }

        return characteristic;
    }

    private void readCharacteristic(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID) {

        boolean success = false;

        if (gatt == null) {
            callbackContext.error("BluetoothGatt is null");
            return;
        }

        BluetoothGattService service = gatt.getService(serviceUUID);
        BluetoothGattCharacteristic characteristic = findReadableCharacteristic(service, characteristicUUID);

        if (characteristic == null) {
            callbackContext.error("Characteristic " + characteristicUUID + " not found.");
        } else {
            readCallback = callbackContext;
            if (gatt.readCharacteristic(characteristic)) {
                success = true;
            } else {
                readCallback = null;
                callbackContext.error("Read failed");
            }
        }

        if (!success) {
            commandCompleted();
        }

    }

    private void readRSSI(CallbackContext callbackContext) {

        boolean success = false;

        if (gatt == null) {
            callbackContext.error("BluetoothGatt is null");
            return;
        }

        readCallback = callbackContext;

        if (gatt.readRemoteRssi()) {
            success = true;
        } else {
            readCallback = null;
            callbackContext.error("Read RSSI failed");
        }

        if (!success) {
            commandCompleted();
        }

    }

    public void updateFirmware(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID, String firmwareURL, byte[] data) {
        if (mFirmwareManager == null) {
            mFirmwareManager = new RigFirmwareUpdateManager();
        }
        mFirmwareManager.setObserver(this);
        firmwareCallback = callbackContext;

        try {
            URL url = new URL(firmwareURL);
            RigLeBaseDevice device = null;
            // RigLeBaseDevice device = new RigLeBaseDevice(
            //         this.device,
            //         Arrays.asList(gatt.getService(serviceUUID)),
            //         this.advertisingData
            // );

            mFirmwareManager.updateFirmware(
                    device,
                    url.openStream(),
                    gatt.getService(serviceUUID).getCharacteristic(characteristicUUID),
                    data
            );
        } catch (IOException e) {
            e.printStackTrace();
            callbackContext.error("Problem opening image firmware");
        }
    }
    // Some peripherals re-use UUIDs for multiple characteristics so we need to check the properties
    // and UUID of all characteristics instead of using service.getCharacteristic(characteristicUUID)
    private BluetoothGattCharacteristic findReadableCharacteristic(BluetoothGattService service, UUID characteristicUUID) {
        BluetoothGattCharacteristic characteristic = null;

        int read = BluetoothGattCharacteristic.PROPERTY_READ;

        List<BluetoothGattCharacteristic> characteristics = service.getCharacteristics();
        for (BluetoothGattCharacteristic c : characteristics) {
            if ((c.getProperties() & read) != 0 && characteristicUUID.equals(c.getUuid())) {
                characteristic = c;
                break;
            }
        }

        // As a last resort, try and find ANY characteristic with this UUID, even if it doesn't have the correct properties
        if (characteristic == null) {
            characteristic = service.getCharacteristic(characteristicUUID);
        }

        return characteristic;
    }

    private void writeCharacteristic(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID, byte[] data, int writeType) {

        boolean success = false;

        if (gatt == null) {
            callbackContext.error("BluetoothGatt is null");
            return;
        }

        BluetoothGattService service = gatt.getService(serviceUUID);
        BluetoothGattCharacteristic characteristic = findWritableCharacteristic(service, characteristicUUID, writeType);

        if (characteristic == null) {
            callbackContext.error("Characteristic " + characteristicUUID + " not found.");
        } else {
            characteristic.setValue(data);
            characteristic.setWriteType(writeType);
            writeCallback = callbackContext;

            if (gatt.writeCharacteristic(characteristic)) {
                success = true;
            } else {
                writeCallback = null;
                callbackContext.error("Write failed");
            }
        }

        if (!success) {
            commandCompleted();
        }

    }

    // Some peripherals re-use UUIDs for multiple characteristics so we need to check the properties
    // and UUID of all characteristics instead of using service.getCharacteristic(characteristicUUID)
    private BluetoothGattCharacteristic findWritableCharacteristic(BluetoothGattService service, UUID characteristicUUID, int writeType) {
        BluetoothGattCharacteristic characteristic = null;

        // get write property
        int writeProperty = BluetoothGattCharacteristic.PROPERTY_WRITE;
        if (writeType == BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) {
            writeProperty = BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE;
        }

        List<BluetoothGattCharacteristic> characteristics = service.getCharacteristics();
        for (BluetoothGattCharacteristic c : characteristics) {
            if ((c.getProperties() & writeProperty) != 0 && characteristicUUID.equals(c.getUuid())) {
                characteristic = c;
                break;
            }
        }

        // As a last resort, try and find ANY characteristic with this UUID, even if it doesn't have the correct properties
        if (characteristic == null) {
            characteristic = service.getCharacteristic(characteristicUUID);
        }

        return characteristic;
    }

    public void queueRead(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID) {
        BLECommand command = new BLECommand(callbackContext, serviceUUID, characteristicUUID, BLECommand.READ);
        queueCommand(command);
    }

    public void queueWrite(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID, byte[] data, int writeType) {
        BLECommand command = new BLECommand(callbackContext, serviceUUID, characteristicUUID, data, writeType);
        queueCommand(command);
    }

    public void queueRegisterNotifyCallback(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID) {
        BLECommand command = new BLECommand(callbackContext, serviceUUID, characteristicUUID, BLECommand.REGISTER_NOTIFY);
        queueCommand(command);
    }

    public void queueRemoveNotifyCallback(CallbackContext callbackContext, UUID serviceUUID, UUID characteristicUUID) {
        BLECommand command = new BLECommand(callbackContext, serviceUUID, characteristicUUID, BLECommand.REMOVE_NOTIFY);
        queueCommand(command);
    }


    public void queueReadRSSI(CallbackContext callbackContext) {
        BLECommand command = new BLECommand(callbackContext, null, null, BLECommand.READ_RSSI);
        queueCommand(command);
    }

    // add a new command to the queue
    private void queueCommand(BLECommand command) {
        LOG.d(TAG,"Queuing Command " + command);
        commandQueue.add(command);

        PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
        result.setKeepCallback(true);
        command.getCallbackContext().sendPluginResult(result);

        if (!bleProcessing) {
            processCommands();
        }
    }

    // command finished, queue the next command
    private void commandCompleted() {
        LOG.d(TAG,"Processing Complete");
        bleProcessing = false;
        processCommands();
    }

    // process the queue
    private void processCommands() {
        LOG.d(TAG,"Processing Commands");

        if (bleProcessing) { return; }

        BLECommand command = commandQueue.poll();
        if (command != null) {
            if (command.getType() == BLECommand.READ) {
                LOG.d(TAG,"Read " + command.getCharacteristicUUID());
                bleProcessing = true;
                readCharacteristic(command.getCallbackContext(), command.getServiceUUID(), command.getCharacteristicUUID());
            } else if (command.getType() == BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) {
                LOG.d(TAG,"Write " + command.getCharacteristicUUID());
                bleProcessing = true;
                writeCharacteristic(command.getCallbackContext(), command.getServiceUUID(), command.getCharacteristicUUID(), command.getData(), command.getType());
            } else if (command.getType() == BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) {
                LOG.d(TAG,"Write No Response " + command.getCharacteristicUUID());
                bleProcessing = true;
                writeCharacteristic(command.getCallbackContext(), command.getServiceUUID(), command.getCharacteristicUUID(), command.getData(), command.getType());
            } else if (command.getType() == BLECommand.REGISTER_NOTIFY) {
                LOG.d(TAG,"Register Notify " + command.getCharacteristicUUID());
                bleProcessing = true;
                registerNotifyCallback(command.getCallbackContext(), command.getServiceUUID(), command.getCharacteristicUUID());
            } else if (command.getType() == BLECommand.REMOVE_NOTIFY) {
                LOG.d(TAG,"Remove Notify " + command.getCharacteristicUUID());
                bleProcessing = true;
                removeNotifyCallback(command.getCallbackContext(), command.getServiceUUID(), command.getCharacteristicUUID());
            } else if (command.getType() == BLECommand.READ_RSSI) {
                LOG.d(TAG,"Read RSSI");
                bleProcessing = true;
                readRSSI(command.getCallbackContext());
            } else {
                // this shouldn't happen
                throw new RuntimeException("Unexpected BLE Command type " + command.getType());
            }
        } else {
            LOG.d(TAG, "Command Queue is empty.");
        }

    }

    private String generateHashKey(BluetoothGattCharacteristic characteristic) {
        return generateHashKey(characteristic.getService().getUuid(), characteristic);
    }

    private String generateHashKey(UUID serviceUUID, BluetoothGattCharacteristic characteristic) {
        return String.valueOf(serviceUUID) + "|" + characteristic.getUuid() + "|" + characteristic.getInstanceId();
    }

    // FIRMWARE UPDATE
    @Override
    public void updateProgress(final int progress) {
        LOG.d(TAG, "Firmware update progressed ( " + Integer.toString(progress) + "% )");
        if (firmwareCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, progress);
            result.setKeepCallback(true);
            firmwareCallback.sendPluginResult(result);
        }
    }

    @Override
    public void updateStatus(String status, int error) {
        LOG.d(TAG, "Firmware updated received ( " + status + ")");

    }

    @Override
    public void didFinishUpdate() {
        LOG.d(TAG, "Firmware updated finished");
        if (firmwareCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, 100);
            result.setKeepCallback(true);
            firmwareCallback.sendPluginResult(result);
            firmwareCallback.success();
        }
    }

    @Override
    public void updateFailed(final RigDfuError error) {
        LOG.d(TAG, "Firmware updated failed ( " + error.getErrorMessage() + " )");
        if (firmwareCallback != null) {
            firmwareCallback.error("Update failed:" + error.getErrorMessage());
        }
    }

}
