// (c) 2014-2016 Don Coleman
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

import android.Manifest;
import android.app.Activity;
import android.util.Base64;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.Build;
import android.os.ParcelUuid;

import android.provider.Settings;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.LOG;
import org.apache.cordova.PermissionHelper;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.util.*;
import java.net.URL;
import java.io.IOException;
import com.rigado.rigablue.RigCoreBluetooth;
import com.rigado.rigablue.RigLeBaseDevice;
import com.rigado.rigablue.RigDeviceRequest;
import com.rigado.rigablue.RigAvailableDeviceData;
import com.rigado.rigablue.RigLeConnectionManager;
import com.rigado.rigablue.RigLeDiscoveryManager;
import com.rigado.rigablue.RigFirmwareUpdateManager;
import com.rigado.rigablue.RigDfuError;
import com.rigado.rigablue.IRigLeBaseDeviceObserver;
import com.rigado.rigablue.IRigLeConnectionManagerObserver;
import com.rigado.rigablue.IRigLeDiscoveryManagerObserver;
import com.rigado.rigablue.IRigFirmwareUpdateManagerObserver;

public class BLECentralPlugin extends CordovaPlugin implements IRigLeDiscoveryManagerObserver, IRigLeConnectionManagerObserver, IRigLeBaseDeviceObserver, IRigFirmwareUpdateManagerObserver {
    // actions
    private static final String SCAN = "scan";
    private static final String START_SCAN = "startScan";
    private static final String STOP_SCAN = "stopScan";
    private static final String START_SCAN_WITH_OPTIONS = "startScanWithOptions";

    private static final String LIST = "list";

    private static final String CONNECT = "connect";
    private static final String DISCONNECT = "disconnect";

    private static final String READ = "read";
    private static final String WRITE = "write";
    private static final String WRITE_WITHOUT_RESPONSE = "writeWithoutResponse";

    private static final String READ_RSSI = "readRSSI";

    private static final String START_NOTIFICATION = "startNotification"; // register for characteristic notification
    private static final String STOP_NOTIFICATION = "stopNotification"; // remove characteristic notification

    private static final String IS_ENABLED = "isEnabled";
    private static final String IS_CONNECTED  = "isConnected";

    private static final String SETTINGS = "showBluetoothSettings";
    private static final String ENABLE = "enable";

    private static final String START_STATE_NOTIFICATIONS = "startStateNotifications";
    private static final String STOP_STATE_NOTIFICATIONS = "stopStateNotifications";

    private static final String HELLO_WORLD = "helloWorld";
    private static final String UPDATE_FIRMWARE = "updateFirmware";


    // callbacks
    CallbackContext discoverCallback;
    private CallbackContext enableBluetoothCallback;

    private static final String TAG = "BLEPlugin";
    private static final int REQUEST_ENABLE_BLUETOOTH = 1;

    BluetoothAdapter bluetoothAdapter;
    BluetoothLeScanner bluetoothScanner;
    BluetoothManager bluetoothManager;
    ScanSettings settings;
    List<ScanFilter> filters;

    // key is the MAC Address
    Map<String, RigAvailableDeviceData> availableDevices = new LinkedHashMap<String, RigAvailableDeviceData>();
    Map<String, RigLeBaseDevice> devices = new LinkedHashMap<String, RigLeBaseDevice>();


    // Callbacks
    Map<String, CallbackContext> connectCallbacks = new LinkedHashMap<String, CallbackContext>();
    Map<String, CallbackContext> disconnectCallbacks = new LinkedHashMap<String, CallbackContext>();
    Map<String, CallbackContext> writeCallbacks = new LinkedHashMap<String, CallbackContext>();
    Map<String, CallbackContext> readCallbacks = new LinkedHashMap<String, CallbackContext>();
    Map<String, CallbackContext> readRSSICallbacks = new LinkedHashMap<String, CallbackContext>();
    Map<String, CallbackContext> notifyCallbacks = new LinkedHashMap<String, CallbackContext>();

    // Rigado
    private RigCoreBluetooth mRigCoreBluetooth;
    private RigLeConnectionManager mRigConnectionManager;
    private RigLeDiscoveryManager mRigDiscoveryManager;
    private RigFirmwareUpdateManager mFirmwareManager;

    // scan options
    boolean reportDuplicates = false;

    // Android 23 requires new permissions for BluetoothLeScanner.startScan()
    private static final String ACCESS_COARSE_LOCATION = Manifest.permission.ACCESS_COARSE_LOCATION;
    private static final int REQUEST_ACCESS_COARSE_LOCATION = 2;
    private static final int PERMISSION_DENIED_ERROR = 20;
    private CallbackContext permissionCallback;
    private UUID[] serviceUUIDs;
    private int scanSeconds;

    // Bluetooth state notification
    CallbackContext stateCallback;
    CallbackContext firmwareCallback;
    BroadcastReceiver stateReceiver;
    Map<Integer, String> bluetoothStates = new Hashtable<Integer, String>() {{
        put(BluetoothAdapter.STATE_OFF, "off");
        put(BluetoothAdapter.STATE_TURNING_OFF, "turningOff");
        put(BluetoothAdapter.STATE_ON, "on");
        put(BluetoothAdapter.STATE_TURNING_ON, "turningOn");
    }};

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        RigCoreBluetooth.initialize(this.cordova.getActivity().getApplicationContext());
        mRigCoreBluetooth = RigCoreBluetooth.getInstance();
        mRigConnectionManager = RigLeConnectionManager.getInstance();
        mRigDiscoveryManager = RigLeDiscoveryManager.getInstance();
        // your init code here
    }
    public void onDestroy() {
        removeStateListener();
    }

    public void onReset() {
        removeStateListener();
    }


    @Override
    public boolean execute(String action, CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        LOG.d(TAG, "action = " + action);

        // TODO
        if (bluetoothAdapter == null) {
            Activity activity = cordova.getActivity();
            boolean hardwareSupportsBLE = activity.getApplicationContext()
                                            .getPackageManager()
                                            .hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) &&
                                            Build.VERSION.SDK_INT >= 18;
            if (!hardwareSupportsBLE) {
              LOG.w(TAG, "This hardware does not support Bluetooth Low Energy.");
              callbackContext.error("This hardware does not support Bluetooth Low Energy.");
              return false;
            }
            bluetoothManager = (BluetoothManager) activity.getSystemService(Context.BLUETOOTH_SERVICE);
            bluetoothAdapter = bluetoothManager.getAdapter();
        }

        // if (bluetoothScanner == null) {
        //     bluetoothScanner = bluetoothAdapter.getBluetoothLeScanner();
        //     ScanSettings.Builder sBuilder = new ScanSettings.Builder()
        //         .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY);

        //     if (Build.VERSION.SDK_INT > 22) {
        //         sBuilder.setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE);
        //     }
        //     settings = sBuilder.build();

        // }

        boolean validAction = true;

        if (action.equals(SCAN)) {
            // Done

            UUID[] serviceUUIDs = parseServiceUUIDList(args.getJSONArray(0));
            int scanSeconds = args.getInt(1);

            resetScanOptions();
            scan(callbackContext, serviceUUIDs, scanSeconds);

        } else if (action.equals(START_SCAN)) {
            // Done

            UUID[] serviceUUIDs = parseServiceUUIDList(args.getJSONArray(0));
            resetScanOptions();
            scan(callbackContext, serviceUUIDs, -1);

        } else if (action.equals(STOP_SCAN)) {
            // Done

            // stopDiscoverCallback = callbackContext;
            mRigDiscoveryManager.stopDiscoveringDevices();
            callbackContext.success();

        } else if (action.equals(LIST)) {
            // Done
            listKnownDevices(callbackContext);

        } else if (action.equals(CONNECT)) {
            // Done
            String macAddress = args.getString(0);
            connect(callbackContext, macAddress);

        } else if (action.equals(DISCONNECT)) {
            // Done
            String macAddress = args.getString(0);
            disconnect(callbackContext, macAddress);

        } else if (action.equals(READ)) {
            // Done
            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            read(callbackContext, macAddress, serviceUUID, characteristicUUID);

        } else if (action.equals(READ_RSSI)) {
            // Done
            String macAddress = args.getString(0);
            readRSSI(callbackContext, macAddress);

        } else if (action.equals(WRITE)) {
            // Done
            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            byte[] data = args.getArrayBuffer(3);
            int type = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT;
            write(callbackContext, macAddress, serviceUUID, characteristicUUID, data, type);

        } else if (action.equals(WRITE_WITHOUT_RESPONSE)) {
            // Done
            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            byte[] data = args.getArrayBuffer(3);
            int type = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE;
            write(callbackContext, macAddress, serviceUUID, characteristicUUID, data, type);

        } else if (action.equals(START_NOTIFICATION)) {
            // Done
            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            registerNotifyCallback(callbackContext, macAddress, serviceUUID, characteristicUUID);

        } else if (action.equals(STOP_NOTIFICATION)) {
            // Done
            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            removeNotifyCallback(callbackContext, macAddress, serviceUUID, characteristicUUID);

        } else if (action.equals(IS_ENABLED)) {
            // Done
            if (bluetoothAdapter.isEnabled()) {
                callbackContext.success();
            } else {
                callbackContext.error("Bluetooth is disabled.");
            }

        } else if (action.equals(IS_CONNECTED)) {
            // Done
            String macAddress = args.getString(0);
            if (devices.containsKey(macAddress)) {
                callbackContext.success();
            } else {
                callbackContext.error("Not connected.");
            }

        } else if (action.equals(SETTINGS)) {
            // Done
            Intent intent = new Intent(Settings.ACTION_BLUETOOTH_SETTINGS);
            cordova.getActivity().startActivity(intent);
            callbackContext.success();

        } else if (action.equals(ENABLE)) {
            // Done
            enableBluetoothCallback = callbackContext;
            Intent intent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
            cordova.startActivityForResult(this, intent, REQUEST_ENABLE_BLUETOOTH);

        } else if (action.equals(START_STATE_NOTIFICATIONS)) {
            // Done
            if (this.stateCallback != null) {
                callbackContext.error("State callback already registered.");
            } else {
                this.stateCallback = callbackContext;
                // addStateListener();
                sendBluetoothStateChange(bluetoothAdapter.getState());
            }

        } else if (action.equals(STOP_STATE_NOTIFICATIONS)) {
            // Done
            if (this.stateCallback != null) {
                // Clear callback in JavaScript without actually calling it
                PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
                result.setKeepCallback(false);
                this.stateCallback.sendPluginResult(result);
                this.stateCallback = null;
            }
            // removeStateListener();
            callbackContext.success();

        } else if (action.equals(START_SCAN_WITH_OPTIONS)) {
            // Done
            UUID[] serviceUUIDs = parseServiceUUIDList(args.getJSONArray(0));
            JSONObject options = args.getJSONObject(1);

            resetScanOptions();
            this.reportDuplicates = options.optBoolean("reportDuplicates", false);
            scan(callbackContext, serviceUUIDs, -1);

        } else if (action.equals(UPDATE_FIRMWARE)) {
            String macAddress = args.getString(0);
            UUID serviceUUID = uuidFromString(args.getString(1));
            UUID characteristicUUID = uuidFromString(args.getString(2));
            String firmwareURL = args.getString(3);
            byte[] data = args.getArrayBuffer(4);

            updateFirmware(callbackContext, macAddress, serviceUUID, characteristicUUID, firmwareURL, data);
        } else {
            validAction = false;
        }

        return validAction;
    }

    private UUID[] parseServiceUUIDList(JSONArray jsonArray) throws JSONException {
        List<UUID> serviceUUIDs = new ArrayList<UUID>();

        for(int i = 0; i < jsonArray.length(); i++){
            String uuidString = jsonArray.getString(i);
            serviceUUIDs.add(uuidFromString(uuidString));
        }

        return serviceUUIDs.toArray(new UUID[jsonArray.length()]);
    }

    private void onBluetoothStateChange(Intent intent) {
        final String action = intent.getAction();

        if (action.equals(BluetoothAdapter.ACTION_STATE_CHANGED)) {
            final int state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR);
            sendBluetoothStateChange(state);
        }
    }

    private void sendBluetoothStateChange(int state) {
        if (this.stateCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, this.bluetoothStates.get(state));
            result.setKeepCallback(true);
            this.stateCallback.sendPluginResult(result);
        }
    }

    private void addStateListener() {
        if (this.stateReceiver == null) {
            this.stateReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    onBluetoothStateChange(intent);
                }
            };
        }

        try {
            IntentFilter intentFilter = new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED);
            webView.getContext().registerReceiver(this.stateReceiver, intentFilter);
        } catch (Exception e) {
            LOG.e(TAG, "Error registering state receiver: " + e.getMessage(), e);
        }
    }

    private void removeStateListener() {
        if (this.stateReceiver != null) {
            try {
                webView.getContext().unregisterReceiver(this.stateReceiver);
            } catch (Exception e) {
                LOG.e(TAG, "Error unregistering state receiver: " + e.getMessage(), e);
            }
        }
        this.stateCallback = null;
        this.stateReceiver = null;
    }

    private void connect(CallbackContext callbackContext, String macAddress) {
        // Since connect was explicitely called, we remove the disconnectCallback
        if (disconnectCallbacks.containsKey(macAddress)) {
            disconnectCallbacks.remove(macAddress);
        }
        connectCallbacks.put(macAddress, callbackContext);
        RigAvailableDeviceData device = availableDevices.get(macAddress);
        mRigConnectionManager.connectDevice(device, 0);
    }

    private void disconnect(CallbackContext callbackContext, String macAddress) {
        disconnectCallbacks.put(macAddress, callbackContext);
        RigLeBaseDevice device = devices.get(macAddress);

        // Since disconnect was explicitely called, we remove the connectCallback
        if (connectCallbacks.containsKey(macAddress)) {
            connectCallbacks.remove(macAddress);
        }

        if (device != null) {
            mRigConnectionManager.disconnectDevice(device);
        } else {
            RigAvailableDeviceData availableDevice = availableDevices.get(macAddress);
            mRigConnectionManager.cancelConnection(availableDevice);
            callbackContext.success();
            if(devices.containsKey(device.getAddress())) {
                devices.remove(device.getAddress());
            }
        }
    }

    private void read(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID) {

        RigLeBaseDevice device = devices.get(macAddress);

        if (device == null) {
            callbackContext.error("Peripheral " + macAddress + " not connected.");
            return;
        }

        device.setObserver(this);
        readCallbacks.put(macAddress, callbackContext);
        BluetoothGattCharacteristic characteristic = device.findCharacteristic(serviceUUID, characteristicUUID, BluetoothGattCharacteristic.PROPERTY_READ);
        boolean result = device.readCharacteristic(characteristic);

        if (result == false) {
            callbackContext.error("Characteristic " + characteristicUUID + " not found.");
            readCallbacks.remove(macAddress);
            return;
        }
    }

    private void readRSSI(CallbackContext callbackContext, String macAddress) {
        RigLeBaseDevice device = devices.get(macAddress);

        if (device == null) {
            callbackContext.error("Peripheral " + macAddress + " not connected.");
            return;
        }

        device.setObserver(this);
        readRSSICallbacks.put(macAddress, callbackContext);
        boolean result = device.readRSSI();
    }

    private void write(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID,
                       byte[] data, int writeType) {

        RigLeBaseDevice device = devices.get(macAddress);

        if (device == null) {
            callbackContext.error("Peripheral " + macAddress + " not connected.");
            return;
        }

        device.setObserver(this);
        BluetoothGattCharacteristic characteristic = device.findCharacteristic(serviceUUID, characteristicUUID, writeType);
        if (writeType != BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) {
            writeCallbacks.put(generateHashKey(macAddress, characteristic), callbackContext);
        }
        boolean result = device.writeCharacteristic(characteristic, data);
        if (result == false) {
            callbackContext.error("Characteristic " + characteristicUUID + " not found.");
            if (writeType != BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) {
                writeCallbacks.remove(macAddress);
            }
            return;
        }
        if (writeType == BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE) {
            callbackContext.success();
        }

    }

    private void updateFirmware(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID, String firmwareURL, byte[] activationBytes) {

        if (mFirmwareManager == null) {
            mFirmwareManager = new RigFirmwareUpdateManager();
        }
        mFirmwareManager.setObserver(this);
        if (firmwareCallback != null) {
            firmwareCallback.error("Cannot start two firmware updates at the same time");
        }
        firmwareCallback = callbackContext;

        try {
            URL url = new URL(firmwareURL);
            RigLeBaseDevice device = devices.get(macAddress);
            if (device == null) {
                callbackContext.error("Peripheral " + macAddress + " not found.");
                return;
            }
            BluetoothGattCharacteristic characteristic = device.findCharacteristic(serviceUUID, characteristicUUID, BluetoothGattCharacteristic.PROPERTY_WRITE);
            mFirmwareManager.updateFirmware(
                                            device,
                                            url.openStream(),
                                            characteristic,
                                            activationBytes
            );
        } catch (IOException e) {
            e.printStackTrace();
            callbackContext.error("Problem opening image firmware");
        }
    }

    private void registerNotifyCallback(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID) {

        RigLeBaseDevice device = devices.get(macAddress);

        if (device == null) {
            callbackContext.error("Peripheral " + macAddress + " not connected.");
            return;
        }

        device.setObserver(this);
        BluetoothGattCharacteristic characteristic = device.findCharacteristic(serviceUUID, characteristicUUID, BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        boolean result = false;
        if (characteristic != null) {
            notifyCallbacks.put(generateHashKey(macAddress, characteristic), callbackContext);
            result = device.setCharacteristicNotification(characteristic, true);
        } else {
            callbackContext.error("Characteristic " + characteristicUUID + " not found.");
            return;
        }

        if (result == false) {
            callbackContext.error("Characteristic " + characteristicUUID + " not found.");
            notifyCallbacks.remove(generateHashKey(macAddress, characteristic));
            return;
        }
    }

    private void removeNotifyCallback(CallbackContext callbackContext, String macAddress, UUID serviceUUID, UUID characteristicUUID) {

        RigLeBaseDevice device = devices.get(macAddress);

        if (device == null) {
            callbackContext.error("Peripheral " + macAddress + " not connected.");
            return;
        }

        device.setObserver(this);
        BluetoothGattCharacteristic characteristic = device.findCharacteristic(serviceUUID, characteristicUUID, BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        if (characteristic != null) {
            notifyCallbacks.remove(generateHashKey(macAddress, characteristic));
            device.setCharacteristicNotification(characteristic, false);
        }
        callbackContext.success();
    }


    private void scan(CallbackContext callbackContext, UUID[] serviceUUIDs, int scanSeconds) {
        if(!PermissionHelper.hasPermission(this, ACCESS_COARSE_LOCATION)) {
            // save info so we can call this method again after permissions are granted
            permissionCallback = callbackContext;
            this.serviceUUIDs = serviceUUIDs;
            this.scanSeconds = scanSeconds;
            PermissionHelper.requestPermission(this, REQUEST_ACCESS_COARSE_LOCATION, ACCESS_COARSE_LOCATION);
            return;
        }

        RigDeviceRequest req = new RigDeviceRequest(serviceUUIDs, scanSeconds);
        req.setObserver(this);
        mRigDiscoveryManager.startDiscoverDevices(req);

        // We send empty result to signify we have started
        PluginResult result = new PluginResult(PluginResult.Status.NO_RESULT);
        result.setKeepCallback(true);
        callbackContext.sendPluginResult(result);

    }

    private void listKnownDevices(CallbackContext callbackContext) {

        JSONArray json = new JSONArray();

        // do we care about consistent order? will peripherals.values() be in order?
        for (RigAvailableDeviceData entry : mRigDiscoveryManager.getDiscoveredDevices()) {
            json.put(this.asJSONObject(entry));
        }

        PluginResult result = new PluginResult(PluginResult.Status.OK, json);
        callbackContext.sendPluginResult(result);
    }


    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {

        if (requestCode == REQUEST_ENABLE_BLUETOOTH) {

            if (resultCode == Activity.RESULT_OK) {
                LOG.d(TAG, "User enabled Bluetooth");
                if (enableBluetoothCallback != null) {
                    enableBluetoothCallback.success();
                }
            } else {
                LOG.d(TAG, "User did *NOT* enable Bluetooth");
                if (enableBluetoothCallback != null) {
                    enableBluetoothCallback.error("User did not enable Bluetooth");
                }
            }

            enableBluetoothCallback = null;
        }
    }

    /* @Override */
    public void onRequestPermissionResult(int requestCode, String[] permissions,
                                          int[] grantResults) /* throws JSONException */ {
        for(int result:grantResults) {
            if(result == PackageManager.PERMISSION_DENIED)
            {
                LOG.d(TAG, "User *rejected* Coarse Location Access");
                this.permissionCallback.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, PERMISSION_DENIED_ERROR));
                return;
            }
        }

        switch(requestCode) {
            case REQUEST_ACCESS_COARSE_LOCATION:
                LOG.d(TAG, "User granted Coarse Location Access");
                scan(permissionCallback, serviceUUIDs, scanSeconds);
                this.permissionCallback = null;
                this.serviceUUIDs = null;
                this.scanSeconds = -1;
                break;
        }
    }

    private UUID uuidFromString(String uuid) {
        return UUIDHelper.uuidFromString(uuid);
    }

    /**
     * Reset the BLE scanning options
     */
    private void resetScanOptions() {
        this.reportDuplicates = false;
    }

    /// RIGABLUE

    private String generateHashKey(String macAddress, BluetoothGattCharacteristic characteristic) {
        UUID serviceUUID = characteristic.getService().getUuid();
        return macAddress + "|" + String.valueOf(serviceUUID) + "|" + characteristic.getUuid() + "|" + characteristic.getInstanceId();
    }

    // JSON serialization
    static JSONObject byteArrayToJSON(byte[] bytes) throws JSONException {
        JSONObject object = new JSONObject();
        object.put("CDVType", "ArrayBuffer");
        object.put("data", Base64.encodeToString(bytes, Base64.NO_WRAP));
        return object;
    }

    private JSONObject asJSONObject(String errorMessage, String macAddress, String name)  {

        JSONObject json = new JSONObject();

        try {
            json.put("name", name);
            json.put("id", macAddress); // mac address
            json.put("errorMessage", errorMessage);
        } catch (JSONException e) { // this shouldn't happen
            e.printStackTrace();
        }

        return json;
    }

    private JSONObject asJSONObject(RigLeBaseDevice device) {

        JSONObject json = this.asJSONObject(device.getAvailableDeviceData());

        try {
            JSONArray servicesArray = new JSONArray();
            JSONArray characteristicsArray = new JSONArray();
            json.put("services", servicesArray);
            json.put("characteristics", characteristicsArray);

            for (BluetoothGattService service : device.getServiceList()) {
                servicesArray.put(UUIDHelper.uuidToString(service.getUuid()));

                for (BluetoothGattCharacteristic characteristic : service.getCharacteristics()) {
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
        } catch (JSONException e) { // TODO better error handling
            e.printStackTrace();
        }

        return json;
    }

    private JSONObject asJSONObject(RigAvailableDeviceData device) {

        JSONObject json = new JSONObject();

        try {
            json.put("name", device.getUncachedName());
            json.put("id", device.getBluetoothDevice().getAddress()); // mac address
            json.put("advertising", byteArrayToJSON(device.getScanRecord()));
            json.put("rssi", device.getRssi());
        } catch (JSONException e) { // this shouldn't happen
            e.printStackTrace();
        }

        return json;
    }

    // Discovery manager
    @Override
    public void didDiscoverDevice(RigAvailableDeviceData device) {
        availableDevices.put(device.toString(), device);
        if (discoverCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, this.asJSONObject(device));
            result.setKeepCallback(true);
            discoverCallback.sendPluginResult(result);
        }
    }

    @Override
    public void discoveryDidTimeout() {}

    @Override
    public void bluetoothPowerStateChanged(boolean enabled) {
        String val = "off";
        if (enabled) {
            val = "on";
        }
        if (this.stateCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, val);
            result.setKeepCallback(true);
            this.stateCallback.sendPluginResult(result);
        }
    }

    @Override
    public void bluetoothDoesNotSupported() {}

    // Connection manager
    @Override
    public void didConnectDevice(RigLeBaseDevice device) {

        devices.put(device.getAddress(), device);
        CallbackContext disconnectCallback = disconnectCallbacks.get(device.getAddress());

        if (disconnectCallback != null) {
            disconnectCallback.error(this.asJSONObject("Peripheral connected while trying to connect", device.getAddress(), device.getName()));
        }
    }

    @Override
    public void didDisconnectDevice(BluetoothDevice device) {
        if(devices.containsKey(device.getAddress())) {
            devices.remove(device.getAddress());
        }

        CallbackContext disconnectCallback = disconnectCallbacks.get(device.getAddress());
        if (disconnectCallback != null) {
            disconnectCallback.success();
        }

        CallbackContext connectCallback = connectCallbacks.get(device.getAddress());
        if (connectCallback != null) {
            connectCallback.error(this.asJSONObject("Peripheral Disconnected", device.getAddress(), device.getName()));
        }
    }

    @Override
    public void deviceConnectionDidFail(RigAvailableDeviceData device) {
        if(devices.containsKey(device.getAddress())) {
            devices.remove(device.getAddress());
        }
        CallbackContext connectCallback = connectCallbacks.get(device.getAddress());
        if (connectCallback != null) {
            LOG.e(TAG, "Connection failed. status");
            connectCallback.error(this.asJSONObject("Service discovery failed", device.getAddress(), device.getUncachedName()));
        }
    }

    @Override
    public void deviceConnectionDidTimeout(RigAvailableDeviceData device) {

        CallbackContext connectCallback = connectCallbacks.get(device.getAddress());
        if (connectCallback != null) {
            LOG.e(TAG, "Connection failed. status");
            connectCallback.error(this.asJSONObject("Connection timeout", device.getAddress(), device.getUncachedName()));
        }
    }

    // Device manager
    @Override
    public void didUpdateValue(RigLeBaseDevice device, BluetoothGattCharacteristic characteristic) {
        // On read AND on notification
        CallbackContext readCallback = readCallbacks.get(device.getAddress());

        if (readCallback != null) {
            readCallback.success(characteristic.getValue());
            readCallbacks.remove(device.getAddress());
        }

        CallbackContext notifyCallback = notifyCallbacks.get(generateHashKey(device.getAddress(), characteristic));

        if (notifyCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, characteristic.getValue());
            result.setKeepCallback(true);
            notifyCallback.sendPluginResult(result);
        }
    };

    @Override
    public void didUpdateNotifyState(RigLeBaseDevice device, BluetoothGattCharacteristic characteristic) {};

    @Override
    public void didWriteValue(RigLeBaseDevice device, BluetoothGattCharacteristic characteristic) {
        CallbackContext writeCallback = writeCallbacks.get(generateHashKey(device.getAddress(), characteristic));
        if (writeCallback != null) {
            writeCallback.success();
            writeCallbacks.remove(generateHashKey(device.getAddress(), characteristic));
        }
    };

    @Override
    public void didReadRSSI(RigLeBaseDevice device, int RSSI) {
        CallbackContext readRSSICallback = readRSSICallbacks.get(device.getAddress());

        if (readRSSICallback != null) {
            readRSSICallback.success(RSSI);
            readRSSICallbacks.remove(device.getAddress());
        }
    };

    @Override
    public void discoveryDidComplete(RigLeBaseDevice device) {
        CallbackContext connectCallback = connectCallbacks.get(device.getAddress());
        if (connectCallback != null) {
            PluginResult result = new PluginResult(PluginResult.Status.OK, this.asJSONObject(device));
            result.setKeepCallback(true);
            connectCallback.sendPluginResult(result);
        }
    };

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
            firmwareCallback.success();
            firmwareCallback = null;
        }
    }

    @Override
    public void updateFailed(final RigDfuError error) {
        LOG.d(TAG, "Firmware updated failed ( " + error.getErrorMessage() + " )");
        if (firmwareCallback != null) {
            firmwareCallback.error("Update failed:" + error.getErrorMessage());
            firmwareCallback = null;
        }
    }
}
