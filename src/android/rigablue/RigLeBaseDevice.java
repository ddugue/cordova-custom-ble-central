package com.rigado.rigablue;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 *  RigLeBaseDevice.java
 *
 *  @copyright (c) Rigado, Inc. All rights reserved.
 *
 *  Source code licensed under BMD-200 Software License Agreement.
 *  You should have received a copy with purchase of BMD-200 product.
 *  If not, contact info@rigado.com for a copy.
 */

/**
 * This class provides and object representation of a Bluetooth device with all of its available
 * services and characteristics.
 *
 * @author Eric Stutzenberger
 * @version 1.0
 */
public class RigLeBaseDevice implements IRigCoreBluetoothDeviceObserver {

    /**
     * The list of services available on this device.
     */
    private List<BluetoothGattService> mBluetoothGattServices;

    /**
     * The low level Bluetooth device api object
     */
    private BluetoothDevice mBluetoothDevice;

    /**
     * The local name of the device provided by GAP.
     */
    private String mName;

    /**
     * The observer object assigned to this device.  This object will receive updates regarding
     * state changes and notifications.
     */
    private IRigLeBaseDeviceObserver mObserver;

    private IRigLeDescriptorObserver mDescriptorObserver;

    /**
     * The scan response data that was present in the RigAvailableDevice data.
     */
    private RigAvailableDeviceData mScanRecord;

    /**
     * A value indicating if full discovery has been completed for this device object.  This
     * includes discovering all characteristics for all services and reading all of their values
     * if the read property is present.
     */
    private boolean mIsDiscoveryComplete;

    /**
     * A value indicating if full descriptor discovery has been completed for this device object.
     * This includes reading all descriptors for all characteristics in each available service.
     *
     */
    private boolean mIsDescriptorDiscoveryComplete;

    /**
     * Local index value for managing device discovery.
     */
    private int mServiceIndex;

    /**
     * Local index value for managing device discovery.
     */
    private int mCharacteristicIndex;

    /**
     * Local index value for managing descriptor discovery.
     */
    private int mDescriptorIndex;

    /**
     * Creates a new base device object.
     *
     *  @param deviceName The local name of the device parsed from the advertising
     *                    data {@code scanRecord} or set using {@link BluetoothDevice#getName()}.
     *                    See {@link RigAvailableDeviceData#parseNameFromScanRecord(byte[],
     *                    BluetoothDevice)}
     *  @param bluetoothDevice The Bluetooth device for this base device
     *  @param serviceList The list of services available for the Bluetooth device
     *  @param scanRecord The advertising data for this device
     */
    public RigLeBaseDevice(String deviceName,
                           BluetoothDevice bluetoothDevice,
                           List<BluetoothGattService> serviceList,
                           RigAvailableDeviceData scanRecord) {
        mBluetoothDevice = bluetoothDevice;
        mName = deviceName;
        mBluetoothGattServices = new ArrayList<BluetoothGattService>();
        if (serviceList != null) {
            UUID mGapUuid = UUID.fromString("00001800-0000-1000-8000-00805f9b34fb");
            UUID mGattUuid = UUID.fromString("00001801-0000-1000-8000-00805f9b34fb");
            for(BluetoothGattService service : serviceList) {
                if(service.getUuid().equals(mGapUuid) ||
                        service.getUuid().equals(mGattUuid)) {
                    //Ignore GAP and GATT services for now
                    continue;
                }
                mBluetoothGattServices.add(service);
            }
        }
        mScanRecord = scanRecord;
        mIsDiscoveryComplete = false;
    }

    /**
     * Creates a new base device object using {@link BluetoothDevice#getName()}
     *
     * @param bluetoothDevice The Bluetooth device for this base device
     * @param serviceList The list of services available for the Bluetooth device
     * @param scanRecord The advertising data for this device
     */
    public RigLeBaseDevice(BluetoothDevice bluetoothDevice,
                           List<BluetoothGattService> serviceList,
                           RigAvailableDeviceData scanRecord) {
        this(bluetoothDevice.getName(), bluetoothDevice, serviceList, scanRecord);
    }

    /**
     * Constructs a string representation for this device
     *
     * @return Returns the device name and address as one string
     */
    @Override
    public String toString() {
        return (mName + ":" + mBluetoothDevice.getAddress());
    }


    private BluetoothGattService getService(UUID serviceUUID) {
        for(BluetoothGattService service : mBluetoothGattServices) {
            if(service.getUuid().equals(serviceUUID)) {
                return service;
            }
        }
        return null;
    }

    /**
     * Characteristic finding
     **/
    // Some peripherals re-use UUIDs for multiple characteristics so we need to check the properties
    // and UUID of all characteristics instead of using service.getCharacteristic(characteristicUUID)
    public BluetoothGattCharacteristic findCharacteristic(UUID serviceUUID, UUID characteristicUUID, int charType) {
        BluetoothGattCharacteristic characteristic = null;

        BluetoothGattService service = getService(serviceUUID);

        if (service == null) {
            return null;
        }
        List<BluetoothGattCharacteristic> characteristics = service.getCharacteristics();
        for (BluetoothGattCharacteristic c : characteristics) {
            if ((c.getProperties() & charType) != 0 && characteristicUUID.equals(c.getUuid())) {
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

    public String getAddress() {
        return mBluetoothDevice.getAddress();
    }

    /**
     * Compares two RigLeBaseDevice objects and determines if they are the same device
     *
     * @param o The RigLeBaseDevice object for comparison
     * @return Returns true if the devices have the same address; false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if(o instanceof RigLeBaseDevice) {
            RigLeBaseDevice device = (RigLeBaseDevice)o;
            return mBluetoothDevice.equals(device.getBluetoothDevice());
        }
        return false;
    }

    /**
     * @return The list of services available on this device.
     */
    public List<BluetoothGattService> getServiceList() {
        return mBluetoothGattServices;
    }

    /**
     * @return Returns the local device name for this device.
     */
    public String getName() {
        return mName;
    }

    /**
     * @return Returns the Bluetooth MAC address for this device
     */
    public BluetoothDevice getBluetoothDevice() {
        return mBluetoothDevice;
    }

    /**
     * @return Returns the scan record data of the advertisement
     */
    public byte[] getScanRecord() { return mScanRecord.getScanRecord(); }
    public RigAvailableDeviceData getAvailableDeviceData() { return mScanRecord; }

    /**
     * @return Returns the state of device discovery
     */
    public boolean isDiscoveryComplete() {
        return mIsDiscoveryComplete;
    }

    /**
     * This function can be used to bypass full device discovery if not needed.
     */
    public void setDiscoveryComplete() {
        mIsDiscoveryComplete = true;
    }

    /**
     * This function starts the full discovery process.  This process will discovery all
     * characteristics of all services and issue read requests for all characteristics which
     * have the read property.
     */
    public void runDiscovery() {
        RigLog.d("__runDiscovery__");
        mServiceIndex = 0;
        mCharacteristicIndex = 0;

        didUpdateValue(null, null);
    }

    /**
     * Sets the observer for this device.
     *
     * @param observer The observer object
     */
    public void setObserver(IRigLeBaseDeviceObserver observer) {
        mObserver = observer;
    }

    /**
     * Sets the descriptor observer for this device.
     *
     * @param observer The observer object
     */
    public void setDescriptorObserver(IRigLeDescriptorObserver observer) {
        mDescriptorObserver = observer;
    }

    /**
     * Reads the value of the characteristic
     *
     * @param descriptor The descriptor to read
     * @return Return false if the descriptor is invalid
     */
    public boolean readDescriptor(BluetoothGattDescriptor descriptor) {
        RigLog.d("RigLeBaseDevice.readDescriptor");
        if(descriptor == null) {
            RigLog.w("Descriptor was null! Ignoring read request.");
            return false;
        }

        RigCoreBluetooth.getInstance().readDescriptor(mBluetoothDevice, descriptor);
        return true;
    }

    /**
     * Reads the value of the characteristic
     *
     * @param characteristic The characteristic to read
     * @return If the read property is not set, false is returned; true otherwise
     */
    public boolean readCharacteristic(BluetoothGattCharacteristic characteristic) {
        RigLog.d("RigLeBaseDevice.readCharacteristic");
        if((characteristic.getProperties() & BluetoothGattCharacteristic.PROPERTY_READ) == 0) {
            RigLog.e("Read property not set -- ignoring read request! " + characteristic.getUuid());
            return false;
        }
        RigCoreBluetooth.getInstance().readCharacteristic(mBluetoothDevice, characteristic);
        return true;
    }

    /**
     * Reads the RSSI of the device
     *
     * @return If the read property is not set, false is returned; true otherwise
     */
    public boolean readRSSI() {
        RigLog.d("RigLeBaseDevice.readRSSI");
        RigCoreBluetooth.getInstance().readRSSI(mBluetoothDevice);
        return true;
    }
    /**
     * Writes value to the characteristic
     *
     * @param characteristic The characteristic to write
     * @param value The value to write to the characteristic
     * @return If the write proptery is not set, false is returned; true otherwise.
     */
    public boolean writeCharacteristic(BluetoothGattCharacteristic characteristic, byte [] value) {
        RigLog.d("RigLeBaseDevice.writeCharacteristic");
        int props = characteristic.getProperties();
        if(((props & BluetoothGattCharacteristic.PROPERTY_WRITE) == 0) &&
                ((props & BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE) == 0)) {
            RigLog.e("Write properties not set -- ignoring write request!" + characteristic.getUuid());
            return false;
        }
        RigCoreBluetooth.getInstance().writeCharacteristic(mBluetoothDevice, characteristic, value);
        return true;
    }

    /**
     * Enable or disable the notification state for the characteristic
     *
     * @param characteristic The characteristic to adjust
     * @param enabled The notification state to set
     * @return If the notify property is not set, false is returned; true otherwise
     */
    public boolean setCharacteristicNotification(BluetoothGattCharacteristic characteristic, boolean enabled) {
        RigLog.d("RigLeBaseDevice.setCharacteristicNotification");
        if((characteristic.getProperties() & BluetoothGattCharacteristic.PROPERTY_NOTIFY) == 0) {
            RigLog.e("Notify property not set -- ignoring notify request!" + characteristic.getUuid());
            return false;
        }
        RigCoreBluetooth.getInstance().setCharacteristicNotification(mBluetoothDevice, characteristic, enabled);
        return true;
    }

    /**
     * This callback is received from the low level Bluetooth API when the state of a characteristic
     * notification has been successfully updated.
     *
     * @param btDevice The device for which the characteristic state changed
     * @param characteristic The characteristic which changed notification state
     */
    @Override
    public void didUpdateNotificationState(BluetoothDevice btDevice, BluetoothGattCharacteristic characteristic) {
        if(mObserver != null) {
            mObserver.didUpdateNotifyState(this, characteristic);
        }
    }

    /**
     * This callback is received from the low level Bluetooth API when the value of a characteristic
     * has changed.  This happens either due to an asynchronous notification or due to a read
     * request.
     *
     * @param btDevice The device for which the characteristic value changed
     * @param characteristic The characteristic which had a value change
     */
    @Override
    public void didUpdateValue(BluetoothDevice btDevice, BluetoothGattCharacteristic characteristic) {
        if(mIsDiscoveryComplete) {
            if(mObserver != null) {
                mObserver.didUpdateValue(this, characteristic);
            }
        } else {
            if(characteristic != null) {
                RigLog.i("Read Value during discovery for " + characteristic.getUuid() + ": " + Arrays.toString(characteristic.getValue()));
            }

            /* Find next readable characteristic - This is a tricky bit of code here.  Because
            * a characteristic may not be readable, we need to skip over it.  However, if we
            * do find a characteristic that we can read, the read is issued and the function exits.
            * This is because we need to wait for the BT Stack to inform us the read has
            * completed prior to starting another read. The important point here is that across
            * calls to this function, the characteristic and service indexes are not reset.  This
            * keeps the code from starting the search over every time since the search is actually
            * just being paused while a read completes. */
            while(mServiceIndex < mBluetoothGattServices.size()) {
                BluetoothGattService service = mBluetoothGattServices.get(mServiceIndex);
                if (service == null) {
                    return;
                }
                while (mCharacteristicIndex < service.getCharacteristics().size()) {
                    BluetoothGattCharacteristic c = service.getCharacteristics().get(mCharacteristicIndex);
                    mCharacteristicIndex++;
                    RigLog.d("Characteristic: " + mCharacteristicIndex);
                    if (readCharacteristic(c)) {
                        return;
                    }
                }
                mCharacteristicIndex = 0;
                RigLog.d("Characteristic: " + mCharacteristicIndex);
                mServiceIndex++;
                RigLog.d("Service: " + mServiceIndex);
            }

            /* At this point, all services and characteristics have been exhausted. */
            mIsDiscoveryComplete = true;
            if(mObserver != null) {
                RigLog.d("Discovery did complete");
                mObserver.discoveryDidComplete(this);
            } else {
                RigLog.e("Discovery did complete but the observer was null!");
            }
        }
    }

    /**
     * This callback is received anytime a write to a characteristic has completed.  This will
     * be called even if a write is performed using WriteWithoutResponse.
     * @param btDevice The device for which the characteristic value write finished
     * @param characteristic The characteristic which had its value written
     */
    @Override
    public void didWriteValue(BluetoothDevice btDevice, BluetoothGattCharacteristic characteristic) {
        if(mObserver != null) {
            mObserver.didWriteValue(this, characteristic);
        }
    }

    /**
     * This callback is received anytime a write to a characteristic has completed.  This will
     * be called even if a write is performed using WriteWithoutResponse.
     * @param btDevice The device for which the characteristic value write finished
     * @param characteristic The characteristic which had its value written
     */
    @Override
    public void didReadRSSI(BluetoothDevice btDevice, int RSSI) {
        if(mObserver != null) {
            mObserver.didReadRSSI(this, RSSI);
        }
    }

    /**
     * This callback is received from the low level Bluetooth API due to a read request
     * on a BluetoothGattDescriptor.
     *
     * @param btDevice The device for which the descriptor read was requested
     * @param descriptor The descriptor which was read
     */
    @Override
    public void didReadDescriptor(BluetoothDevice btDevice, BluetoothGattDescriptor descriptor) {
        if (mDescriptorObserver != null) {
            mDescriptorObserver.didReadDescriptor(this, descriptor);

        }
    }
}
