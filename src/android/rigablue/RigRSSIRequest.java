package com.rigado.rigablue;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;

/**
 *  RigReadRequest.java
 *
 *  @copyright (c) Rigado, Inc. All rights reserved.
 *
 *  Source code licensed under BMD-200 Software License Agreement.
 *  You should have received a copy with purchase of BMD-200 product.
 *  If not, contact info@rigado.com for a copy.
 */

/**
 * This class provides a Data Request implementation for request a read of a characteristics value.
 * It is used by RigCoreBluetooth to manage synchronous data requests to the low level
 * Bluetooth APIs.
 *
 * @author Eric Stutzenberger
 * @version 1.0
 */
public class RigRSSIRequest implements IRigDataRequest {

    private BluetoothDevice mDevice;

    public RigReadRequest(BluetoothDevice device) {
        mDevice = device;
    }

    @Override
    public void post(RigService service) {
        service.readCharacteristic(mDevice.getAddress());
    }
}
