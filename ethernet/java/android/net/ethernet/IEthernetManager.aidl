/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.ethernet;

import android.net.ethernet.EthernetInfo;
import android.net.ethernet.EthernetConfiguration;
import android.net.DhcpInfo;

import android.os.Messenger;
import android.os.WorkSource;

/**
 * Interface that allows controlling and querying Ethernet connectivity.
 *
 * {@hide}
 */
interface IEthernetManager
{
    List<EthernetConfiguration> getConfiguredNetworks();

    int addOrUpdateNetwork(in EthernetConfiguration config);

    boolean removeNetwork(int netId);

    boolean enableNetwork(int netId, boolean disableOthers);

    boolean disableNetwork(int netId);

    boolean disconnect();

    boolean reconnect();

    EthernetInfo getConnectionInfo();

    boolean setEthernetEnabled(boolean enabled);

    int getEthernetState();

    boolean isEthernetEnabled();

    boolean saveConfiguration();

    DhcpInfo getDhcpInfo();

    boolean acquireEthernetLock(IBinder lock, int lockType, String tag, in WorkSource ws);

    void updateEthernetLockWorkSource(IBinder lock, in WorkSource ws);

    boolean releaseEthernetLock(IBinder lock);

    boolean initializeMulticastFiltering();

    boolean isMulticastEnabled();

    void acquireMulticastLock(IBinder binder, String tag);

    void releaseMulticastLock();

    boolean startEthernet();

    boolean stopEthernet();

    Messenger getEthernetServiceMessenger();

    Messenger getEthernetStateMachineMessenger();

    String getConfigFile();

    void captivePortalCheckComplete();
}
