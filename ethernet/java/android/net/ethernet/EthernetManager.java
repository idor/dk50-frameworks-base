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

import android.annotation.SdkConstant;
import android.annotation.SdkConstant.SdkConstantType;
import android.content.Context;
import android.net.DhcpInfo;
import android.os.Binder;
import android.os.IBinder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import android.os.WorkSource;
import android.os.Messenger;
import android.util.Log;
import android.util.SparseArray;

import java.util.concurrent.CountDownLatch;

import com.android.internal.util.AsyncChannel;
import com.android.internal.util.Protocol;

import java.util.List;

/**
 * This class provides the primary API for managing all aspects of Ethernet
 * connectivity. Get an instance of this class by calling
 * {@link android.content.Context#getSystemService(String) Context.getSystemService(Context.ETHERNET_SERVICE)}.

 * It deals with several categories of items:
 * <ul>
 * <li>Ethernet connectivity can be established or torn down, and dynamic
 * information about the state of the network can be queried.</li>
 * <li>It defines the names of various Intent actions that are broadcast
 * upon any sort of change in Ethernet state.
 * </ul>
 * This is the API to use when performing Ethernet specific operations. To
 * perform operations that pertain to network connectivity at an abstract
 * level, use {@link android.net.ConnectivityManager}.
 */
public class EthernetManager {

    private static final String TAG = "EthernetManager";

    /**
     * Broadcast intent action indicating that Ethernet has been enabled, disabled,
     * enabling, disabling, or unknown. One extra provides this state as an int.
     * Another extra provides the previous state, if available.
     *
     * @see #EXTRA_ETHERNET_STATE
     * @see #EXTRA_PREVIOUS_ETHERNET_STATE
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String ETHERNET_STATE_CHANGED_ACTION =
        "android.net.ethernet.ETHERNET_STATE_CHANGED";

    /**
     * The lookup key for an int that indicates whether Ethernet is enabled,
     * disabled, enabling, disabling, or unknown.  Retrieve it with
     * {@link android.content.Intent#getIntExtra(String,int)}.
     *
     * @see #ETHERNET_STATE_DISABLED
     * @see #ETHERNET_STATE_DISABLING
     * @see #ETHERNET_STATE_ENABLED
     * @see #ETHERNET_STATE_ENABLING
     * @see #ETHERNET_STATE_UNKNOWN
     */
    public static final String EXTRA_ETHERNET_STATE = "ethernet_state";

    /**
     * The previous Ethernet state.
     *
     * @see #EXTRA_ETHERNET_STATE
     */
    public static final String EXTRA_PREVIOUS_ETHERNET_STATE = "previous_ethernet_state";

    /**
     * Ethernet is currently being disabled. The state will change to {@link #ETHERNET_STATE_DISABLED} if
     * it finishes successfully.
     *
     * @see #ETHERNET_STATE_CHANGED_ACTION
     * @see #getEthernetState()
     */
    public static final int ETHERNET_STATE_DISABLING = 0;

    /**
     * Ethernet is disabled.
     *
     * @see #ETHERNET_STATE_CHANGED_ACTION
     * @see #getEthernetState()
     */
    public static final int ETHERNET_STATE_DISABLED = 1;

    /**
     * Ethernet is currently being enabled. The state will change to {@link #ETHERNET_STATE_ENABLED} if
     * it finishes successfully.
     *
     * @see #ETHERNET_STATE_CHANGED_ACTION
     * @see #getEthernetState()
     */
    public static final int ETHERNET_STATE_ENABLING = 2;

    /**
     * Ethernet is enabled.
     *
     * @see #ETHERNET_STATE_CHANGED_ACTION
     * @see #getEthernetState()
     */
    public static final int ETHERNET_STATE_ENABLED = 3;

    /**
     * Ethernet is in an unknown state. This state will occur when an error happens while enabling
     * or disabling.
     *
     * @see #ETHERNET_STATE_CHANGED_ACTION
     * @see #getEthernetState()
     */
    public static final int ETHERNET_STATE_UNKNOWN = 4;

    /**
     * Broadcast intent action indicating that the state of Ethernet connectivity
     * has changed. One extra provides the new state
     * in the form of a {@link android.net.NetworkInfo} object. If the new
     * state is CONNECTED, additional extras may provide the EthernetInfo of the link.
     * as a {@code String}.
     * @see #EXTRA_NETWORK_INFO
     * @see #EXTRA_ETHERNET_INFO
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String NETWORK_STATE_CHANGED_ACTION = "android.net.ethernet.STATE_CHANGE";

    /**
     * The lookup key for a {@link android.net.NetworkInfo} object associated
     * with the Ethernet network. Retrieve with
     * {@link android.content.Intent#getParcelableExtra(String)}.
     */
    public static final String EXTRA_NETWORK_INFO = "networkInfo";

    /**
     * The lookup key for a {@link android.net.ethernet.EthernetInfo} object giving the
     * information about the link to which we are connected. Only present
     * when the new state is CONNECTED.  Retrieve with
     * {@link android.content.Intent#getParcelableExtra(String)}.
     */
    public static final String EXTRA_ETHERNET_INFO = "ethernetInfo";

    /**
     * Broadcast intent action indicating that the configured networks changed.
     * This can be as a result of adding/updating/deleting a network. If
     * {@link #EXTRA_MULTIPLE_NETWORKS_CHANGED} is set to true the new configuration
     * can be retreived with the {@link #EXTRA_ETHERNET_CONFIGURATION} extra. If multiple
     * Ethernet configurations changed, {@link #EXTRA_ETHERNET_CONFIGURATION} will not be present.
     * @hide
     */
    public static final String CONFIGURED_NETWORKS_CHANGED_ACTION =
        "android.net.ethernet.CONFIGURED_NETWORKS_CHANGE";

    /**
     * The lookup key for a (@link android.net.ethernet.EthernetConfiguration} object representing
     * the changed Ethernet configuration when the {@link #CONFIGURED_NETWORKS_CHANGED_ACTION}
     * broadcast is sent.
     * @hide
     */
    public static final String EXTRA_ETHERNET_CONFIGURATION = "ethernetConfiguration";

    /**
     * Multiple network configurations have changed.
     * @see #CONFIGURED_NETWORKS_CHANGED_ACTION
     *
     * @hide
     */
    public static final String EXTRA_MULTIPLE_NETWORKS_CHANGED = "multipleChanges";

    /**
     * The lookup key for an integer indicating the reason an Ethernet network configuration
     * has changed. Only present if {@link #EXTRA_MULTIPLE_NETWORKS_CHANGED} is {@code false}
     * @see #CONFIGURED_NETWORKS_CHANGED_ACTION
     * @hide
     */
    public static final String EXTRA_CHANGE_REASON = "changeReason";

    /**
     * The configuration is new and was added.
     * @hide
     */
    public static final int CHANGE_REASON_ADDED = 0;

    /**
     * The configuration was removed and is no longer present in the system's list of
     * configured networks.
     * @hide
     */
    public static final int CHANGE_REASON_REMOVED = 1;

    /**
     * The configuration has changed as a result of explicit action or because the system
     * took an automated action such as disabling a malfunctioning configuration.
     * @hide
     */
    public static final int CHANGE_REASON_CONFIG_CHANGE = 2;

    /**
     * Broadcast intent action indicating that the link configuration
     * changed on ethernet.
     * @hide
     */
    public static final String LINK_CONFIGURATION_CHANGED_ACTION =
        "android.net.ethernet.LINK_CONFIGURATION_CHANGED";

    /**
     * The lookup key for a {@link android.net.LinkProperties} object
     * associated with the Ethernet network. Retrieve with
     * {@link android.content.Intent#getParcelableExtra(String)}.
     * @hide
     */
    public static final String EXTRA_LINK_PROPERTIES = "linkProperties";

    /**
     * The lookup key for a {@link android.net.LinkCapabilities} object
     * associated with the Ethernet network. Retrieve with
     * {@link android.content.Intent#getParcelableExtra(String)}.
     * @hide
     */
    public static final String EXTRA_LINK_CAPABILITIES = "linkCapabilities";

    /**
     * The network IDs of the configured networks could have changed.
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String NETWORK_IDS_CHANGED_ACTION = "android.net.ethernet.NETWORK_IDS_CHANGED";

    /**
     * Activity Action: Pick an Ethernet network to connect to.
     * <p>Input: Nothing.
     * <p>Output: Nothing.
     */
    @SdkConstant(SdkConstantType.ACTIVITY_INTENT_ACTION)
    public static final String ACTION_PICK_ETHERNET_NETWORK = "android.net.ethernet.PICK_ETHERNET_NETWORK";

    /**
     * In this Ethernet lock mode, Ethernet will be kept active,
     * and will behave normally, i.e., it will attempt to automatically
     * establish a connection to a remembered link.
     */
    public static final int ETHERNET_MODE_FULL = 1;

    /**
     * In this Ethernet lock mode, Ethernet will be kept active,
     * but will only operated at Fast Ethernet (10/100) speed
     * for energy saving.
     */
    public static final int ETHERNET_MODE_RESTRICTED_FE = 2;

    /**
     * In this Ethernet lock mode, Ethernet will be kept active as in mode
     * {@link #ETHERNET_MODE_FULL} but it operates at high performance
     * Gigabit (if supported by the hardware) with minimum packet loss and
     * low packet latency even when the device screen is off.
     * This mode will consume more power and hence should be used only when
     * there is a need for such an active connection.
     * <p>
     * An example use case is when a voice connection needs to be
     * kept active even after the device screen goes off. Holding the
     * regular {@link #ETHERNET_MODE_FULL} lock will keep the ethernet
     * connection active, but the connection can be lossy.
     * Holding a {@link #ETHERNET_MODE_FULL_HIGH_PERF} lock for the
     * duration of the voice call will improve the call quality.
     * <p>
     * When there is no support from the hardware, this lock mode
     * will have the same behavior as {@link #ETHERNET_MODE_FULL}
     */
    public static final int ETHERNET_MODE_FULL_HIGH_PERF = 3;

    /** List of asyncronous notifications
     * @hide
     */
    public static final int DATA_ACTIVITY_NOTIFICATION = 1;

    //Lowest bit indicates data reception and the second lowest
    //bit indicates data transmitted
    /** @hide */
    public static final int DATA_ACTIVITY_NONE         = 0x00;
    /** @hide */
    public static final int DATA_ACTIVITY_IN           = 0x01;
    /** @hide */
    public static final int DATA_ACTIVITY_OUT          = 0x02;
    /** @hide */
    public static final int DATA_ACTIVITY_INOUT        = 0x03;

    /* Maximum number of active locks we allow.
     * This limit was added to prevent apps from creating a ridiculous number
     * of locks and crashing the system by overflowing the global ref table.
     */
    private static final int MAX_ACTIVE_LOCKS = 50;

    /* Number of currently active EthernetLocks and MulticastLocks */
    private int mActiveLockCount;

    private Context mContext;
    IEthernetManager mService;

    private static final int INVALID_KEY = 0;
    private int mListenerKey = 1;
    private final SparseArray mListenerMap = new SparseArray();
    private final Object mListenerMapLock = new Object();

    private AsyncChannel mAsyncChannel = new AsyncChannel();
    private ServiceHandler mHandler;
    private Messenger mEthernetServiceMessenger;
    private final CountDownLatch mConnected = new CountDownLatch(1);

    /**
     * Create a new EthernetManager instance.
     * Applications will almost always want to use
     * {@link android.content.Context#getSystemService Context.getSystemService()} to retrieve
     * the standard {@link android.content.Context#ETHERNET_SERVICE Context.ETHERNET_SERVICE}.
     * @param context the application context
     * @param service the Binder interface
     * @hide - hide this because it takes in a parameter of type IEthernetManager, which
     * is a system private class.
     */
    public EthernetManager(Context context, IEthernetManager service) {
        mContext = context;
        mService = service;
        init();
    }

    /**
     * Return a list of all the networks configured.
     * Not all fields of EthernetConfiguration are returned. Only the following
     * fields are filled in:
     * <ul>
     * <li>networkId</li>
     * <li>networkName</li>
     * <li>priority</li>
     * </ul>
     * @return a list of network configurations in the form of a list
     * of {@link EthernetConfiguration} objects. Upon failure to fetch or
     * when when Ethernet is turned off, it can be null.
     */
    public List<EthernetConfiguration> getConfiguredNetworks() {
        try {
            return mService.getConfiguredNetworks();
        } catch (RemoteException e) {
            return null;
        }
    }

    /**
     * Add a new network description to the set of configured networks.
     * The {@code networkId} field of the supplied configuration object
     * is ignored.
     * <p/>
     * The new network will be marked DISABLED by default. To enable it,
     * called {@link #enableNetwork}.
     *
     * @param config the set of variables that describe the configuration,
     *            contained in a {@link EthernetConfiguration} object.
     * @return the ID of the newly created network description. This is used in
     *         other operations to specified the network to be acted upon.
     *         Returns {@code -1} on failure.
     */
    public int addNetwork(EthernetConfiguration config) {
        if (config == null) {
            return -1;
        }
        config.networkId = -1;
        return addOrUpdateNetwork(config);
    }

    /**
     * Update the network description of an existing configured network.
     *
     * @param config the set of variables that describe the configuration,
     *            contained in a {@link EthernetConfiguration} object. It may
     *            be sparse, so that only the items that are being changed
     *            are non-<code>null</code>. The {@code networkId} field
     *            must be set to the ID of the existing network being updated.
     * @return Returns the {@code networkId} of the supplied
     *         {@code EthernetConfiguration} on success.
     *         <br/>
     *         Returns {@code -1} on failure, including when the {@code networkId}
     *         field of the {@code EthernetConfiguration} does not refer to an
     *         existing network.
     */
    public int updateNetwork(EthernetConfiguration config) {
        if (config == null || config.networkId < 0) {
            return -1;
        }
        return addOrUpdateNetwork(config);
    }

    /**
     * Internal method for doing the RPC that creates a new network description
     * or updates an existing one.
     *
     * @param config The possibly sparse object containing the variables that
     *         are to set or updated in the network description.
     * @return the ID of the network on success, {@code -1} on failure.
     */
    private int addOrUpdateNetwork(EthernetConfiguration config) {
        try {
            return mService.addOrUpdateNetwork(config);
        } catch (RemoteException e) {
            return -1;
        }
    }

    /**
     * Remove the specified network from the list of configured networks.
     * This may result in the asynchronous delivery of state change
     * events.
     * @param netId the integer that identifies the network configuration
     * to the supplicant
     * @return {@code true} if the operation succeeded
     */
    public boolean removeNetwork(int netId) {
        try {
            return mService.removeNetwork(netId);
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Allow a previously configured network to be connected to. If
     * <code>disableOthers</code> is true, then all other configured
     * networks are disabled, and an attempt to connect to the selected
     * network is initiated. This may result in the asynchronous delivery
     * of state change events.
     * @param netId the ID of the network in the list of configured networks
     * @param disableOthers if true, disable all other networks. The way to
     * select a particular network to connect to is specify {@code true}
     * for this parameter.
     * @return {@code true} if the operation succeeded
     */
    public boolean enableNetwork(int netId, boolean disableOthers) {
        try {
            return mService.enableNetwork(netId, disableOthers);
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Disable a configured network. The specified network will not be
     * a candidate for associating. This may result in the asynchronous
     * delivery of state change events.
     * @param netId the ID of the network as returned by {@link #addNetwork}.
     * @return {@code true} if the operation succeeded
     */
    public boolean disableNetwork(int netId) {
        try {
            return mService.disableNetwork(netId);
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Disconnect from the currently active link. This may result
     * in the asynchronous delivery of state change events.
     * @return {@code true} if the operation succeeded
     */
    public boolean disconnect() {
        try {
            mService.disconnect();
            return true;
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Reconnect to the currently active link, if we are currently
     * disconnected. This may result in the asynchronous delivery of state
     * change events.
     * @return {@code true} if the operation succeeded
     */
    public boolean reconnect() {
        try {
            mService.reconnect();
            return true;
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Return dynamic information about the current Ethernet connection, if any is active.
     * @return the Ethernet information, contained in {@link EthernetInfo}.
     */
    public EthernetInfo getConnectionInfo() {
        try {
            return mService.getConnectionInfo();
        } catch (RemoteException e) {
            return null;
        }
    }

    /**
     * Persist the current list of configured networks.
     * <p>
     * Note: It is possible for this method to change the network IDs of
     * existing networks. You should assume the network IDs can be different
     * after calling this method.
     *
     * @return {@code true} if the operation succeeded
     */
    public boolean saveConfiguration() {
        try {
            return mService.saveConfiguration();
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Return the DHCP-assigned addresses from the last successful DHCP request,
     * if any.
     * @return the DHCP information
     */
    public DhcpInfo getDhcpInfo() {
        try {
            return mService.getDhcpInfo();
        } catch (RemoteException e) {
            return null;
        }
    }

    /**
     * Enable or disable Ethernet.
     * @param enabled {@code true} to enable, {@code false} to disable.
     * @return {@code true} if the operation succeeds (or if the existing state
     *         is the same as the requested state).
     */
    public boolean setEthernetEnabled(boolean enabled) {
        try {
            return mService.setEthernetEnabled(enabled);
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Gets the Ethernet enabled state.
     * @return One of {@link #ETHERNET_STATE_DISABLED},
     *         {@link #ETHERNET_STATE_DISABLING}, {@link #ETHERNET_STATE_ENABLED},
     *         {@link #ETHERNET_STATE_ENABLING}, {@link #ETHERNET_STATE_UNKNOWN}
     * @see #isEthernetEnabled()
     */
    public int getEthernetState() {
        try {
            return mService.getEthernetEnabledState();
        } catch (RemoteException e) {
            return ETHERNET_STATE_UNKNOWN;
        }
    }

    /**
     * Return whether Ethernet is enabled or disabled.
     * @return {@code true} if Ethernet is enabled
     * @see #getEthernetState()
     */
    public boolean isEthernetEnabled() {
        return getEthernetState() == ETHERNET_STATE_ENABLED;
    }

   /**
     * Start the driver and connect to network.
     *
     * This function will over-ride device idle status. For example,
     * even if the device is idle,
     * a start ethernet would mean that ethernet connection is kept active until
     * a stopEthernet() is sent.
     *
     * This API is used by EthernetStateTracker
     *
     * @return {@code true} if the operation succeeds else {@code false}
     * @hide
     */
    public boolean startEthernet() {
        try {
            mService.startEthernet();
            return true;
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Disconnect from a network (if any) and stop the driver.
     *
     * This function will over-ride device idle status.
     * Ethernet stays inactive until a startEthernet() is issued.
     *
     * This API is used by EthernetStateTracker
     *
     * @return {@code true} if the operation succeeds else {@code false}
     * @hide
     */
    public boolean stopEthernet() {
        try {
            mService.stopEthernet();
            return true;
        } catch (RemoteException e) {
            return false;
        }
    }

    /* TODO: deprecate synchronous API and open up the following API */

    private static final int BASE = Protocol.BASE_ETHERNET_MANAGER;

    /* Commands to EthernetService */
    /** @hide */
    public static final int CONNECT_NETWORK                 = BASE + 1;
    /** @hide */
    public static final int CONNECT_NETWORK_FAILED          = BASE + 2;
    /** @hide */
    public static final int CONNECT_NETWORK_SUCCEEDED       = BASE + 3;

    /** @hide */
    public static final int FORGET_NETWORK                  = BASE + 4;
    /** @hide */
    public static final int FORGET_NETWORK_FAILED           = BASE + 5;
    /** @hide */
    public static final int FORGET_NETWORK_SUCCEEDED        = BASE + 6;

    /** @hide */
    public static final int SAVE_NETWORK                    = BASE + 7;
    /** @hide */
    public static final int SAVE_NETWORK_FAILED             = BASE + 8;
    /** @hide */
    public static final int SAVE_NETWORK_SUCCEEDED          = BASE + 9;

    /** @hide */
    public static final int DISABLE_NETWORK                 = BASE + 17;
    /** @hide */
    public static final int DISABLE_NETWORK_FAILED          = BASE + 18;
    /** @hide */
    public static final int DISABLE_NETWORK_SUCCEEDED       = BASE + 19;

    /* For system use only */
    /** @hide */
    public static final int ENABLE_TRAFFIC_STATS_POLL       = BASE + 31;
    /** @hide */
    public static final int TRAFFIC_STATS_POLL              = BASE + 32;


    /**
     * Passed with {@link ActionListener#onFailure}.
     * Indicates that the operation failed due to an internal error.
     * @hide
     */
    public static final int ERROR                       = 0;

    /**
     * Passed with {@link ActionListener#onFailure}.
     * Indicates that the operation is already in progress
     * @hide
     */
    public static final int IN_PROGRESS                 = 1;

    /**
     * Passed with {@link ActionListener#onFailure}.
     * Indicates that the operation failed because the framework is busy and
     * unable to service the request
     * @hide
     */
    public static final int BUSY                        = 2;

    /** Interface for callback invocation on an application action {@hide} */
    public interface ActionListener {
        /** The operation succeeded */
        public void onSuccess();
        /**
         * The operation failed
         * @param reason The reason for failure could be one of
         * {@link #ERROR}, {@link #IN_PROGRESS} or {@link #BUSY}
         */
        public void onFailure(int reason);
    }

    /** Interface for callback invocation on a TX packet count poll action {@hide} */
    public interface TxPacketCountListener {
        /**
         * The operation succeeded
         * @param count TX packet counter
         */
        public void onSuccess(int count);
        /**
         * The operation failed
         * @param reason The reason for failure could be one of
         * {@link #ERROR}, {@link #IN_PROGRESS} or {@link #BUSY}
         */
        public void onFailure(int reason);
    }

    private class ServiceHandler extends Handler {
        ServiceHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message message) {
            Object listener = removeListener(message.arg2);
            switch (message.what) {

		/* ActionListeners grouped together */
                case EthernetManager.CONNECT_NETWORK_FAILED:
                case EthernetManager.FORGET_NETWORK_FAILED:
                case EthernetManager.SAVE_NETWORK_FAILED:
                case EthernetManager.DISABLE_NETWORK_FAILED:
                    if (listener != null) {
                        ((ActionListener) listener).onFailure(message.arg1);
                    }
                    break;

                /* ActionListeners grouped together */
                case EthernetManager.CONNECT_NETWORK_SUCCEEDED:
                case EthernetManager.FORGET_NETWORK_SUCCEEDED:
                case EthernetManager.SAVE_NETWORK_SUCCEEDED:
                case EthernetManager.DISABLE_NETWORK_SUCCEEDED:
                    if (listener != null) {
                        ((ActionListener) listener).onSuccess();
                    }
                    break;

                default:
                    //ignore
                    break;
            }
        }
    }

    private int putListener(Object listener) {
        if (listener == null) return INVALID_KEY;
        int key;
        synchronized (mListenerMapLock) {
            do {
                key = mListenerKey++;
            } while (key == INVALID_KEY);
            mListenerMap.put(key, listener);
        }
        return key;
    }

    private Object removeListener(int key) {
        if (key == INVALID_KEY) return null;
        synchronized (mListenerMapLock) {
            Object listener = mListenerMap.get(key);
            mListenerMap.remove(key);
            return listener;
        }
    }

    private void init() {
        mEthernetServiceMessenger = getEthernetServiceMessenger();
        if (mEthernetServiceMessenger == null) {
            mAsyncChannel = null;
            return;
        }

        HandlerThread t = new HandlerThread("EthernetManager");
        t.start();
        mHandler = new ServiceHandler(t.getLooper());
        mAsyncChannel.connect(mContext, mHandler, mEthernetServiceMessenger);
        try {
            mConnected.await();
        } catch (InterruptedException e) {
            Log.e(TAG, "interrupted wait at init");
        }
    }

    private void validateChannel() {
        if (mAsyncChannel == null) throw new IllegalStateException(
                "No permission to access and change ethernet or a bad initialization");
    }

    /**
     * Connect to a network with the given configuration.
     *
     * For a new network, this function is used instead of a
     * sequence of addNetwork(), enableNetwork(), saveConfiguration() and
     * reconnect()
     *
     * @param config the set of variables that describe the configuration,
     *            contained in a {@link EthernetConfiguration} object.
     * @param listener for callbacks on success or failure. Can be null.
     * @throws IllegalStateException if the EthernetManager instance needs to be
     * initialized again
     *
     * @hide
     */
    public void connect(EthernetConfiguration config, ActionListener listener) {
        if (config == null) throw new IllegalArgumentException("config cannot be null");
        validateChannel();
        // Use INVALID_NETWORK_ID for arg1 when passing a config object
        // arg1 is used to pass network id when the network already exists
        mAsyncChannel.sendMessage(CONNECT_NETWORK, EthernetConfiguration.INVALID_NETWORK_ID,
                putListener(listener), config);
    }

    /**
     * Connect to a network with the given networkId.
     *
     * This function is used instead of a enableNetwork(), saveConfiguration() and
     * reconnect()
     *
     * @param networkId the network id identifiying the network in the
     *                supplicant configuration list
     * @param listener for callbacks on success or failure. Can be null.
     * @throws IllegalStateException if the EthernetManager instance needs to be
     * initialized again
     * @hide
     */
    public void connect(int networkId, ActionListener listener) {
        if (networkId < 0) throw new IllegalArgumentException("Network id cannot be negative");
        validateChannel();
        mAsyncChannel.sendMessage(CONNECT_NETWORK, networkId, putListener(listener));
    }

    /**
     * Save the given network in the supplicant config. If the network already
     * exists, the configuration is updated. A new network is enabled
     * by default.
     *
     * For a new network, this function is used instead of a
     * sequence of addNetwork(), enableNetwork() and saveConfiguration().
     *
     * For an existing network, it accomplishes the task of updateNetwork()
     * and saveConfiguration()
     *
     * @param config the set of variables that describe the configuration,
     *            contained in a {@link EthernetConfiguration} object.
     * @param listener for callbacks on success or failure. Can be null.
     * @throws IllegalStateException if the EthernetManager instance needs to be
     * initialized again
     * @hide
     */
    public void save(EthernetConfiguration config, ActionListener listener) {
        if (config == null) throw new IllegalArgumentException("config cannot be null");
        validateChannel();
        mAsyncChannel.sendMessage(SAVE_NETWORK, 0, putListener(listener), config);
    }

    /**
     * Delete the network in the supplicant config.
     *
     * This function is used instead of a sequence of removeNetwork()
     * and saveConfiguration().
     *
     * @param config the set of variables that describe the configuration,
     *            contained in a {@link EthernetConfiguration} object.
     * @param listener for callbacks on success or failure. Can be null.
     * @throws IllegalStateException if the EthernetManager instance needs to be
     * initialized again
     * @hide
     */
    public void forget(int netId, ActionListener listener) {
        if (netId < 0) throw new IllegalArgumentException("Network id cannot be negative");
        validateChannel();
        mAsyncChannel.sendMessage(FORGET_NETWORK, netId, putListener(listener));
    }

    /**
     * Disable network
     *
     * @param netId is the network Id
     * @param listener for callbacks on success or failure. Can be null.
     * @throws IllegalStateException if the EthernetManager instance needs to be
     * initialized again
     * @hide
     */
    public void disable(int netId, ActionListener listener) {
        if (netId < 0) throw new IllegalArgumentException("Network id cannot be negative");
        validateChannel();
        mAsyncChannel.sendMessage(DISABLE_NETWORK, netId, putListener(listener));
    }

    /**
     * Get a reference to EthernetService handler. This is used by a client to establish
     * an AsyncChannel communication with EthernetService
     *
     * @return Messenger pointing to the EthernetService handler
     * @hide
     */
    public Messenger getEthernetServiceMessenger() {
        try {
            return mService.getEthernetServiceMessenger();
        } catch (RemoteException e) {
            return null;
        } catch (SecurityException e) {
            return null;
        }
    }

    /**
     * Get a reference to EthernetStateMachine handler.
     * @return Messenger pointing to the EthernetService handler
     * @hide
     */
    public Messenger getEthernetStateMachineMessenger() {
        try {
            return mService.getEthernetStateMachineMessenger();
        } catch (RemoteException e) {
            return null;
        }
    }

    /**
     * Returns the file in which IP and proxy configuration data is stored
     * @hide
     */
    public String getConfigFile() {
        try {
            return mService.getConfigFile();
        } catch (RemoteException e) {
            return null;
        }
    }

    /**
     * Allows an application to keep the Ethernet awake at full-speed.
     * Normally the Ethernet may turn at low speed  when the user has not used
     * the device in a while.
     * Acquiring an EthernetLock will keep the link at full speed until the
     * lock is released.  Multiple applications may hold EthernetLocks, and the
     * chipset will only be allowed to turn low when no EthernetLocks are held
     * in any application.
     * <p>
     * Before using a EthernetLock, consider carefully if your application
     * requires Ethernet access.  A program that needs to download large
     * files should hold an EthernetLock to ensure that the download will
     * complete, but a program whose network usage is occasional or
     * low-bandwidth should not hold an EthernetLock to avoid adversely
     * affecting battery life or consuming too much energy.
     * <p>
     * Note that EthernetLocks cannot override the user-level "Ethernet
     * Enabled" setting.  They simply keep the chipset from turning low-speed
     * when Ethernet is already on but the device is idle.
     * <p>
     * Any application using an EthernetLock must request the
     * {@code android.permission.WAKE_LOCK} permission in an
     * {@code &lt;uses-permission&gt;} element of the application's manifest.
     */
    public class EthernetLock {
        private String mTag;
        private final IBinder mBinder;
        private int mRefCount;
        int mLockType;
        private boolean mRefCounted;
        private boolean mHeld;
        private WorkSource mWorkSource;

        private EthernetLock(int lockType, String tag) {
            mTag = tag;
            mLockType = lockType;
            mBinder = new Binder();
            mRefCount = 0;
            mRefCounted = true;
            mHeld = false;
        }

        /**
         * Locks the Ethernet chipset on until {@link #release} is called.
         *
         * If this EthernetLock is reference-counted, each call to
	 * {@code acquire} will increment the reference count, and the chipset
	 * will remain locked as long as the reference count is
         * above zero.
         *
         * If this EthernetLock is not reference-counted, the first call to
	 * {@code acquire} will lock the chipset, but subsequent calls will be
	 * ignored.  Only one call to {@link #release} will be required,
	 * regardless of the number of times that {@code acquire} is called.
         */
        public void acquire() {
            synchronized (mBinder) {
                if (mRefCounted ? (++mRefCount == 1) : (!mHeld)) {
                    try {
                        mService.acquireEthernetLock(mBinder, mLockType, mTag, mWorkSource);
                        synchronized (EthernetManager.this) {
                            if (mActiveLockCount >= MAX_ACTIVE_LOCKS) {
                                mService.releaseEthernetLock(mBinder);
                                throw new UnsupportedOperationException(
                                            "Exceeded maximum number of ethernet locks");
                            }
                            mActiveLockCount++;
                        }
                    } catch (RemoteException ignore) {
                    }
                    mHeld = true;
                }
            }
        }

        /**
         * Unlocks the Ethernet chipset, allowing it to turn low-speed when the
	 * device is idle.
         *
         * If this EthernetLock is reference-counted, each call to
	 * {@code release} will decrement the reference count, and the chipset
	 * will be unlocked only when the reference count reaches
         * zero. If the reference count goes below zero (that is, if
	 * {@code release} is called a greater number of times than
	 * {@link #acquire}), an exception is thrown.
         *
         * If this EthernetLock is not reference-counted, the first call to
	 * {@code release} (after the chipset was locked using
	 * {@link #acquire}) will unlock the chipset, and subsequent
         * calls will be ignored.
         */
        public void release() {
            synchronized (mBinder) {
                if (mRefCounted ? (--mRefCount == 0) : (mHeld)) {
                    try {
                        mService.releaseEthernetLock(mBinder);
                        synchronized (EthernetManager.this) {
                            mActiveLockCount--;
                        }
                    } catch (RemoteException ignore) {
                    }
                    mHeld = false;
                }
                if (mRefCount < 0) {
                    throw new RuntimeException("EthernetLock under-locked " + mTag);
                }
            }
        }

        /**
         * Controls whether this is a reference-counted or
	 * non-reference-counted EthernetLock.
         *
         * Reference-counted EthernetLocks keep track of the number of calls to
	 * {@link #acquire} and {@link #release}, and only allow the chipset to
	 * go low-speed when every call to {@link #acquire}
         * has been balanced with a call to {@link #release}.
	 * Non-reference-counted EthernetLocks lock the chipset whenever
	 * {@link #acquire} is called and it is unlocked, and unlock the
         * chipset whenever {@link #release} is called and it is locked.
         *
         * @param refCounted true if this EthernetLock should keep a
	 * reference count
         */
        public void setReferenceCounted(boolean refCounted) {
            mRefCounted = refCounted;
        }

        /**
         * Checks whether this EthernetLock is currently held.
         *
         * @return true if this EthernetLock is held, false otherwise
         */
        public boolean isHeld() {
            synchronized (mBinder) {
                return mHeld;
            }
        }

        public void setWorkSource(WorkSource ws) {
            synchronized (mBinder) {
                if (ws != null && ws.size() == 0) {
                    ws = null;
                }
                boolean changed = true;
                if (ws == null) {
                    mWorkSource = null;
                } else if (mWorkSource == null) {
                    changed = mWorkSource != null;
                    mWorkSource = new WorkSource(ws);
                } else {
                    changed = mWorkSource.diff(ws);
                    if (changed) {
                        mWorkSource.set(ws);
                    }
                }
                if (changed && mHeld) {
                    try {
                        mService.updateEthernetLockWorkSource(mBinder, mWorkSource);
                    } catch (RemoteException e) {
                    }
                }
            }
        }

        public String toString() {
            String s1, s2, s3;
            synchronized (mBinder) {
                s1 = Integer.toHexString(System.identityHashCode(this));
                s2 = mHeld ? "held; " : "";
                if (mRefCounted) {
                    s3 = "refcounted: refcount = " + mRefCount;
                } else {
                    s3 = "not refcounted";
                }
                return "EthernetLock{ " + s1 + "; " + s2 + s3 + " }";
            }
        }

        @Override
        protected void finalize() throws Throwable {
            super.finalize();
            synchronized (mBinder) {
                if (mHeld) {
                    try {
                        mService.releaseEthernetLock(mBinder);
                        synchronized (EthernetManager.this) {
                            mActiveLockCount--;
                        }
                    } catch (RemoteException ignore) {
                    }
                }
            }
        }
    }

    /**
     * Creates a new EthernetLock.
     *
     * @param lockType the type of lock to create.
     * See {@link #ETHERNET_MODE_FULL}, {@link #ETHERNET_MODE_FULL_HIGH_PERF}
     * and {@link #ETHERNET_MODE_RESTRICTED_FE} for descriptions of the types
     * of Ethernet locks.
     * @param tag a tag for the EthernetLock to identify it in debugging
     * messages. This string is never shown to the user under normal
     * conditions, but should be descriptive enough to identify your
     * application and the specific EthernetLock within it, if it
     * holds multiple EthernetLocks.
     *
     * @return a new, unacquired EthernetLock with the given tag.
     *
     * @see EthernetLock
     */
    public EthernetLock createEthernetLock(int lockType, String tag) {
        return new EthernetLock(lockType, tag);
    }

    /**
     * Creates a new EthernetLock.
     *
     * @param tag a tag for the EthernetLock to identify it in debugging
     * messages. This string is never shown to the user under normal
     * conditions, but should be descriptive enough to identify your
     * application and the specific EthernetLock within it, if it
     * holds multiple EthernetLocks.
     *
     * @return a new, unacquired EthernetLock with the given tag.
     *
     * @see EthernetLock
     */
    public EthernetLock createEthernetLock(String tag) {
        return new EthernetLock(ETHERNET_MODE_FULL, tag);
    }

    /**
     * Create a new MulticastLock
     *
     * @param tag a tag for the MulticastLock to identify it in debugging
     *            messages.  This string is never shown to the user under
     *            normal conditions, but should be descriptive enough to
     *            identify your application and the specific MulticastLock
     *            within it, if it holds multiple MulticastLocks.
     *
     * @return a new, unacquired MulticastLock with the given tag.
     *
     * @see MulticastLock
     */
    public MulticastLock createMulticastLock(String tag) {
        return new MulticastLock(tag);
    }

    /**
     * Allows an application to receive Ethernet Multicast packets.
     * Normally the Ethernet stack filters out packets not explicitly
     * addressed to this device.  Acquring a MulticastLock will
     * cause the stack to receive packets addressed to multicast
     * addresses.  Processing these extra packets can cause a noticable
     * battery drain and should be disabled when not needed.
     */
    public class MulticastLock {
        private String mTag;
        private final IBinder mBinder;
        private int mRefCount;
        private boolean mRefCounted;
        private boolean mHeld;

        private MulticastLock(String tag) {
            mTag = tag;
            mBinder = new Binder();
            mRefCount = 0;
            mRefCounted = true;
            mHeld = false;
        }

        /**
         * Locks Ethernet Multicast on until {@link #release} is called.
         *
         * If this MulticastLock is reference-counted each call to
         * {@code acquire} will increment the reference count, and the
         * ethernet interface will receive multicast packets as long as the
         * reference count is above zero.
         *
         * If this MulticastLock is not reference-counted, the first call to
         * {@code acquire} will turn on the multicast packets, but subsequent
         * calls will be ignored.  Only one call to {@link #release} will
         * be required, regardless of the number of times that {@code acquire}
         * is called.
         *
         * Note that other applications may also lock Ethernet Multicast on.
         * Only they can relinquish their lock.
         *
         * Also note that applications cannot leave Multicast locked on.
         * When an app exits or crashes, any Multicast locks will be released.
         */
        public void acquire() {
            synchronized (mBinder) {
                if (mRefCounted ? (++mRefCount == 1) : (!mHeld)) {
                    try {
                        mService.acquireMulticastLock(mBinder, mTag);
                        synchronized (EthernetManager.this) {
                            if (mActiveLockCount >= MAX_ACTIVE_LOCKS) {
                                mService.releaseMulticastLock();
                                throw new UnsupportedOperationException(
                                        "Exceeded maximum number of ethernet locks");
                            }
                            mActiveLockCount++;
                        }
                    } catch (RemoteException ignore) {
                    }
                    mHeld = true;
                }
            }
        }

        /**
         * Unlocks Ethernet Multicast, restoring the filter of packets
         * not addressed specifically to this device and saving power.
         *
         * If this MulticastLock is reference-counted, each call to
         * {@code release} will decrement the reference count, and the
         * multicast packets will only stop being received when the reference
         * count reaches zero.  If the reference count goes below zero (that
         * is, if {@code release} is called a greater number of times than
         * {@link #acquire}), an exception is thrown.
         *
         * If this MulticastLock is not reference-counted, the first call to
         * {@code release} (after the chipset was multicast locked using
         * {@link #acquire}) will unlock the multicast, and subsequent calls
         * will be ignored.
         *
         * Note that if any other Ethernet Multicast Locks are still outstanding
         * this {@code release} call will not have an immediate effect.  Only
         * when all applications have released all their Multicast Locks will
         * the Multicast filter be turned back on.
         *
         * Also note that when an app exits or crashes all of its Multicast
         * Locks will be automatically released.
         */
        public void release() {
            synchronized (mBinder) {
                if (mRefCounted ? (--mRefCount == 0) : (mHeld)) {
                    try {
                        mService.releaseMulticastLock();
                        synchronized (EthernetManager.this) {
                            mActiveLockCount--;
                        }
                    } catch (RemoteException ignore) {
                    }
                    mHeld = false;
                }
                if (mRefCount < 0) {
                    throw new RuntimeException("MulticastLock under-locked "
                            + mTag);
                }
            }
        }

        /**
         * Controls whether this is a reference-counted or non-reference-
         * counted MulticastLock.
         *
         * Reference-counted MulticastLocks keep track of the number of calls
         * to {@link #acquire} and {@link #release}, and only stop the
         * reception of multicast packets when every call to {@link #acquire}
         * has been balanced with a call to {@link #release}.  Non-reference-
         * counted MulticastLocks allow the reception of multicast packets
         * whenever {@link #acquire} is called and stop accepting multicast
         * packets whenever {@link #release} is called.
         *
         * @param refCounted true if this MulticastLock should keep a reference
         * count
         */
        public void setReferenceCounted(boolean refCounted) {
            mRefCounted = refCounted;
        }

        /**
         * Checks whether this MulticastLock is currently held.
         *
         * @return true if this MulticastLock is held, false otherwise
         */
        public boolean isHeld() {
            synchronized (mBinder) {
                return mHeld;
            }
        }

        public String toString() {
            String s1, s2, s3;
            synchronized (mBinder) {
                s1 = Integer.toHexString(System.identityHashCode(this));
                s2 = mHeld ? "held; " : "";
                if (mRefCounted) {
                    s3 = "refcounted: refcount = " + mRefCount;
                } else {
                    s3 = "not refcounted";
                }
                return "MulticastLock{ " + s1 + "; " + s2 + s3 + " }";
            }
        }

        @Override
        protected void finalize() throws Throwable {
            super.finalize();
            setReferenceCounted(false);
            release();
        }
    }

    /**
     * Check multicast filter status.
     *
     * @return true if multicast packets are allowed.
     *
     * @hide pending API council approval
     */
    public boolean isMulticastEnabled() {
        try {
            return mService.isMulticastEnabled();
        } catch (RemoteException e) {
            return false;
        }
    }

    /**
     * Initialize the multicast filtering to 'on'
     * @hide no intent to publish
     */
    public boolean initializeMulticastFiltering() {
        try {
            mService.initializeMulticastFiltering();
            return true;
        } catch (RemoteException e) {
             return false;
        }
    }

    /** @hide */
    public void captivePortalCheckComplete() {
        try {
            mService.captivePortalCheckComplete();
        } catch (RemoteException e) {}
    }

    protected void finalize() throws Throwable {
        try {
            if (mHandler != null && mHandler.getLooper() != null) {
                mHandler.getLooper().quit();
            }
        } finally {
            super.finalize();
        }
    }
}
