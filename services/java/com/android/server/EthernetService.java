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

package com.android.server;

import android.app.ActivityManager;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.TaskStackBuilder;
import android.bluetooth.BluetoothAdapter;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.net.ethernet.IEthernetManager;
import android.net.ethernet.EthernetInfo;
import android.net.ethernet.EthernetManager;
import android.net.ethernet.EthernetStateMachine;
import android.net.ethernet.EthernetConfiguration;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.NetworkInfo;
import android.net.NetworkInfo.State;
import android.net.NetworkInfo.DetailedState;
import android.net.TrafficStats;
import android.os.Binder;
import android.os.Handler;
import android.os.Messenger;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.INetworkManagementService;
import android.os.Message;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.WorkSource;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import android.util.Slog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.io.FileDescriptor;
import java.io.PrintWriter;

import com.android.internal.app.IBatteryStats;
import com.android.internal.telephony.TelephonyIntents;
import com.android.internal.util.AsyncChannel;
import com.android.server.am.BatteryStatsService;
import com.android.internal.R;

/**
 * EthernetService handles remote Ethernet operation requests by implementing
 * the IEthernetManager interface.
 *
 * @hide
 */
public class EthernetService extends IEthernetManager.Stub {
    private static final String TAG = "EthernetService";
    private static final boolean DBG = false;

    private final EthernetStateMachine mEthernetStateMachine;

    private Context mContext;

    private AlarmManager mAlarmManager;
    private PendingIntent mIdleIntent;
    private static final int IDLE_REQUEST = 0;
    private boolean mScreenOff;
    private boolean mDeviceIdle;
    private boolean mEmergencyCallbackMode = false;
    private int mPluggedType;

    private final LockList mLocks = new LockList();
    // some ethernet lock statistics
    private int mFullHighPerfLocksAcquired;
    private int mFullHighPerfLocksReleased;
    private int mFullLocksAcquired;
    private int mFullLocksReleased;
    private int mRestrictedFeLocksAcquired;
    private int mRestrictedFeLocksReleased;

    private final List<Multicaster> mMulticasters =
            new ArrayList<Multicaster>();
    private int mMulticastEnabled;
    private int mMulticastDisabled;

    private final IBatteryStats mBatteryStats;

    private boolean mEnableTrafficStatsPoll = false;
    private int mTrafficStatsPollToken = 0;
    private long mTxPkts;
    private long mRxPkts;
    /* Tracks last reported data activity */
    private int mDataActivity;
    private String mInterfaceName;

    /**
     * Interval in milliseconds between polling for traffic
     * statistics
     */
    private static final int POLL_TRAFFIC_STATS_INTERVAL_MSECS = 1000;

    /**
     * See {@link Settings.Global#ETHERNET_IDLE_MS}. This is the default value if a
     * Settings.Global value is not present. This timeout value is chosen as
     * the approximate point at which the battery drain caused by Wi-Fi
     * being enabled but not active exceeds the battery drain caused by
     * re-establishing a connection to the mobile data network.
     */
    private static final long DEFAULT_IDLE_MS = 15 * 60 * 1000; /* 15 minutes */

    private static final String ACTION_DEVICE_IDLE =
            "com.android.server.EthernetManager.action.DEVICE_IDLE";

    private static final int ETHERNET_DISABLED                  = 0;
    private static final int ETHERNET_ENABLED                   = 1;

    /* Persisted state that tracks the ethernet interaction from settings */
    private AtomicInteger mPersistEthernetState = new AtomicInteger(ETHERNET_DISABLED);
    /* Tracks whether ethernet is enabled from EthernetStateMachine's perspective */
    private boolean mEthernetEnabled;

    private boolean mIsReceiverRegistered = false;


    NetworkInfo mNetworkInfo = new NetworkInfo(ConnectivityManager.TYPE_ETHERNET, 0, "ETHERNET", "");

    /**
     * Asynchronous channel to EthernetStateMachine
     */
    private AsyncChannel mEthernetStateMachineChannel;

    /**
     * Clients receiving asynchronous messages
     */
    private List<AsyncChannel> mClients = new ArrayList<AsyncChannel>();

    /**
     * Handles client connections
     */
    private class AsyncServiceHandler extends Handler {

        AsyncServiceHandler(android.os.Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case EthernetManager.ENABLE_TRAFFIC_STATS_POLL: {
                    mEnableTrafficStatsPoll = (msg.arg1 == 1);
                    mTrafficStatsPollToken++;
                    if (mEnableTrafficStatsPoll) {
                        notifyOnDataActivity();
                        sendMessageDelayed(Message.obtain(this, EthernetManager.TRAFFIC_STATS_POLL,
                                mTrafficStatsPollToken, 0), POLL_TRAFFIC_STATS_INTERVAL_MSECS);
                    }
                    break;
                }
                case EthernetManager.TRAFFIC_STATS_POLL: {
                    if (msg.arg1 == mTrafficStatsPollToken) {
                        notifyOnDataActivity();
                        sendMessageDelayed(Message.obtain(this, EthernetManager.TRAFFIC_STATS_POLL,
                                mTrafficStatsPollToken, 0), POLL_TRAFFIC_STATS_INTERVAL_MSECS);
                    }
                    break;
                }
                case EthernetManager.CONNECT_NETWORK: {
                    mEthernetStateMachine.sendMessage(Message.obtain(msg));
                    break;
                }
                case EthernetManager.SAVE_NETWORK: {
                    mEthernetStateMachine.sendMessage(Message.obtain(msg));
                    break;
                }
                case EthernetManager.FORGET_NETWORK: {
                    mEthernetStateMachine.sendMessage(Message.obtain(msg));
                    break;
                }
                case EthernetManager.DISABLE_NETWORK: {
                    mEthernetStateMachine.sendMessage(Message.obtain(msg));
                    break;
                }
                default: {
                    Slog.d(TAG, "EthernetServicehandler.handleMessage ignoring msg=" + msg);
                    break;
                }
            }
        }
    }
    private AsyncServiceHandler mAsyncServiceHandler;

    /**
     * Handles interaction with EthernetStateMachine
     */
    private class EthernetStateMachineHandler extends Handler {
        private AsyncChannel mWsmChannel;

        EthernetStateMachineHandler(android.os.Looper looper) {
            super(looper);
            mWsmChannel = new AsyncChannel();
            mWsmChannel.connect(mContext, this, mEthernetStateMachine.getHandler());
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                default: {
                    Slog.d(TAG, "EthernetStateMachineHandler.handleMessage ignoring msg=" + msg);
                    break;
                }
            }
        }
    }
    EthernetStateMachineHandler mEthernetStateMachineHandler;

    /**
     * Temporary for computing UIDS that are responsible for starting ETHERNET.
     * Protected by mEthernetStateTracker lock.
     */
    private final WorkSource mTmpWorkSource = new WorkSource();

    EthernetService(Context context) {
        mContext = context;

        mInterfaceName =  SystemProperties.get("ethernet.interface", "eth0");

        mEthernetStateMachine = new EthernetStateMachine(mContext, mInterfaceName);
        mBatteryStats = BatteryStatsService.getService();

        mAlarmManager = (AlarmManager)mContext.getSystemService(Context.ALARM_SERVICE);
        Intent idleIntent = new Intent(ACTION_DEVICE_IDLE, null);
        mIdleIntent = PendingIntent.getBroadcast(mContext, IDLE_REQUEST, idleIntent, 0);

        IntentFilter filter = new IntentFilter();
        filter.addAction(EthernetManager.ETHERNET_STATE_CHANGED_ACTION);
        filter.addAction(EthernetManager.NETWORK_STATE_CHANGED_ACTION);

        mContext.registerReceiver(
                new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        if (intent.getAction().equals(EthernetManager.ETHERNET_STATE_CHANGED_ACTION)) {
                            int ethernetState = intent.getIntExtra(EthernetManager.EXTRA_ETHERNET_STATE,
                                    EthernetManager.ETHERNET_STATE_DISABLED);

                            mEthernetEnabled = (ethernetState == EthernetManager.ETHERNET_STATE_ENABLED);

                        } else if (intent.getAction().equals(
                                EthernetManager.NETWORK_STATE_CHANGED_ACTION)) {
                            mNetworkInfo = (NetworkInfo) intent.getParcelableExtra(
                                    EthernetManager.EXTRA_NETWORK_INFO);
                            switch(mNetworkInfo.getDetailedState()) {
                                case CONNECTED:
                                case DISCONNECTED:
                                case CAPTIVE_PORTAL_CHECK:
                                    evaluateTrafficStatsPolling();
                                    break;
                            }
                        }
                    }
                }, filter);

        HandlerThread ethernetThread = new HandlerThread("EthernetService");
        ethernetThread.start();
        mAsyncServiceHandler = new AsyncServiceHandler(ethernetThread.getLooper());
        mEthernetStateMachineHandler = new EthernetStateMachineHandler(ethernetThread.getLooper());
    }

    /**
     * Check if Ethernet needs to be enabled and start
     * if needed
     *
     * This function is used only at boot time
     */
    public void checkAndStartEthernet() {
        mPersistEthernetState.set(getPersistedEthernetState());
        /* Start if Ethernet should be enabled or the saved state indicates Ethernet was on */
        boolean ethernetEnabled = shouldEthernetBeEnabled() || testAndClearEthernetSavedState();
        Slog.i(TAG, "EthernetService starting up with Ethernet " +
                (ethernetEnabled ? "enabled" : "disabled"));

        // If we are already disabled, avoid changing persist state here
        if (ethernetEnabled) setEthernetEnabled(ethernetEnabled);
    }

    private boolean testAndClearEthernetSavedState() {
        final ContentResolver cr = mContext.getContentResolver();
        int ethernetSavedState = 0;
        try {
            ethernetSavedState = Settings.Global.getInt(cr, Settings.Global.ETHERNET_SAVED_STATE);
            if(ethernetSavedState == 1)
                Settings.Global.putInt(cr, Settings.Global.ETHERNET_SAVED_STATE, 0);
        } catch (Settings.SettingNotFoundException e) {
            ;
        }
        return (ethernetSavedState == 1);
    }

    private int getPersistedEthernetState() {
        final ContentResolver cr = mContext.getContentResolver();
        try {
            return Settings.Global.getInt(cr, Settings.Global.ETHERNET_ON);
        } catch (Settings.SettingNotFoundException e) {
            Settings.Global.putInt(cr, Settings.Global.ETHERNET_ON, ETHERNET_DISABLED);
            return ETHERNET_DISABLED;
        }
    }

    private boolean shouldEthernetBeEnabled() {
	return mPersistEthernetState.get() != ETHERNET_DISABLED;
    }

    private void handleEthernetToggled(boolean ethernetEnabled) {
        if (ethernetEnabled) {
	    persistEthernetState(ETHERNET_ENABLED);
        } else {
            persistEthernetState(ETHERNET_DISABLED);
        }
    }

    private void persistEthernetState(int state) {
        final ContentResolver cr = mContext.getContentResolver();
        mPersistEthernetState.set(state);
        Settings.Global.putInt(cr, Settings.Global.ETHERNET_ON, state);
    }

    private void enforceAccessPermission() {
        mContext.enforceCallingOrSelfPermission(
		android.Manifest.permission.ACCESS_ETHERNET_STATE,
		"EthernetService");
    }

    private void enforceChangePermission() {
        mContext.enforceCallingOrSelfPermission(
		android.Manifest.permission.CHANGE_ETHERNET_STATE,
		"EthernetService");
    }

    private void enforceMulticastChangePermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.CHANGE_ETHERNET_MULTICAST_STATE,
                "EthernetService");
    }

    private void enforceConnectivityInternalPermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.CONNECTIVITY_INTERNAL,
                "ConnectivityService");
    }

    /**
     * see {@link android.net.ethernet.EthernetManager#setEthernetEnabled(boolean)}
     * @param enable {@code true} to enable, {@code false} to disable.
     * @return {@code true} if the enable/disable operation was
     *         started or is already in the queue.
     */
    public synchronized boolean setEthernetEnabled(boolean enable) {
        enforceChangePermission();
        Slog.d(TAG, "setEthernetEnabled: " + enable + " pid=" + Binder.getCallingPid()
                    + ", uid=" + Binder.getCallingUid());
        if (DBG) {
            Slog.e(TAG, "Invoking mEthernetStateMachine.setEthernetEnabled\n");
        }

        if (enable) {
            reportStartWorkSource();
        }
        mEthernetStateMachine.setEthernetEnabled(enable);

        /*
         * Caller might not have WRITE_SECURE_SETTINGS,
         * only CHANGE_ETHERNET_STATE is enforced
         */

        long ident = Binder.clearCallingIdentity();
        try {
            handleEthernetToggled(enable);
        } finally {
            Binder.restoreCallingIdentity(ident);
        }

        if (enable) {
            if (!mIsReceiverRegistered) {
                registerForBroadcasts();
                mIsReceiverRegistered = true;
            }
        } else if (mIsReceiverRegistered) {
            mContext.unregisterReceiver(mReceiver);
            mIsReceiverRegistered = false;
        }

        return true;
    }

    /**
     * see {@link EthernetManager#getEthernetState()}
     * @return One of {@link EthernetManager#ETHERNET_STATE_DISABLED},
     *         {@link EthernetManager#ETHERNET_STATE_DISABLING},
     *         {@link EthernetManager#ETHERNET_STATE_ENABLED},
     *         {@link EthernetManager#ETHERNET_STATE_ENABLING},
     *         {@link EthernetManager#ETHERNET_STATE_UNKNOWN}
     */
    public int getEthernetEnabledState() {
        enforceAccessPermission();
        return mEthernetStateMachine.syncGetEthernetState();
    }

    /**
     * see {@link android.net.ethernet.EthernetManager#disconnect()}
     */
    public void disconnect() {
        enforceChangePermission();
        mEthernetStateMachine.disconnectCommand();
    }

    /**
     * see {@link android.net.ethernet.EthernetManager#reconnect()}
     */
    public void reconnect() {
        enforceChangePermission();
        mEthernetStateMachine.reconnectCommand();
    }

    /**
     * see {@link android.net.ethernet.EthernetManager#getConfiguredNetworks()}
     * @return the list of configured networks
     */
    public List<EthernetConfiguration> getConfiguredNetworks() {
        enforceAccessPermission();
        if (mEthernetStateMachineChannel != null) {
            return mEthernetStateMachine.syncGetConfiguredNetworks(mEthernetStateMachineChannel);
        } else {
            Slog.e(TAG, "mEthernetStateMachineChannel is not initialized");
            return null;
        }
    }

    /**
     * see {@link android.net.ethernet.EthernetManager#addOrUpdateNetwork(EthernetConfiguration)}
     * @return the identifier for the new or updated
     * network if the operation succeeds, or {@code -1} if it fails
     */
    public int addOrUpdateNetwork(EthernetConfiguration config) {
        enforceChangePermission();
        if (mEthernetStateMachineChannel != null) {
            return mEthernetStateMachine.syncAddOrUpdateNetwork(mEthernetStateMachineChannel, config);
        } else {
            Slog.e(TAG, "mEthernetStateMachineChannel is not initialized");
            return -1;
        }
    }

     /**
     * See {@link android.net.ethernet.EthernetManager#removeNetwork(int)}
     * @param netId the integer that identifies the network configuration
     * to the supplicant
     * @return {@code true} if the operation succeeded
     */
    public boolean removeNetwork(int netId) {
        enforceChangePermission();
        if (mEthernetStateMachineChannel != null) {
            return mEthernetStateMachine.syncRemoveNetwork(mEthernetStateMachineChannel, netId);
        } else {
            Slog.e(TAG, "mEthernetStateMachineChannel is not initialized");
            return false;
        }
    }

    /**
     * See {@link android.net.ethernet.EthernetManager#enableNetwork(int, boolean)}
     * @param netId the integer that identifies the network configuration
     * @param disableOthers if true, disable all other networks.
     * @return {@code true} if the operation succeeded
     */
    public boolean enableNetwork(int netId, boolean disableOthers) {
        enforceChangePermission();
        if (mEthernetStateMachineChannel != null) {
            return mEthernetStateMachine.syncEnableNetwork(mEthernetStateMachineChannel, netId,
                    disableOthers);
        } else {
            Slog.e(TAG, "mEthernetStateMachineChannel is not initialized");
            return false;
        }
    }

    /**
     * See {@link android.net.ethernet.EthernetManager#disableNetwork(int)}
     * @param netId the integer that identifies the network configuration
     * @return {@code true} if the operation succeeded
     */
    public boolean disableNetwork(int netId) {
        enforceChangePermission();
        if (mEthernetStateMachineChannel != null) {
            return mEthernetStateMachine.syncDisableNetwork(mEthernetStateMachineChannel, netId);
        } else {
            Slog.e(TAG, "mEthernetStateMachineChannel is not initialized");
            return false;
        }
    }

    /**
     * See {@link android.net.ethernet.EthernetManager#getConnectionInfo()}
     * @return the Ethernet information, contained in {@link EthernetInfo}.
     */
    public EthernetInfo getConnectionInfo() {
        enforceAccessPermission();
        /*
         * Make sure we have the latest information
         */
        return mEthernetStateMachine.syncRequestConnectionInfo();
    }

    /**
     * Persist the current list of configured networks.
     * @return {@code true} if the operation succeeded
     *
     * TODO: deprecate this
     */
    public boolean saveConfiguration() {
        boolean result = true;
        enforceChangePermission();
        if (mEthernetStateMachineChannel != null) {
            return mEthernetStateMachine.syncSaveConfig(mEthernetStateMachineChannel);
        } else {
            Slog.e(TAG, "mEthernetStateMachineChannel is not initialized");
            return false;
        }
    }

    /**
     * Return the DHCP-assigned addresses from the last successful DHCP request,
     * if any.
     * @return the DHCP information
     */
    public DhcpInfo getDhcpInfo() {
        enforceAccessPermission();
        return mEthernetStateMachine.syncGetDhcpInfo();
    }

    /**
     * see {@link android.net.ethernet.EthernetManager#startEthernet}
     *
     */
    public void startEthernet() {
        enforceConnectivityInternalPermission();
        /* TODO: may be add permissions for access only to connectivity service
         * TODO: if a start issued, keep ethernet alive until a stop issued irrespective
         * of EthernetLock & device idle status unless ethernet enabled status is toggled
         */

        mEthernetStateMachine.setDriverStart(true, mEmergencyCallbackMode);
        mEthernetStateMachine.reconnectCommand();
    }

    public void captivePortalCheckComplete() {
        enforceConnectivityInternalPermission();
        mEthernetStateMachine.captivePortalCheckComplete();
    }

    /**
     * see {@link android.net.ethernet.EthernetManager#stopEthernet}
     *
     */
    public void stopEthernet() {
        enforceConnectivityInternalPermission();
        /*
         * TODO: if a stop is issued, ethernet is brought up only by startEthernet
         * unless ethernet enabled status is toggled
         */
        mEthernetStateMachine.setDriverStart(false, mEmergencyCallbackMode);
    }

    /**
     * Get a reference to handler. This is used by a client to establish
     * an AsyncChannel communication with EthernetService
     */
    public Messenger getEthernetServiceMessenger() {
        enforceAccessPermission();
        enforceChangePermission();
        return new Messenger(mAsyncServiceHandler);
    }

    /** Get a reference to EthernetStateMachine handler for AsyncChannel communication */
    public Messenger getEthernetStateMachineMessenger() {
        enforceAccessPermission();
        enforceChangePermission();
        return mEthernetStateMachine.getMessenger();
    }

    /**
     * Get the IP and proxy configuration file
     */
    public String getConfigFile() {
        enforceAccessPermission();
        return mEthernetStateMachine.getConfigFile();
    }

    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();

            long idleMillis =
                Settings.Global.getLong(mContext.getContentResolver(),
                                        Settings.Global.ETHERNET_IDLE_MS, DEFAULT_IDLE_MS);
            int stayAwakeConditions =
                Settings.Global.getInt(mContext.getContentResolver(),
                                       Settings.Global.STAY_ON_WHILE_PLUGGED_IN, 0);
            if (action.equals(Intent.ACTION_SCREEN_ON)) {
                if (DBG) {
                    Slog.d(TAG, "ACTION_SCREEN_ON");
                }
                mAlarmManager.cancel(mIdleIntent);
                mScreenOff = false;
                evaluateTrafficStatsPolling();
                setDeviceIdleAndUpdateEthernet(false);
            } else if (action.equals(Intent.ACTION_SCREEN_OFF)) {
                if (DBG) {
                    Slog.d(TAG, "ACTION_SCREEN_OFF");
                }
                mScreenOff = true;
                evaluateTrafficStatsPolling();
                /*
                 * Set a timer to put Ethernet to sleep, but only if the screen is off
                 * AND the "stay on while plugged in" setting doesn't match the
                 * current power conditions (i.e, not plugged in, plugged in to USB,
                 * or plugged in to AC).
                 */
                if (!shouldEthernetStayAwake(stayAwakeConditions, mPluggedType)) {
                    //Delayed shutdown if ethernet is connected
                    if (mNetworkInfo.getDetailedState() == DetailedState.CONNECTED) {
                        if (DBG) Slog.d(TAG, "setting ACTION_DEVICE_IDLE: " + idleMillis + " ms");
                        mAlarmManager.set(AlarmManager.RTC_WAKEUP, System.currentTimeMillis()
                                + idleMillis, mIdleIntent);
                    } else {
                        setDeviceIdleAndUpdateEthernet(true);
                    }
                }
            } else if (action.equals(ACTION_DEVICE_IDLE)) {
                setDeviceIdleAndUpdateEthernet(true);
            } else if (action.equals(Intent.ACTION_BATTERY_CHANGED)) {
                /*
                 * Set a timer to put Ethernet to sleep, but only if the screen is off
                 * AND we are transitioning from a state in which the device was supposed
                 * to stay awake to a state in which it is not supposed to stay awake.
                 * If "stay awake" state is not changing, we do nothing, to avoid resetting
                 * the already-set timer.
                 */
                int pluggedType = intent.getIntExtra("plugged", 0);
                if (DBG) {
                    Slog.d(TAG, "ACTION_BATTERY_CHANGED pluggedType: " + pluggedType);
                }
                if (mScreenOff && shouldEthernetStayAwake(stayAwakeConditions, mPluggedType) &&
                        !shouldEthernetStayAwake(stayAwakeConditions, pluggedType)) {
                    long triggerTime = System.currentTimeMillis() + idleMillis;
                    if (DBG) {
                        Slog.d(TAG, "setting ACTION_DEVICE_IDLE timer for " + idleMillis + "ms");
                    }
                    mAlarmManager.set(AlarmManager.RTC_WAKEUP, triggerTime, mIdleIntent);
                }

                mPluggedType = pluggedType;
            } else if (action.equals(TelephonyIntents.ACTION_EMERGENCY_CALLBACK_MODE_CHANGED)) {
                mEmergencyCallbackMode = intent.getBooleanExtra("phoneinECMState", false);
                updateEthernetState();
            }
        }

        /**
         * Determines whether the Ethernet chipset should stay awake or be put to
         * sleep. Looks at the setting for the sleep policy and the current
         * conditions.
         *
         * @see #shouldDeviceStayAwake(int, int)
         */
        private boolean shouldEthernetStayAwake(int stayAwakeConditions, int pluggedType) {
            //Never sleep as long as the user has not changed the settings
            int ethernetSleepPolicy = Settings.Global.getInt(mContext.getContentResolver(),
                    Settings.Global.ETHERNET_SLEEP_POLICY,
                    Settings.Global.ETHERNET_SLEEP_POLICY_NEVER);

            if (ethernetSleepPolicy == Settings.Global.ETHERNET_SLEEP_POLICY_NEVER) {
                // Never sleep
                return true;
            } else if ((ethernetSleepPolicy == Settings.Global.ETHERNET_SLEEP_POLICY_NEVER_WHILE_PLUGGED) &&
                    (pluggedType != 0)) {
                // Never sleep while plugged, and we're plugged
                return true;
            } else {
                // Default
                return shouldDeviceStayAwake(stayAwakeConditions, pluggedType);
            }
        }

        /**
         * Determine whether the bit value corresponding to {@code pluggedType} is set in
         * the bit string {@code stayAwakeConditions}. Because a {@code pluggedType} value
         * of {@code 0} isn't really a plugged type, but rather an indication that the
         * device isn't plugged in at all, there is no bit value corresponding to a
         * {@code pluggedType} value of {@code 0}. That is why we shift by
         * {@code pluggedType - 1} instead of by {@code pluggedType}.
         * @param stayAwakeConditions a bit string specifying which "plugged types" should
         * keep the device (and hence Ethernet) awake.
         * @param pluggedType the type of plug (USB, AC, or none) for which the check is
         * being made
         * @return {@code true} if {@code pluggedType} indicates that the device is
         * supposed to stay awake, {@code false} otherwise.
         */
        private boolean shouldDeviceStayAwake(int stayAwakeConditions, int pluggedType) {
            return (stayAwakeConditions & pluggedType) != 0;
        }
    };

    private void setDeviceIdleAndUpdateEthernet(boolean deviceIdle) {
        mDeviceIdle = deviceIdle;
        reportStartWorkSource();
        updateEthernetState();
    }

    private synchronized void reportStartWorkSource() {
        mTmpWorkSource.clear();
        if (mDeviceIdle) {
            for (int i=0; i<mLocks.mList.size(); i++) {
                mTmpWorkSource.add(mLocks.mList.get(i).mWorkSource);
            }
        }
        mEthernetStateMachine.updateBatteryWorkSource(mTmpWorkSource);
    }

    private void updateEthernetState() {
        boolean lockHeld = mLocks.hasLocks();
        int strongestLockMode = EthernetManager.ETHERNET_MODE_FULL;
        boolean ethernetShouldBeStarted;

        if (mEmergencyCallbackMode) {
            ethernetShouldBeStarted = false;
        } else {
            ethernetShouldBeStarted = !mDeviceIdle || lockHeld;
        }

        if (lockHeld) {
            strongestLockMode = mLocks.getStrongestLockMode();
        }
        /* If device is not idle, lockmode cannot be restricted to Fast-Ethernet only */
        if (!mDeviceIdle && strongestLockMode == EthernetManager.ETHERNET_MODE_RESTRICTED_FE) {
            strongestLockMode = EthernetManager.ETHERNET_MODE_FULL;
        }

        if (shouldEthernetBeEnabled()) {
            if (ethernetShouldBeStarted) {
                reportStartWorkSource();
                mEthernetStateMachine.setEthernetEnabled(true);
                mEthernetStateMachine.setRestrictedFeMode(
                        strongestLockMode == EthernetManager.ETHERNET_MODE_RESTRICTED_FE);
                mEthernetStateMachine.setDriverStart(true, mEmergencyCallbackMode);
                mEthernetStateMachine.setHighPerfModeEnabled(strongestLockMode
                        == EthernetManager.ETHERNET_MODE_FULL_HIGH_PERF);
            } else {
                mEthernetStateMachine.setDriverStart(false, mEmergencyCallbackMode);
            }
        } else {
            mEthernetStateMachine.setEthernetEnabled(false);
        }
    }

    private void registerForBroadcasts() {
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(Intent.ACTION_SCREEN_ON);
        intentFilter.addAction(Intent.ACTION_SCREEN_OFF);
        intentFilter.addAction(Intent.ACTION_BATTERY_CHANGED);
        intentFilter.addAction(ACTION_DEVICE_IDLE);
        intentFilter.addAction(TelephonyIntents.ACTION_EMERGENCY_CALLBACK_MODE_CHANGED);
        mContext.registerReceiver(mReceiver, intentFilter);
    }

    @Override
    protected void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
        if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
                != PackageManager.PERMISSION_GRANTED) {
            pw.println("Permission Denial: can't dump EthernetService from from pid="
                    + Binder.getCallingPid()
                    + ", uid=" + Binder.getCallingUid());
            return;
        }
        pw.println("Ethernet is " + mEthernetStateMachine.syncGetEthernetStateByName());
        pw.println("Stay-awake conditions: " +
                Settings.Global.getInt(mContext.getContentResolver(),
                                       Settings.Global.STAY_ON_WHILE_PLUGGED_IN, 0));
        pw.println();

        pw.println("Internal state:");
        pw.println(mEthernetStateMachine);
        pw.println();
        pw.println("Locks acquired: " + mFullLocksAcquired + " full, " +
                mFullHighPerfLocksAcquired + " full high perf, " +
                mRestrictedFeLocksAcquired + " restricted");
        pw.println("Locks released: " + mFullLocksReleased + " full, " +
                mFullHighPerfLocksReleased + " full high perf, " +
                mRestrictedFeLocksReleased + " restricted");
        pw.println();
        pw.println("Locks held:");
        mLocks.dump(pw);

        pw.println();
        pw.println("EthernetStateMachine dump");
        mEthernetStateMachine.dump(fd, pw, args);
    }

    private class EthernetLock extends DeathRecipient {
        EthernetLock(int lockMode, String tag, IBinder binder, WorkSource ws) {
            super(lockMode, tag, binder, ws);
        }

        public void binderDied() {
            synchronized (mLocks) {
                releaseEthernetLockLocked(mBinder);
            }
        }

        public String toString() {
            return "EthernetLock{" + mTag + " type=" + mMode + " binder=" + mBinder + "}";
        }
    }

    private class LockList {
        private List<EthernetLock> mList;

        private LockList() {
            mList = new ArrayList<EthernetLock>();
        }

        private synchronized boolean hasLocks() {
            return !mList.isEmpty();
        }

        private synchronized int getStrongestLockMode() {
            if (mList.isEmpty()) {
                return EthernetManager.ETHERNET_MODE_FULL;
            }

            if (mFullHighPerfLocksAcquired > mFullHighPerfLocksReleased) {
                return EthernetManager.ETHERNET_MODE_FULL_HIGH_PERF;
            }

            if (mFullLocksAcquired > mFullLocksReleased) {
                return EthernetManager.ETHERNET_MODE_FULL;
            }

            return EthernetManager.ETHERNET_MODE_RESTRICTED_FE;
        }

        private void addLock(EthernetLock lock) {
            if (findLockByBinder(lock.mBinder) < 0) {
                mList.add(lock);
            }
        }

        private EthernetLock removeLock(IBinder binder) {
            int index = findLockByBinder(binder);
            if (index >= 0) {
                EthernetLock ret = mList.remove(index);
                ret.unlinkDeathRecipient();
                return ret;
            } else {
                return null;
            }
        }

        private int findLockByBinder(IBinder binder) {
            int size = mList.size();
            for (int i = size - 1; i >= 0; i--)
                if (mList.get(i).mBinder == binder)
                    return i;
            return -1;
        }

        private void dump(PrintWriter pw) {
            for (EthernetLock l : mList) {
                pw.print("    ");
                pw.println(l);
            }
        }
    }

    void enforceWakeSourcePermission(int uid, int pid) {
        if (uid == android.os.Process.myUid()) {
            return;
        }
        mContext.enforcePermission(android.Manifest.permission.UPDATE_DEVICE_STATS,
                pid, uid, null);
    }

    public boolean acquireEthernetLock(IBinder binder, int lockMode, String tag, WorkSource ws) {
        mContext.enforceCallingOrSelfPermission(android.Manifest.permission.WAKE_LOCK, null);
        if (lockMode != EthernetManager.ETHERNET_MODE_FULL &&
                lockMode != EthernetManager.ETHERNET_MODE_RESTRICTED_FE &&
                lockMode != EthernetManager.ETHERNET_MODE_FULL_HIGH_PERF) {
            Slog.e(TAG, "Illegal argument, lockMode= " + lockMode);
            if (DBG) throw new IllegalArgumentException("lockMode=" + lockMode);
            return false;
        }
        if (ws != null && ws.size() == 0) {
            ws = null;
        }
        if (ws != null) {
            enforceWakeSourcePermission(Binder.getCallingUid(), Binder.getCallingPid());
        }
        if (ws == null) {
            ws = new WorkSource(Binder.getCallingUid());
        }
        EthernetLock ethernetLock = new EthernetLock(lockMode, tag, binder, ws);
        synchronized (mLocks) {
            return acquireEthernetLockLocked(ethernetLock);
        }
    }

    private void noteAcquireEthernetLock(EthernetLock ethernetLock) throws RemoteException {
        switch(ethernetLock.mMode) {
            case EthernetManager.ETHERNET_MODE_FULL:
            case EthernetManager.ETHERNET_MODE_FULL_HIGH_PERF:
            case EthernetManager.ETHERNET_MODE_RESTRICTED_FE:
                mBatteryStats.noteFullEthernetLockAcquiredFromSource(ethernetLock.mWorkSource);
                break;
        }
    }

    private void noteReleaseEthernetLock(EthernetLock ethernetLock) throws RemoteException {
        switch(ethernetLock.mMode) {
            case EthernetManager.ETHERNET_MODE_FULL:
            case EthernetManager.ETHERNET_MODE_FULL_HIGH_PERF:
            case EthernetManager.ETHERNET_MODE_RESTRICTED_FE:
                mBatteryStats.noteFullEthernetLockReleasedFromSource(ethernetLock.mWorkSource);
                break;
        }
    }

    private boolean acquireEthernetLockLocked(EthernetLock ethernetLock) {
        if (DBG) Slog.d(TAG, "acquireEthernetLockLocked: " + ethernetLock);

        mLocks.addLock(ethernetLock);

        long ident = Binder.clearCallingIdentity();
        try {
            noteAcquireEthernetLock(ethernetLock);
            switch(ethernetLock.mMode) {
            case EthernetManager.ETHERNET_MODE_FULL:
                ++mFullLocksAcquired;
                break;
            case EthernetManager.ETHERNET_MODE_FULL_HIGH_PERF:
                ++mFullHighPerfLocksAcquired;
                break;

            case EthernetManager.ETHERNET_MODE_RESTRICTED_FE:
                ++mRestrictedFeLocksAcquired;
                break;
            }

            // Be aggressive about adding new locks into the accounted state...
            // we want to over-report rather than under-report.
            reportStartWorkSource();

            updateEthernetState();
            return true;
        } catch (RemoteException e) {
            return false;
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    public void updateEthernetLockWorkSource(IBinder lock, WorkSource ws) {
        int uid = Binder.getCallingUid();
        int pid = Binder.getCallingPid();
        if (ws != null && ws.size() == 0) {
            ws = null;
        }
        if (ws != null) {
            enforceWakeSourcePermission(uid, pid);
        }
        long ident = Binder.clearCallingIdentity();
        try {
            synchronized (mLocks) {
                int index = mLocks.findLockByBinder(lock);
                if (index < 0) {
                    throw new IllegalArgumentException("Ethernet lock not active");
                }
                EthernetLock wl = mLocks.mList.get(index);
                noteReleaseEthernetLock(wl);
                wl.mWorkSource = ws != null ? new WorkSource(ws) : new WorkSource(uid);
                noteAcquireEthernetLock(wl);
            }
        } catch (RemoteException e) {
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    public boolean releaseEthernetLock(IBinder lock) {
        mContext.enforceCallingOrSelfPermission(android.Manifest.permission.WAKE_LOCK, null);
        synchronized (mLocks) {
            return releaseEthernetLockLocked(lock);
        }
    }

    private boolean releaseEthernetLockLocked(IBinder lock) {
        boolean hadLock;

        EthernetLock ethernetLock = mLocks.removeLock(lock);

        if (DBG) Slog.d(TAG, "releaseEthernetLockLocked: " + ethernetLock);

        hadLock = (ethernetLock != null);

        long ident = Binder.clearCallingIdentity();
        try {
            if (hadLock) {
                noteReleaseEthernetLock(ethernetLock);
                switch(ethernetLock.mMode) {
                    case EthernetManager.ETHERNET_MODE_FULL:
                        ++mFullLocksReleased;
                        break;
                    case EthernetManager.ETHERNET_MODE_FULL_HIGH_PERF:
                        ++mFullHighPerfLocksReleased;
                        break;
                    case EthernetManager.ETHERNET_MODE_RESTRICTED_FE:
                        ++mRestrictedFeLocksReleased;
                        break;
                }
            }

            // TODO - should this only happen if you hadLock?
            updateEthernetState();

        } catch (RemoteException e) {
        } finally {
            Binder.restoreCallingIdentity(ident);
        }

        return hadLock;
    }

    private abstract class DeathRecipient
            implements IBinder.DeathRecipient {
        String mTag;
        int mMode;
        IBinder mBinder;
        WorkSource mWorkSource;

        DeathRecipient(int mode, String tag, IBinder binder, WorkSource ws) {
            super();
            mTag = tag;
            mMode = mode;
            mBinder = binder;
            mWorkSource = ws;
            try {
                mBinder.linkToDeath(this, 0);
            } catch (RemoteException e) {
                binderDied();
            }
        }

        void unlinkDeathRecipient() {
            mBinder.unlinkToDeath(this, 0);
        }
    }

    private class Multicaster extends DeathRecipient {
        Multicaster(String tag, IBinder binder) {
            super(Binder.getCallingUid(), tag, binder, null);
        }

        public void binderDied() {
            Slog.e(TAG, "Multicaster binderDied");
            synchronized (mMulticasters) {
                int i = mMulticasters.indexOf(this);
                if (i != -1) {
                    removeMulticasterLocked(i, mMode);
                }
            }
        }

        public String toString() {
            return "Multicaster{" + mTag + " binder=" + mBinder + "}";
        }

        public int getUid() {
            return mMode;
        }
    }

    public void initializeMulticastFiltering() {
        enforceMulticastChangePermission();

        synchronized (mMulticasters) {
            // if anybody had requested filters be off, leave off
            if (mMulticasters.size() != 0) {
                return;
            } else {
                mEthernetStateMachine.startFilteringMulticastV4Packets();
            }
        }
    }

    public void acquireMulticastLock(IBinder binder, String tag) {
        enforceMulticastChangePermission();

        synchronized (mMulticasters) {
            mMulticastEnabled++;
            mMulticasters.add(new Multicaster(tag, binder));
            // Note that we could call stopFilteringMulticastV4Packets only when
            // our new size == 1 (first call), but this function won't
            // be called often and by making the stopPacket call each
            // time we're less fragile and self-healing.
            mEthernetStateMachine.stopFilteringMulticastV4Packets();
        }

        int uid = Binder.getCallingUid();
        Long ident = Binder.clearCallingIdentity();
        try {
            mBatteryStats.noteEthernetMulticastEnabled(uid);
        } catch (RemoteException e) {
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    public void releaseMulticastLock() {
        enforceMulticastChangePermission();

        int uid = Binder.getCallingUid();
        synchronized (mMulticasters) {
            mMulticastDisabled++;
            int size = mMulticasters.size();
            for (int i = size - 1; i >= 0; i--) {
                Multicaster m = mMulticasters.get(i);
                if ((m != null) && (m.getUid() == uid)) {
                    removeMulticasterLocked(i, uid);
                }
            }
        }
    }

    private void removeMulticasterLocked(int i, int uid)
    {
        Multicaster removed = mMulticasters.remove(i);

        if (removed != null) {
            removed.unlinkDeathRecipient();
        }
        if (mMulticasters.size() == 0) {
            mEthernetStateMachine.startFilteringMulticastV4Packets();
        }

        Long ident = Binder.clearCallingIdentity();
        try {
            mBatteryStats.noteEthernetMulticastDisabled(uid);
        } catch (RemoteException e) {
        } finally {
            Binder.restoreCallingIdentity(ident);
        }
    }

    public boolean isMulticastEnabled() {
        enforceAccessPermission();

        synchronized (mMulticasters) {
            return (mMulticasters.size() > 0);
        }
    }

    /**
     * Evaluate if traffic stats polling is needed based on
     * connection and screen on status
     */
    private void evaluateTrafficStatsPolling() {
        Message msg;
        if (mNetworkInfo.getDetailedState() == DetailedState.CONNECTED && !mScreenOff) {
            msg = Message.obtain(mAsyncServiceHandler,
                    EthernetManager.ENABLE_TRAFFIC_STATS_POLL, 1, 0);
        } else {
            msg = Message.obtain(mAsyncServiceHandler,
                    EthernetManager.ENABLE_TRAFFIC_STATS_POLL, 0, 0);
        }
        msg.sendToTarget();
    }

    private void notifyOnDataActivity() {
        long sent, received;
        long preTxPkts = mTxPkts, preRxPkts = mRxPkts;
        int dataActivity = EthernetManager.DATA_ACTIVITY_NONE;

        mTxPkts = TrafficStats.getTxPackets(mInterfaceName);
        mRxPkts = TrafficStats.getRxPackets(mInterfaceName);

        if (preTxPkts > 0 || preRxPkts > 0) {
            sent = mTxPkts - preTxPkts;
            received = mRxPkts - preRxPkts;
            if (sent > 0) {
                dataActivity |= EthernetManager.DATA_ACTIVITY_OUT;
            }
            if (received > 0) {
                dataActivity |= EthernetManager.DATA_ACTIVITY_IN;
            }

            if (dataActivity != mDataActivity && !mScreenOff) {
                mDataActivity = dataActivity;
                for (AsyncChannel client : mClients) {
                    client.sendMessage(EthernetManager.DATA_ACTIVITY_NOTIFICATION, mDataActivity);
                }
            }
        }
    }
}
