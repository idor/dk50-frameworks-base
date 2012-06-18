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

import static android.net.ethernet.EthernetManager.ETHERNET_STATE_DISABLED;
import static android.net.ethernet.EthernetManager.ETHERNET_STATE_DISABLING;
import static android.net.ethernet.EthernetManager.ETHERNET_STATE_ENABLED;
import static android.net.ethernet.EthernetManager.ETHERNET_STATE_ENABLING;
import static android.net.ethernet.EthernetManager.ETHERNET_STATE_UNKNOWN;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.backup.IBackupManager;
import android.bluetooth.BluetoothAdapter;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.DhcpInfoInternal;
import android.net.DhcpStateMachine;
import android.net.InterfaceConfiguration;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.NetworkInfo;
import android.net.NetworkInfo.DetailedState;
import android.net.NetworkUtils;
import android.os.Binder;
import android.os.IBinder;
import android.os.INetworkManagementService;
import android.os.Message;
import android.os.Messenger;
import android.os.PowerManager;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.WorkSource;
import android.provider.Settings;
import android.util.EventLog;
import android.util.Log;
import android.util.LruCache;

import com.android.internal.R;
import com.android.internal.app.IBatteryStats;
import com.android.internal.util.AsyncChannel;
import com.android.internal.util.Protocol;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * Track the state of Ethernet connectivity. All event handling is done here,
 * and all changes in connectivity state are initiated here.
 *
 * @hide
 */
public class EthernetStateMachine extends StateMachine {

    private static final String TAG = "EthernetStateMachine";
    private static final String NETWORKTYPE = "ETHERNET";
    private static final boolean DBG = false;

    private EthernetMonitor mEthernetMonitor;
    private EthernetNative mEthernetNative;
    private EthernetConfigStore mEthernetConfigStore;
    private INetworkManagementService mNwService;
    private ConnectivityManager mCm;

    private boolean mTemporarilyDisconnectEthernet = false;
    private final String mPrimaryDeviceType;

    private String mInterfaceName;
    /* Tethering interface could be seperate from lan interface */
    private String mTetherInterfaceName;

    private int mLastNetworkId;
    private int mReconnectCount = 0;

    /* Tracks if state machine has received any screen state change broadcast yet.
     * We can miss one of these at boot.
     */
    private AtomicBoolean mScreenBroadcastReceived = new AtomicBoolean(false);

    private PowerManager.WakeLock mSuspendWakeLock;

    /**
     * Tether state change notification time out
     */
    private static final int TETHER_NOTIFICATION_TIME_OUT_MSECS = 5000;

    /* Tracks sequence number on a tether notification time out */
    private int mTetherToken = 0;

    /**
     * Driver start time out.
     */
    private static final int DRIVER_START_TIME_OUT_MSECS = 10000;

    /* Tracks sequence number on a driver time out */
    private int mDriverStartToken = 0;

    private LinkProperties mLinkProperties;

    // Wakelock held during ethernet start/stop and driver load/unload
    private PowerManager.WakeLock mWakeLock;

    private Context mContext;

    private DhcpInfoInternal mDhcpInfoInternal;
    private EthernetInfo mEthernetInfo;
    private NetworkInfo mNetworkInfo;
    private DhcpStateMachine mDhcpStateMachine;

    private AlarmManager mAlarmManager;
    private PendingIntent mDriverStopIntent;

    /* Tracks if we are filtering Multicast v4 packets. Default is to filter. */
    private AtomicBoolean mFilteringMulticastV4Packets = new AtomicBoolean(true);

    // Channel for sending replies.
    private AsyncChannel mReplyChannel = new AsyncChannel();

    // Event log tags (must be in sync with event-log-tags)
    private static final int EVENTLOG_ETHERNET_STATE_CHANGED        = 50031;
    private static final int EVENTLOG_ETHERNET_EVENT_HANDLED        = 50032;

    /* The base for ethernet message types */
    static final int BASE = Protocol.BASE_ETHERNET;

    /* Load the driver */
    static final int CMD_LOAD_DRIVER                      = BASE + 1;
    /* Unload the driver */
    static final int CMD_UNLOAD_DRIVER                    = BASE + 2;
    /* Indicates driver load succeeded */
    static final int CMD_LOAD_DRIVER_SUCCESS              = BASE + 3;
    /* Indicates driver load failed */
    static final int CMD_LOAD_DRIVER_FAILURE              = BASE + 4;
    /* Indicates driver unload succeeded */
    static final int CMD_UNLOAD_DRIVER_SUCCESS            = BASE + 5;
    /* Indicates driver unload failed */
    static final int CMD_UNLOAD_DRIVER_FAILURE            = BASE + 6;

    /* Indicates Static IP succeded */
    static final int CMD_STATIC_IP_SUCCESS                = BASE + 11;
    /* Indicates Static IP failed */
    static final int CMD_STATIC_IP_FAILURE                = BASE + 12;
    /* Ready to switch to network as default */
    static final int CMD_CAPTIVE_CHECK_COMPLETE           = BASE + 13;
    /* Invoked when getting a tether state change notification */
    static final int CMD_TETHER_STATE_CHANGE              = BASE + 14;
    /* A delayed message sent to indicate tether state change failed to arrive */
    static final int CMD_TETHER_NOTIFICATION_TIMED_OUT    = BASE + 15;

    /* Add/update a network configuration */
    static final int CMD_ADD_OR_UPDATE_NETWORK            = BASE + 21;
    /* Delete a network */
    static final int CMD_REMOVE_NETWORK                   = BASE + 22;
    /* Enable a network. The device will attempt a connection to the given network. */
    static final int CMD_ENABLE_NETWORK                   = BASE + 23;
    /* Enable all networks */
    static final int CMD_ENABLE_ALL_NETWORKS              = BASE + 24;
    /* Save configuration */
    static final int CMD_SAVE_CONFIG                      = BASE + 25;
    /* Get configured networks*/
    static final int CMD_GET_CONFIGURED_NETWORKS          = BASE + 26;

    /* Disconnect from a network */
    static final int CMD_DISCONNECT                       = BASE + 31;
    /* Reconnect to a network */
    static final int CMD_RECONNECT                        = BASE + 32;

/* Controls suspend mode optimizations
     *
     * When high perf mode is enabled, suspend mode optimizations are disabled
     *
     * When high perf mode is disabled, suspend mode optimizations are enabled
     *
     * Suspend mode optimizations includes packet filtering.
     */
    static final int CMD_SET_HIGH_PERF_MODE               = BASE + 41;
    /* Set up packet filtering */
    static final int CMD_START_PACKET_FILTERING           = BASE + 42;
    /* Clear packet filter */
    static final int CMD_STOP_PACKET_FILTERING            = BASE + 43;

    /* arg1 values to CMD_STOP_PACKET_FILTERING and CMD_START_PACKET_FILTERING */
    static final int MULTICAST_V6  = 1;
    static final int MULTICAST_V4  = 0;

    private static final int SUCCESS = 1;
    private static final int FAILURE = -1;

    /* Phone in emergency call back mode */
    private static final int IN_ECM_STATE = 1;
    private static final int NOT_IN_ECM_STATE = 0;

    /**
     * The maximum number of times we will retry a connection
     * for which we have failed in acquiring an IP address from DHCP. A value of
     * N means that we will make N+1 connection attempts in all.
     * <p>
     * See {@link Settings.Secure#ETHERNET_MAX_DHCP_RETRY_COUNT}. This is the default
     * value if a Settings value is not present.
     */
    private static final int DEFAULT_MAX_DHCP_RETRIES = 9;

    /* Tracks if suspend optimizations need to be disabled by DHCP,
     * screen or due to high perf mode.
     * When any of them needs to disable it, we keep the suspend optimizations
     * disabled
     */
    private int mSuspendOptNeedsDisabled = 0;

    private static final int SUSPEND_DUE_TO_DHCP       = 1;
    private static final int SUSPEND_DUE_TO_HIGH_PERF  = 1<<1;
    private static final int SUSPEND_DUE_TO_SCREEN     = 1<<2;

    /* Tracks if user has enabled suspend optimizations through settings */
    private AtomicBoolean mUserWantsSuspendOpt = new AtomicBoolean(true);

    /**
     * Minimum time interval between enabling all networks.
     * A device can end up repeatedly connecting to a bad network on screen on/off toggle
     * due to enabling every time. We add a threshold to avoid this.
     */
    private static final int MIN_INTERVAL_ENABLE_ALL_NETWORKS_MS = 10 * 60 * 1000; /* 10 minutes */
    private long mLastEnableAllNetworksTime;

    /* Default parent state */
    private State mDefaultState = new DefaultState();
    /* Temporary initial state */
    private State mInitialState = new InitialState();

    /* Unloading the driver */
    private State mDriverUnloadingState = new DriverUnloadingState();
    /* Loading the driver */
    private State mDriverUnloadedState = new DriverUnloadedState();
    /* Driver load/unload failed */
    private State mDriverFailedState = new DriverFailedState();
    /* Driver loading */
    private State mDriverLoadingState = new DriverLoadingState();
    /* Driver loaded */
    private State mDriverLoadedState = new DriverLoadedState();

    /* Connecting to network */
    private State mConnectModeState = new ConnectModeState();
    /* Connected at 802.11 (L2) level */
    private State mL2ConnectedState = new L2ConnectedState();
    /* fetching IP after connection to network */
    private State mObtainingIpState = new ObtainingIpState();
    /* Waiting for captive portal check to be complete */
    private State mCaptivePortalCheckState = new CaptivePortalCheckState();
    /* Connected with IP addr */
    private State mConnectedState = new ConnectedState();
    /* disconnect issued, waiting for network disconnect confirmation */
    private State mDisconnectingState = new DisconnectingState();
    /* Network is not connected */
    private State mDisconnectedState = new DisconnectedState();

    /* waiting for tether notification */
    private State mTetheringState = new TetheringState();
    /* we are tethered through connectivity service */
    private State mTetheredState = new TetheredState();

    private class TetherStateChange {
        ArrayList<String> available;
        ArrayList<String> active;
        TetherStateChange(ArrayList<String> av, ArrayList<String> ac) {
            available = av;
            active = ac;
        }
    }

    /**
     * One of  {@link EthernetManager#ETHERNET_STATE_DISABLED},
     *         {@link EthernetManager#ETHERNET_STATE_DISABLING},
     *         {@link EthernetManager#ETHERNET_STATE_ENABLED},
     *         {@link EthernetManager#ETHERNET_STATE_ENABLING},
     *         {@link EthernetManager#ETHERNET_STATE_UNKNOWN}
     *
     */
    private final AtomicInteger mEthernetState = new AtomicInteger(ETHERNET_STATE_DISABLED);

    private final AtomicInteger mLastEnableUid = new AtomicInteger(Process.myUid());

    /**
     * Keep track of whether ETHERNET is running.
     */
    private boolean mIsRunning = false;

    /**
     * Keep track of whether we last told the battery stats we had started.
     */
    private boolean mReportedRunning = false;

    /**
     * Most recently set source of starting ETHERNET.
     */
    private final WorkSource mRunningEthernetUids = new WorkSource();

    /**
     * The last reported UIDs that were responsible for starting ETHERNET.
     */
    private final WorkSource mLastRunningEthernetUids = new WorkSource();

    private final IBatteryStats mBatteryStats;

    public EthernetStateMachine(Context context, String lanInterface) {
        super(TAG);

        mContext = context;
        mInterfaceName = lanInterface;

        mNetworkInfo = new NetworkInfo(ConnectivityManager.TYPE_ETHERNET, 0, NETWORKTYPE, "");
        mBatteryStats = IBatteryStats.Stub.asInterface(ServiceManager.getService("batteryinfo"));

        IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
        mNwService = INetworkManagementService.Stub.asInterface(b);

        mEthernetNative = new EthernetNative(mInterfaceName);
        mEthernetConfigStore = new EthernetConfigStore(context, mEthernetNative);
        mEthernetMonitor = new EthernetMonitor(this, mEthernetNative);
        mDhcpInfoInternal = new DhcpInfoInternal();
        mEthernetInfo = new EthernetInfo();
        mLinkProperties = new LinkProperties();

        mNetworkInfo.setIsAvailable(false);
        mLinkProperties.clear();
        mLastNetworkId = EthernetConfiguration.INVALID_NETWORK_ID;

        mAlarmManager = (AlarmManager)mContext.getSystemService(Context.ALARM_SERVICE);

        mUserWantsSuspendOpt.set(Settings.Global.getInt(mContext.getContentResolver(),
                    Settings.Global.ETHERNET_SUSPEND_OPTIMIZATIONS_ENABLED, 1) == 1);

        mContext.registerReceiver(
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    ArrayList<String> available = intent.getStringArrayListExtra(
                            ConnectivityManager.EXTRA_AVAILABLE_TETHER);
                    ArrayList<String> active = intent.getStringArrayListExtra(
                            ConnectivityManager.EXTRA_ACTIVE_TETHER);
                    sendMessage(CMD_TETHER_STATE_CHANGE, new TetherStateChange(available, active));
                }
            },new IntentFilter(ConnectivityManager.ACTION_TETHER_STATE_CHANGED));

        IntentFilter screenFilter = new IntentFilter();
        screenFilter.addAction(Intent.ACTION_SCREEN_ON);
        screenFilter.addAction(Intent.ACTION_SCREEN_OFF);
        BroadcastReceiver screenReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();

                if (action.equals(Intent.ACTION_SCREEN_ON)) {
                    handleScreenStateChanged(true);
                } else if (action.equals(Intent.ACTION_SCREEN_OFF)) {
                    handleScreenStateChanged(false);
                }
            }
        };
        mContext.registerReceiver(screenReceiver, screenFilter);

        mContext.getContentResolver().registerContentObserver(Settings.Global.getUriFor(
                Settings.Global.ETHERNET_SUSPEND_OPTIMIZATIONS_ENABLED), false,
                new ContentObserver(getHandler()) {
                    @Override
                    public void onChange(boolean selfChange) {
                        mUserWantsSuspendOpt.set(Settings.Global.getInt(mContext.getContentResolver(),
                                Settings.Global.ETHERNET_SUSPEND_OPTIMIZATIONS_ENABLED, 1) == 1);
                    }
                });

        PowerManager powerManager = (PowerManager)mContext.getSystemService(Context.POWER_SERVICE);
        mWakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG);

        mSuspendWakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "EthernetSuspend");
        mSuspendWakeLock.setReferenceCounted(false);

        addState(mDefaultState);
            addState(mInitialState, mDefaultState);
            addState(mDriverUnloadingState, mDefaultState);
            addState(mDriverUnloadedState, mDefaultState);
                addState(mDriverFailedState, mDriverUnloadedState);
            addState(mDriverLoadingState, mDefaultState);
            addState(mDriverLoadedState, mDefaultState);
                addState(mConnectModeState, mDdefaultState);
                    addState(mL2ConnectedState, mConnectModeState);
                        addState(mObtainingIpState, mL2ConnectedState);
                        addState(mCaptivePortalCheckState, mL2ConnectedState);
                        addState(mConnectedState, mL2ConnectedState);
                    addState(mDisconnectingState, mConnectModeState);
                    addState(mDisconnectedState, mConnectModeState);
            addState(mTetheringState, mDefaultState);
            addState(mTetheredState, mDefaultState);

        setInitialState(mInitialState);

        setLogRecSize(100);
        if (DBG) setDbg(true);

        //start the state machine
        start();
    }

    /*********************************************************
     * Methods exposed for public use
     ********************************************************/

    public Messenger getMessenger() {
        return new Messenger(getHandler());
    }

    /**
     * TODO: doc
     */
    public void setEthernetEnabled(boolean enable) {
        mLastEnableUid.set(Binder.getCallingUid());
        if (enable) {
            /* Argument is the state that is entered prior to load */
            sendMessage(obtainMessage(CMD_LOAD_DRIVER, ETHERNET_STATE_ENABLING, 0));
        } else {
            /* Argument is the state that is entered upon success */
            sendMessage(obtainMessage(CMD_UNLOAD_DRIVER, ETHERNET_STATE_DISABLED, 0));
        }
    }

    /**
     * TODO: doc
     */
    public int syncGetEthernetState() {
        return mEthernetState.get();
    }

    /**
     * TODO: doc
     */
    public String syncGetEthernetStateByName() {
        switch (mEthernetState.get()) {
            case ETHERNET_STATE_DISABLING:
                return "disabling";
            case ETHERNET_STATE_DISABLED:
                return "disabled";
            case ETHERNET_STATE_ENABLING:
                return "enabling";
            case ETHERNET_STATE_ENABLED:
                return "enabled";
            case ETHERNET_STATE_UNKNOWN:
                return "unknown state";
            default:
                return "[invalid state]";
        }
    }

    /**
     * Get status information for the current connection, if any.
     * @return a {@link EthernetInfo} object containing information about the current connection
     *
     */
    public EthernetInfo syncRequestConnectionInfo() {
        return mEthernetInfo;
    }

    public DhcpInfo syncGetDhcpInfo() {
        synchronized (mDhcpInfoInternal) {
            return mDhcpInfoInternal.makeDhcpInfo();
        }
    }

    public void captivePortalCheckComplete() {
        sendMessage(obtainMessage(CMD_CAPTIVE_CHECK_COMPLETE));
    }

    /**
     * Disconnect from link
     */
    public void disconnectCommand() {
        sendMessage(CMD_DISCONNECT);
    }

    /**
     * Initiate a reconnection
     */
    public void reconnectCommand() {
        sendMessage(CMD_RECONNECT);
    }

    /**
     * Add a network synchronously
     *
     * @return network id of the new network
     */
    public int syncAddOrUpdateNetwork(AsyncChannel channel, EthernetConfiguration config) {
        Message resultMsg = channel.sendMessageSynchronously(CMD_ADD_OR_UPDATE_NETWORK, config);
        int result = resultMsg.arg1;
        resultMsg.recycle();
        return result;
    }

    public List<EthernetConfiguration> syncGetConfiguredNetworks(AsyncChannel channel) {
        Message resultMsg = channel.sendMessageSynchronously(CMD_GET_CONFIGURED_NETWORKS);
        List<EthernetConfiguration> result = (List<EthernetConfiguration>) resultMsg.obj;
        resultMsg.recycle();
        return result;
    }

    /**
     * Delete a network
     *
     * @param networkId id of the network to be removed
     */
    public boolean syncRemoveNetwork(AsyncChannel channel, int networkId) {
        Message resultMsg = channel.sendMessageSynchronously(CMD_REMOVE_NETWORK, networkId);
        boolean result = (resultMsg.arg1 != FAILURE);
        resultMsg.recycle();
        return result;
    }

    /**
     * Enable a network
     *
     * @param netId network id of the network
     * @param disableOthers true, if all other networks have to be disabled
     * @return {@code true} if the operation succeeds, {@code false} otherwise
     */
    public boolean syncEnableNetwork(AsyncChannel channel, int netId, boolean disableOthers) {
        Message resultMsg = channel.sendMessageSynchronously(CMD_ENABLE_NETWORK, netId,
                disableOthers ? 1 : 0);
        boolean result = (resultMsg.arg1 != FAILURE);
        resultMsg.recycle();
        return result;
    }

    /**
     * Disable a network
     *
     * @param netId network id of the network
     * @return {@code true} if the operation succeeds, {@code false} otherwise
     */
    public boolean syncDisableNetwork(AsyncChannel channel, int netId) {
        Message resultMsg = channel.sendMessageSynchronously(EthernetManager.DISABLE_NETWORK, netId);
        boolean result = (resultMsg.arg1 != EthernetManager.DISABLE_NETWORK_FAILED);
        resultMsg.recycle();
        return result;
    }

    public void enableAllNetworks() {
        sendMessage(CMD_ENABLE_ALL_NETWORKS);
    }

    /**
     * Start filtering Multicast v4 packets
     */
    public void startFilteringMulticastV4Packets() {
        mFilteringMulticastV4Packets.set(true);
        sendMessage(obtainMessage(CMD_START_PACKET_FILTERING, MULTICAST_V4, 0));
    }

    /**
     * Stop filtering Multicast v4 packets
     */
    public void stopFilteringMulticastV4Packets() {
        mFilteringMulticastV4Packets.set(false);
        sendMessage(obtainMessage(CMD_STOP_PACKET_FILTERING, MULTICAST_V4, 0));
    }

    /**
     * Start filtering Multicast v4 packets
     */
    public void startFilteringMulticastV6Packets() {
        sendMessage(obtainMessage(CMD_START_PACKET_FILTERING, MULTICAST_V6, 0));
    }

    /**
     * Stop filtering Multicast v4 packets
     */
    public void stopFilteringMulticastV6Packets() {
        sendMessage(obtainMessage(CMD_STOP_PACKET_FILTERING, MULTICAST_V6, 0));
    }

    /**
     * Returns the ethernet configuration file
     */
    public String getConfigFile() {
        return mEthernetConfigStore.getConfigFile();
    }

    /**
     * Save configuration
     *
     * @return {@code true} if the operation succeeds, {@code false} otherwise
     *
     * TODO: deprecate this
     */
    public boolean syncSaveConfig(AsyncChannel channel) {
        Message resultMsg = channel.sendMessageSynchronously(CMD_SAVE_CONFIG);
        boolean result = (resultMsg.arg1 != FAILURE);
        resultMsg.recycle();
        return result;
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        String LS = System.getProperty("line.separator");
        sb.append("current HSM state: ").append(getCurrentState().getName()).append(LS);
        sb.append("mLinkProperties ").append(mLinkProperties).append(LS);
        sb.append("mEthernetInfo ").append(mEthernetInfo).append(LS);
        sb.append("mDhcpInfoInternal ").append(mDhcpInfoInternal).append(LS);
        sb.append("mNetworkInfo ").append(mNetworkInfo).append(LS);
        sb.append("mLastNetworkId ").append(mLastNetworkId).append(LS);
        sb.append("mReconnectCount ").append(mReconnectCount).append(LS);
        sb.append("mUserWantsSuspendOpt ").append(mUserWantsSuspendOpt).append(LS);
        sb.append("mSuspendOptNeedsDisabled ").append(mSuspendOptNeedsDisabled).append(LS);

        sb.append(mEthernetConfigStore.dump());
        return sb.toString();
    }

    @Override
    protected boolean recordLogRec(Message msg) {
        //Ignore screen on/off & common messages when driver has started
        if (getCurrentState() == mConnectedState || getCurrentState() == mDisconnectedState) {
            switch (msg.what) {
                case CMD_LOAD_DRIVER:
	        case CMD_SET_HIGH_PERF_MODE:
                case CMD_SET_SUSPEND_OPT_ENABLED:
                case CMD_ENABLE_ALL_NETWORKS:
                return false;
            }
        }

	return true;
    }

    /*********************************************************
     * Internal private functions
     ********************************************************/

    private void handleScreenStateChanged(boolean screenOn) {
        if (DBG) log("handleScreenStateChanged: " + screenOn);
        if (screenOn) enableAllNetworks();
        if (mUserWantsSuspendOpt.get()) {
            if (screenOn) {
                sendMessage(obtainMessage(CMD_SET_SUSPEND_OPT_ENABLED, 0, 0));
            } else {
                //Allow 2s for suspend optimizations to be set
                mSuspendWakeLock.acquire(2000);
                sendMessage(obtainMessage(CMD_SET_SUSPEND_OPT_ENABLED, 1, 0));
            }
        }
        mScreenBroadcastReceived.set(true);
    }

    private void checkAndSetConnectivityInstance() {
        if (mCm == null) {
            mCm = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        }
    }

    private boolean startTethering(ArrayList<String> available) {

        checkAndSetConnectivityInstance();

        String[] ethernetRegexs = mCm.getTetherableEthernetRegexs();

        for (String intf : available) {
            for (String regex : ethernetRegexs) {
                if (intf.matches(regex)) {

                    InterfaceConfiguration ifcg = null;
                    try {
                        ifcg = mNwService.getInterfaceConfig(intf);
                        if (ifcg != null) {
                            /* IP/netmask: 192.168.49.1/255.255.255.0 */
                            ifcg.setLinkAddress(new LinkAddress(
                                    NetworkUtils.numericToInetAddress("192.168.49.1"), 24));
                            ifcg.setInterfaceUp();

                            mNwService.setInterfaceConfig(intf, ifcg);
                        }
                    } catch (Exception e) {
                        loge("Error configuring interface " + intf + ", :" + e);
                        return false;
                    }

                    if(mCm.tether(intf) != ConnectivityManager.TETHER_ERROR_NO_ERROR) {
                        loge("Error tethering on " + intf);
                        return false;
                    }
                    mTetherInterfaceName = intf;
                    return true;
                }
            }
        }
        // We found no interfaces to tether
        return false;
    }

    private void stopTethering() {

        checkAndSetConnectivityInstance();

        /* Clear the interface config to allow dhcp correctly configure new
           ip settings */
        InterfaceConfiguration ifcg = null;
        try {
            ifcg = mNwService.getInterfaceConfig(mTetherInterfaceName);
            if (ifcg != null) {
                ifcg.setLinkAddress(
                        new LinkAddress(NetworkUtils.numericToInetAddress("0.0.0.0"), 0));
                mNwService.setInterfaceConfig(mTetherInterfaceName, ifcg);
            }
        } catch (Exception e) {
            loge("Error resetting interface " + mTetherInterfaceName + ", :" + e);
        }

        if (mCm.untether(mTetherInterfaceName) != ConnectivityManager.TETHER_ERROR_NO_ERROR) {
            loge("Untether initiate failed!");
        }
    }

    private boolean isEthernetTethered(ArrayList<String> active) {

        checkAndSetConnectivityInstance();

        String[] ethernetRegexs = mCm.getTetherableEthernetRegexs();
        for (String intf : active) {
            for (String regex : ethernetRegexs) {
                if (intf.matches(regex)) {
                    return true;
                }
            }
        }
        // We found no interfaces that are tethered
        return false;
    }

    private void setSuspendOptimizationsNative(int reason, boolean enabled) {
        if (DBG) log("setSuspendOptimizationsNative: " + reason + " " + enabled);
        if (enabled) {
            mSuspendOptNeedsDisabled &= ~reason;
            /* None of dhcp, screen or highperf need it disabled and user wants it enabled */
            if (mSuspendOptNeedsDisabled == 0 && mUserWantsSuspendOpt.get()) {
                mEthernetNative.setSuspendOptimizations(true);
            }
        } else {
            mSuspendOptNeedsDisabled |= reason;
            mEthernetNative.setSuspendOptimizations(false);
        }
    }

    private void setSuspendOptimizations(int reason, boolean enabled) {
        if (DBG) log("setSuspendOptimizations: " + reason + " " + enabled);
        if (enabled) {
            mSuspendOptNeedsDisabled &= ~reason;
        } else {
            mSuspendOptNeedsDisabled |= reason;
        }
        if (DBG) log("mSuspendOptNeedsDisabled " + mSuspendOptNeedsDisabled);
    }

    private void setEthernetState(int ethernetState) {
        final int previousEthernetState = mEthernetState.get();

        try {
            if (ethernetState == ETHERNET_STATE_ENABLED) {
                mBatteryStats.noteEthernetOn();
            } else if (ethernetState == ETHERNET_STATE_DISABLED) {
                mBatteryStats.noteEthernetOff();
            }
        } catch (RemoteException e) {
            loge("Failed to note battery stats in ethernet");
        }

        mEthernetState.set(ethernetState);

        if (DBG) log("setEthernetState: " + syncGetEthernetStateByName());

        final Intent intent = new Intent(EthernetManager.ETHERNET_STATE_CHANGED_ACTION);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        intent.putExtra(EthernetManager.EXTRA_ETHERNET_STATE, ethernetState);
        intent.putExtra(EthernetManager.EXTRA_PREVIOUS_ETHERNET_STATE, previousEthernetState);
        mContext.sendStickyBroadcastAsUser(intent, UserHandle.ALL);
    }

    private void configureLinkProperties() {
        if (mEthernetConfigStore.isUsingStaticIp(mLastNetworkId)) {
            mLinkProperties = mEthernetConfigStore.getLinkProperties(mLastNetworkId);
        } else {
            synchronized (mDhcpInfoInternal) {
                mLinkProperties = mDhcpInfoInternal.makeLinkProperties();
            }
            mLinkProperties.setHttpProxy(mEthernetConfigStore.getProxyProperties(mLastNetworkId));
        }
        mLinkProperties.setInterfaceName(mInterfaceName);
        if (DBG) {
            log("netId=" + mLastNetworkId  + " Link configured: " +
                    mLinkProperties.toString());
        }
    }

    private int getMaxDhcpRetries() {
        return Settings.Global.getInt(mContext.getContentResolver(),
                                      Settings.Global.ETHERNET_MAX_DHCP_RETRY_COUNT,
                                      DEFAULT_MAX_DHCP_RETRIES);
    }

    private void sendNetworkStateChangeBroadcast() {
        Intent intent = new Intent(EthernetManager.NETWORK_STATE_CHANGED_ACTION);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        intent.putExtra(EthernetManager.EXTRA_NETWORK_INFO, new NetworkInfo(mNetworkInfo));
        intent.putExtra(EthernetManager.EXTRA_LINK_PROPERTIES, new LinkProperties (mLinkProperties));
        if (mNetworkInfo.getDetailedState() == DetailedState.CONNECTED) {
            intent.putExtra(EthernetManager.EXTRA_ETHERNET_INFO, new EthernetInfo(mEthernetInfo));
        }
        mContext.sendStickyBroadcastAsUser(intent, UserHandle.ALL);
    }

    private void sendLinkConfigurationChangedBroadcast() {
        Intent intent = new Intent(EthernetManager.LINK_CONFIGURATION_CHANGED_ACTION);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        intent.putExtra(EthernetManager.EXTRA_LINK_PROPERTIES, new LinkProperties(mLinkProperties));
        mContext.sendBroadcastAsUser(intent, UserHandle.ALL);
    }

    /**
     * Record the detailed state of a network.
     * @param state the new {@code DetailedState}
     */
    private void setNetworkDetailedState(NetworkInfo.DetailedState state) {
        if (DBG) {
            log("setDetailed state, old ="
                    + mNetworkInfo.getDetailedState() + " and new state=" + state);
        }

        if (state != mNetworkInfo.getDetailedState()) {
            mNetworkInfo.setDetailedState(state, null, mEthernetInfo.getSSID());
        }
    }

    private DetailedState getNetworkDetailedState() {
        return mNetworkInfo.getDetailedState();
    }

    /**
     * Resets the Ethernet Connections by clearing any state, resetting any sockets
     * using the interface, stopping DHCP & disabling interface
     */
    private void handleNetworkDisconnect() {
        if (DBG) log("Stopping DHCP and clearing IP");

        /*
         * stop DHCP
         */
        if (mDhcpStateMachine != null) {
            /* In case we were in middle of DHCP operation
               restore back powermode */
            handlePostDhcpSetup();
            mDhcpStateMachine.sendMessage(DhcpStateMachine.CMD_STOP_DHCP);
        }

        try {
            mNwService.clearInterfaceAddresses(mInterfaceName);
            mNwService.disableIpv6(mInterfaceName);
        } catch (Exception e) {
            loge("Failed to clear addresses or disable ipv6" + e);
        }

        /* Reset data structures */
        mEthernetInfo.setInetAddress(null);
        mEthernetInfo.setName(null);
        mEthernetInfo.setNetworkId(EthernetConfiguration.INVALID_NETWORK_ID);
        mEthernetInfo.setLinkSpeed(-1);

        setNetworkDetailedState(DetailedState.DISCONNECTED);
        mEthernetConfigStore.updateStatus(mLastNetworkId, DetailedState.DISCONNECTED);

        /* send event to CM & network change broadcast */
        sendNetworkStateChangeBroadcast(mLastBssid);

        /* Clear network properties */
        mLinkProperties.clear();

        /* Clear IP settings if the network used DHCP */
        if (!mEthernetConfigStore.isUsingStaticIp(mLastNetworkId)) {
            mEthernetConfigStore.clearIpConfiguration(mLastNetworkId);
        }

        mLastNetworkId = EthernetConfiguration.INVALID_NETWORK_ID;
    }

    void handlePreDhcpSetup() {
        /* Disable power save and suspend optimizations during DHCP */
        setSuspendOptimizationsNative(SUSPEND_DUE_TO_DHCP, false);
        mEthernetNative.setPowerSave(false);
    }

    void handlePostDhcpSetup() {
        /* Restore power save and suspend optimizations */
        setSuspendOptimizationsNative(SUSPEND_DUE_TO_DHCP, true);
        mEthernetNative.setPowerSave(true);
    }

    private void handleSuccessfulIpConfiguration(DhcpInfoInternal dhcpInfoInternal) {
        synchronized (mDhcpInfoInternal) {
            mDhcpInfoInternal = dhcpInfoInternal;
        }
        mReconnectCount = 0; //Reset IP failure tracking
        mEthernetConfigStore.setIpConfiguration(mLastNetworkId, dhcpInfoInternal);
        InetAddress addr = NetworkUtils.numericToInetAddress(dhcpInfoInternal.ipAddress);
        mEthernetInfo.setInetAddress(addr);
        if (getNetworkDetailedState() == DetailedState.CONNECTED) {
            //DHCP renewal in connected state
            LinkProperties linkProperties = dhcpInfoInternal.makeLinkProperties();
            linkProperties.setHttpProxy(mEthernetConfigStore.getProxyProperties(mLastNetworkId));
            linkProperties.setInterfaceName(mInterfaceName);
            if (!linkProperties.equals(mLinkProperties)) {
                if (DBG) {
                    log("Link configuration changed for netId: " + mLastNetworkId
                            + " old: " + mLinkProperties + "new: " + linkProperties);
                }
                mLinkProperties = linkProperties;
                sendLinkConfigurationChangedBroadcast();
            }
        } else {
            configureLinkProperties();
        }
    }

    private void handleFailedIpConfiguration() {
        loge("IP configuration failed");

        mEthernetInfo.setInetAddress(null);
        /**
         * If we've exceeded the maximum number of retries for DHCP
         * to a given network, disable the network
         */
        int maxRetries = getMaxDhcpRetries();
        // maxRetries == 0 means keep trying forever
        if (maxRetries > 0 && ++mReconnectCount > maxRetries) {
            loge("Failed " +
                    mReconnectCount + " times, Disabling " + mLastNetworkId);
            mEthernetConfigStore.disableNetwork(mLastNetworkId,
                    EthernetConfiguration.DISABLED_DHCP_FAILURE);
            mReconnectCount = 0;
        }

        /* DHCP times out after about 30 seconds, we do a
         * disconnect and an immediate reconnect to try again
         */
        mEthernetNative.disconnect();
        mEthernetNative.reconnect();
    }

    /********************************************************
     * HSM states
     *******************************************************/

    class DefaultState extends State {
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch (message.what) {
                case CMD_ENABLE_NETWORK:
                case CMD_ADD_OR_UPDATE_NETWORK:
                case CMD_REMOVE_NETWORK:
                case CMD_SAVE_CONFIG:
                    replyToMessage(message, message.what, FAILURE);
                    break;
                case CMD_GET_CONFIGURED_NETWORKS:
                    replyToMessage(message, message.what, (List<EthernetConfiguration>) null);
                    break;
                case CMD_SET_HIGH_PERF_MODE:
                    if (message.arg1 == 1) {
                        setSuspendOptimizations(SUSPEND_DUE_TO_HIGH_PERF, false);
                    } else {
                        setSuspendOptimizations(SUSPEND_DUE_TO_HIGH_PERF, true);
                    }
                    break;
                    /* Discard */
                case CMD_LOAD_DRIVER:
                case CMD_UNLOAD_DRIVER:
                case CMD_TETHER_STATE_CHANGE:
                case CMD_TETHER_NOTIFICATION_TIMED_OUT:
                case CMD_DISCONNECT:
                case CMD_RECONNECT:
                case EthernetMonitor.NETWORK_CONNECTION_EVENT:
                case EthernetMonitor.NETWORK_DISCONNECTION_EVENT:
                case CMD_ENABLE_ALL_NETWORKS:
                case DhcpStateMachine.CMD_PRE_DHCP_ACTION:
                case DhcpStateMachine.CMD_POST_DHCP_ACTION:
                    break;
                case DhcpStateMachine.CMD_ON_QUIT:
                    mDhcpStateMachine = null;
                    break;
                case CMD_SET_SUSPEND_OPT_ENABLED:
                    if (message.arg1 == 1) {
                        mSuspendWakeLock.release();
                        setSuspendOptimizations(SUSPEND_DUE_TO_SCREEN, true);
                    } else {
                        setSuspendOptimizations(SUSPEND_DUE_TO_SCREEN, false);
                    }
                    break;
                case EthernetManager.CONNECT_NETWORK:
                    replyToMessage(message, EthernetManager.CONNECT_NETWORK_FAILED,
                            EthernetManager.BUSY);
                    break;
                case EthernetManager.FORGET_NETWORK:
                    replyToMessage(message, EthernetManager.FORGET_NETWORK_FAILED,
                            EthernetManager.BUSY);
                    break;
                case EthernetManager.SAVE_NETWORK:
                    replyToMessage(message, EthernetManager.SAVE_NETWORK_FAILED,
                            EthernetManager.BUSY);
                    break;
                case EthernetManager.DISABLE_NETWORK:
                    replyToMessage(message, EthernetManager.DISABLE_NETWORK_FAILED,
                            EthernetManager.BUSY);
                    break;
                default:
                    loge("Error! unhandled message" + message);
                    break;
            }
            return HANDLED;
        }
    }

    class InitialState extends State {
        @Override
        //TODO: could move logging into a common class
        public void enter() {
            if (DBG) log(getName() + "\n");
            // [31-8] Reserved for future use
            // [7 - 0] HSM state change
            // 50031 ethernet_state_changed (custom|1|5)
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());

            if (mEthernetNative.isDriverLoaded()) {
                transitionTo(mDriverLoadedState);
            }
            else {
                transitionTo(mDriverUnloadedState);
            }

            /* IPv6 is disabled at boot time and is controlled by framework
             * to be enabled only as long as we are connected
             *
             * This fixes issues, a few being:
             * - IPv6 addresses and routes stick around after disconnection
             * - When connected, the kernel is unaware and can fail to start IPv6 negotiation
             * - The kernel sometimes starts autoconfiguration when 802.3 is not complete
             */
            try {
                mNwService.disableIpv6(mInterfaceName);
            } catch (RemoteException re) {
                loge("Failed to disable IPv6: " + re);
            } catch (IllegalStateException e) {
                loge("Failed to disable IPv6: " + e);
            }
        }
    }

    class DriverLoadingState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());

            final Message message = new Message();
            message.copyFrom(getCurrentMessage());

            new Thread(new Runnable() {
                public void run() {
                    mWakeLock.acquire();
                    //enabling state
                    switch(message.arg1) {
                        case ETHERNET_STATE_ENABLING:
                            setEthernetState(ETHERNET_STATE_ENABLING);
                            break;
                        case ETHERNET_AP_STATE_ENABLING:
                            setEthernetApState(ETHERNET_AP_STATE_ENABLING);
                            break;
                    }

                    if(mEthernetNative.loadDriver()) {
                        if (DBG) log("Driver load successful");
                        sendMessage(CMD_LOAD_DRIVER_SUCCESS);
                    } else {
                        loge("Failed to load driver!");
                        switch(message.arg1) {
                            case ETHERNET_STATE_ENABLING:
                                setEthernetState(ETHERNET_STATE_UNKNOWN);
                                break;
			    default:
                                break;
                        }
                        sendMessage(CMD_LOAD_DRIVER_FAILURE);
                    }
                    mWakeLock.release();
                }
            }).start();
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch (message.what) {
                case CMD_LOAD_DRIVER_SUCCESS:
                    transitionTo(mDriverLoadedState);
                    break;
                case CMD_LOAD_DRIVER_FAILURE:
                    transitionTo(mDriverFailedState);
                    break;
                case CMD_LOAD_DRIVER:
                case CMD_UNLOAD_DRIVER:
                case CMD_START_PACKET_FILTERING:
                case CMD_STOP_PACKET_FILTERING:
                    deferMessage(message);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    class DriverLoadedState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch(message.what) {
                case CMD_UNLOAD_DRIVER:
                    transitionTo(mDriverUnloadingState);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    class DriverUnloadingState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());

            final Message message = new Message();
            message.copyFrom(getCurrentMessage());
            new Thread(new Runnable() {
                public void run() {
                    if (DBG) log(getName() + message.toString() + "\n");
                    mWakeLock.acquire();
                    if(mEthernetNative.unloadDriver()) {
                        if (DBG) log("Driver unload successful");
                        sendMessage(CMD_UNLOAD_DRIVER_SUCCESS);

                        switch(message.arg1) {
                            case ETHERNET_STATE_DISABLED:
                            case ETHERNET_STATE_UNKNOWN:
                                setEthernetState(message.arg1);
                                break;
                        }
                    } else {
                        loge("Failed to unload driver!");
                        sendMessage(CMD_UNLOAD_DRIVER_FAILURE);

                        switch(message.arg1) {
                            case ETHERNET_STATE_DISABLED:
                            case ETHERNET_STATE_UNKNOWN:
                                setEthernetState(ETHERNET_STATE_UNKNOWN);
                                break;
                        }
                    }
                    mWakeLock.release();
                }
            }).start();
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch (message.what) {
                case CMD_UNLOAD_DRIVER_SUCCESS:
                    transitionTo(mDriverUnloadedState);
                    break;
                case CMD_UNLOAD_DRIVER_FAILURE:
                    transitionTo(mDriverFailedState);
                    break;
                case CMD_LOAD_DRIVER:
                case CMD_UNLOAD_DRIVER:
                case CMD_START_PACKET_FILTERING:
                case CMD_STOP_PACKET_FILTERING:
                    deferMessage(message);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    class DriverUnloadedState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch (message.what) {
                case CMD_LOAD_DRIVER:
                    transitionTo(mDriverLoadingState);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    class DriverFailedState extends State {
        @Override
        public void enter() {
            loge(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            return NOT_HANDLED;
        }
    }

    class ConnectModeState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            StateChangeResult stateChangeResult;
            switch(message.what) {
                case CMD_DISCONNECT:
                    mEthernetNative.disconnect();
                    break;
                case CMD_RECONNECT:
                    mEthernetNative.reconnect();
                    break;
                case EthernetManager.CONNECT_NETWORK:
                    /* The connect message can contain a network id passed as arg1 on message or
                     * or a config passed as obj on message.
                     * For a new network, a config is passed to create and connect.
                     * For an existing network, a network id is passed
                     */
                    int netId = message.arg1;
                    EthernetConfiguration config = (EthernetConfiguration) message.obj;

                    /* Save the network config */
                    if (config != null) {
                        NetworkUpdateResult result = mEthernetConfigStore.saveNetwork(config);
                        netId = result.getNetworkId();
                    }

                    if (mEthernetConfigStore.selectNetwork(netId) &&
                            mEthernetNative.reconnect()) {
                        /* The state tracker handles enabling networks upon completion/failure */
                        mSupplicantStateTracker.sendMessage(EthernetManager.CONNECT_NETWORK);
                        replyToMessage(message, EthernetManager.CONNECT_NETWORK_SUCCEEDED);
                        /* Expect a disconnection from the old connection */
                        transitionTo(mDisconnectingState);
                    } else {
                        loge("Failed to connect config: " + config + " netId: " + netId);
                        replyToMessage(message, EthernetManager.CONNECT_NETWORK_FAILED,
                                EthernetManager.ERROR);
                        break;
                    }
                    break;
                case EthernetMonitor.NETWORK_CONNECTION_EVENT:
                    if (DBG) log("Network connection established");
                    mLastNetworkId = message.arg1;
                    mLastName = (String) message.obj;

                    mEthernetInfo.setName(mLastName);
                    mEthernetInfo.setNetworkId(mLastNetworkId);
                    /* send event to CM & network change broadcast */
                    setNetworkDetailedState(DetailedState.OBTAINING_IPADDR);
                    sendNetworkStateChangeBroadcast(mLastName);
                    transitionTo(mObtainingIpState);
                    break;
                case EthernetMonitor.NETWORK_DISCONNECTION_EVENT:
                    if (DBG) log("Network connection lost");
                    handleNetworkDisconnect();
                    transitionTo(mDisconnectedState);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    class L2ConnectedState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch (message.what) {
              case DhcpStateMachine.CMD_PRE_DHCP_ACTION:
                  handlePreDhcpSetup();
                  mDhcpStateMachine.sendMessage(DhcpStateMachine.CMD_PRE_DHCP_ACTION_COMPLETE);
                  break;
              case DhcpStateMachine.CMD_POST_DHCP_ACTION:
                  handlePostDhcpSetup();
                  if (message.arg1 == DhcpStateMachine.DHCP_SUCCESS) {
                      if (DBG) log("DHCP successful");
                      handleSuccessfulIpConfiguration((DhcpInfoInternal) message.obj);
                      transitionTo(mCaptivePortalCheckState);
                  } else if (message.arg1 == DhcpStateMachine.DHCP_FAILURE) {
                      if (DBG) log("DHCP failed");
                      handleFailedIpConfiguration();
                      transitionTo(mDisconnectingState);
                  }
                  break;
                case CMD_DISCONNECT:
                    mEthernetNative.disconnect();
                    transitionTo(mDisconnectingState);
                    break;
                case EthernetManager.CONNECT_NETWORK:
                    int netId = message.arg1;
                    if (mEthernetInfo.getNetworkId() == netId) {
                        break;
                    }
                    return NOT_HANDLED;
                case EthernetManager.SAVE_NETWORK:
                    EthernetConfiguration config = (EthernetConfiguration) message.obj;
                    NetworkUpdateResult result = mEthernetConfigStore.saveNetwork(config);
                    if (mEthernetInfo.getNetworkId() == result.getNetworkId()) {
                        if (result.hasIpChanged()) {
                            log("Reconfiguring IP on connection");
                            transitionTo(mObtainingIpState);
                        }
                        if (result.hasProxyChanged()) {
                            log("Reconfiguring proxy on connection");
                            configureLinkProperties();
                            sendLinkConfigurationChangedBroadcast();
                        }
                    }

                    if (result.getNetworkId() != EthernetConfiguration.INVALID_NETWORK_ID) {
                        replyToMessage(message, EthernetManager.SAVE_NETWORK_SUCCEEDED);
                    } else {
                        loge("Failed to save network");
                        replyToMessage(message, EthernetManager.SAVE_NETWORK_FAILED,
                                EthernetManager.ERROR);
                    }
                    break;
                    /* Ignore */
                case EthernetMonitor.NETWORK_CONNECTION_EVENT:
                    break;
                default:
                    return NOT_HANDLED;
            }

            return HANDLED;
        }
    }

    class ObtainingIpState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());

            if (!mEthernetConfigStore.isUsingStaticIp(mLastNetworkId)) {
                //start DHCP
                if (mDhcpStateMachine == null) {
                    mDhcpStateMachine = DhcpStateMachine.makeDhcpStateMachine(
                            mContext, EthernetStateMachine.this, mInterfaceName);

                }
                mDhcpStateMachine.registerForPreDhcpNotification();
                mDhcpStateMachine.sendMessage(DhcpStateMachine.CMD_START_DHCP);
            } else {
                DhcpInfoInternal dhcpInfoInternal = mEthernetConfigStore.getIpConfiguration(
                        mLastNetworkId);
                InterfaceConfiguration ifcg = new InterfaceConfiguration();
                ifcg.setLinkAddress(dhcpInfoInternal.makeLinkAddress());
                ifcg.setInterfaceUp();
                try {
                    mNwService.setInterfaceConfig(mInterfaceName, ifcg);
                    if (DBG) log("Static IP configuration succeeded");
                    sendMessage(CMD_STATIC_IP_SUCCESS, dhcpInfoInternal);
                } catch (RemoteException re) {
                    loge("Static IP configuration failed: " + re);
                    sendMessage(CMD_STATIC_IP_FAILURE);
                } catch (IllegalStateException e) {
                    loge("Static IP configuration failed: " + e);
                    sendMessage(CMD_STATIC_IP_FAILURE);
                }
            }
        }
      @Override
      public boolean processMessage(Message message) {
          if (DBG) log(getName() + message.toString() + "\n");
          switch(message.what) {
            case CMD_STATIC_IP_SUCCESS:
                  handleSuccessfulIpConfiguration((DhcpInfoInternal) message.obj);
                  transitionTo(mCaptivePortalCheckState);
                  break;
              case CMD_STATIC_IP_FAILURE:
                  handleFailedIpConfiguration();
                  transitionTo(mDisconnectingState);
                  break;
             case EthernetManager.SAVE_NETWORK:
                  deferMessage(message);
                  break;
                  /* Defer any power mode changes since we must keep active power mode at DHCP */
              case CMD_SET_HIGH_PERF_MODE:
                  deferMessage(message);
                  break;
              default:
                  return NOT_HANDLED;
          }
          return HANDLED;
      }
    }

    class CaptivePortalCheckState extends State {
        @Override
        public void enter() {
            setNetworkDetailedState(DetailedState.CAPTIVE_PORTAL_CHECK);
            mEthernetConfigStore.updateStatus(mLastNetworkId, DetailedState.CAPTIVE_PORTAL_CHECK);
            sendNetworkStateChangeBroadcast(mLastName);
        }
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CMD_CAPTIVE_CHECK_COMPLETE:
                    try {
                        mNwService.enableIpv6(mInterfaceName);
                    } catch (RemoteException re) {
                        loge("Failed to enable IPv6: " + re);
                    } catch (IllegalStateException e) {
                        loge("Failed to enable IPv6: " + e);
                    }
                    setNetworkDetailedState(DetailedState.CONNECTED);
                    mEthernetConfigStore.updateStatus(mLastNetworkId, DetailedState.CONNECTED);
                    sendNetworkStateChangeBroadcast(mLastName);
                    transitionTo(mConnectedState);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    class ConnectedState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
       }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
	    return NOT_HANDLED;
        }
        @Override
        public void exit() {
            /* Request a CS wakelock during transition to mobile */
            checkAndSetConnectivityInstance();
            mCm.requestNetworkTransitionWakelock(TAG);
        }
    }

    class DisconnectingState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
	    return NOT_HANDLED;
        }
    }

    class DisconnectedState extends State {
        private boolean mAlarmEnabled = false;
        /* This is set from the overlay config file or from a secure setting.
         * A value of 0 disables scanning in the framework.
         */

        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            boolean ret = HANDLED;
            switch (message.what) {
                case EthernetManager.FORGET_NETWORK:
                case CMD_REMOVE_NETWORK:
                    sendMessageDelayed(obtainMessage(CMD_NO_NETWORKS_PERIODIC_SCAN,
                                ++mPeriodicScanToken, 0), mSupplicantScanIntervalMs);
                    ret = NOT_HANDLED;
                    break;
                case EthernetMonitor.NETWORK_DISCONNECTION_EVENT:
                    break;
                case CMD_RECONNECT:
                    if (mTemporarilyDisconnectEthernet) ret = NOT_HANDLED;
                    break;
                default:
                    ret = NOT_HANDLED;
            }
            return ret;
        }
    }

    class TetheringState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());

            /* Send ourselves a delayed message to shut down if tethering fails to notify */
            sendMessageDelayed(obtainMessage(CMD_TETHER_NOTIFICATION_TIMED_OUT,
                    ++mTetherToken, 0), TETHER_NOTIFICATION_TIME_OUT_MSECS);
        }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch(message.what) {
                case CMD_TETHER_STATE_CHANGE:
                    TetherStateChange stateChange = (TetherStateChange) message.obj;
                    if (isEthernetTethered(stateChange.active)) {
                        transitionTo(mTetheredState);
                    }
                    return HANDLED;
                case CMD_TETHER_NOTIFICATION_TIMED_OUT:
                    if (message.arg1 == mTetherToken) {
                        loge("Failed to get tether update, shutdown soft access point");
                    }
                    break;
                case CMD_LOAD_DRIVER:
                case CMD_UNLOAD_DRIVER:
                case CMD_START_PACKET_FILTERING:
                case CMD_STOP_PACKET_FILTERING:
                    deferMessage(message);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    class TetheredState extends State {
        @Override
        public void enter() {
            if (DBG) log(getName() + "\n");
            EventLog.writeEvent(EVENTLOG_ETHERNET_STATE_CHANGED, getName());
        }
        @Override
        public boolean processMessage(Message message) {
            if (DBG) log(getName() + message.toString() + "\n");
            switch(message.what) {
                case CMD_TETHER_STATE_CHANGE:
                    TetherStateChange stateChange = (TetherStateChange) message.obj;
                    if (!isEthernetTethered(stateChange.active)) {
                        loge("Tethering reports ethernet as untethered!, shut down soft Ap");
                    }
                    return HANDLED;
                case CMD_STOP_AP:
                    if (DBG) log("Untethering before stopping AP");
                    setEthernetApState(ETHERNET_AP_STATE_DISABLING);
                    stopTethering();
                    transitionTo(mSoftApStoppingState);
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    //State machine initiated requests can have replyTo set to null indicating
    //there are no recepients, we ignore those reply actions
    private void replyToMessage(Message msg, int what) {
        if (msg.replyTo == null) return;
        Message dstMsg = obtainMessageWithArg2(msg);
        dstMsg.what = what;
        mReplyChannel.replyToMessage(msg, dstMsg);
    }

    private void replyToMessage(Message msg, int what, int arg1) {
        if (msg.replyTo == null) return;
        Message dstMsg = obtainMessageWithArg2(msg);
        dstMsg.what = what;
        dstMsg.arg1 = arg1;
        mReplyChannel.replyToMessage(msg, dstMsg);
    }

    private void replyToMessage(Message msg, int what, Object obj) {
        if (msg.replyTo == null) return;
        Message dstMsg = obtainMessageWithArg2(msg);
        dstMsg.what = what;
        dstMsg.obj = obj;
        mReplyChannel.replyToMessage(msg, dstMsg);
    }

    /**
     * arg2 on the source message has a unique id that needs to be retained in replies
     * to match the request
     *
     * see EthernetManager for details
     */
    private Message obtainMessageWithArg2(Message srcMsg) {
        Message msg = Message.obtain();
        msg.arg2 = srcMsg.arg2;
        return msg;
    }

    private void log(String s) {
        Log.d(TAG, s);
    }

    private void loge(String s) {
        Log.e(TAG, s);
    }
}
