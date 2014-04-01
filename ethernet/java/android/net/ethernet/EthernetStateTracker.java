/*
 * Copyright (C) 2010 The Android-X86 Open Source Project
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
 *
 * Author: Yi Sun <beyounn@gmail.com>
 */

package android.net.ethernet;

import android.text.TextUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;

import android.R;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.bluetooth.BluetoothHeadset;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.BroadcastReceiver;
import android.net.LinkCapabilities;
import android.net.LinkProperties;
import android.net.ConnectivityManager;
import android.net.NetworkStateTracker;
import android.net.NetworkUtils;
import android.net.LinkCapabilities;
import android.net.NetworkInfo;
import android.net.RouteInfo;
import android.net.InterfaceConfiguration;
import android.net.LinkAddress;
import android.net.NetworkInfo.DetailedState;
import android.net.NetworkInfo.State;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.Parcel;
import android.os.SystemProperties;
import android.os.IBinder;
import android.os.INetworkManagementService;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.*;
import java.util.Collection;
import java.util.Collections;
import java.util.ArrayList;
import java.net.Inet4Address;
import android.net.SamplingDataTracker;
import android.os.Message;
import android.os.Messenger;
import android.net.LinkQualityInfo;
import android.net.DhcpResults;


import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Track the state of Ethernet connectivity. All event handling is done here,
 * and all changes in connectivity state are initiated here.
 * 
 * @hide
 */

public class EthernetStateTracker extends Handler implements NetworkStateTracker {
    private static final String TAG = "EthernetStateTracker";
    private static final String NETWORKTYPE = "ETHERNET";

    public static final int EVENT_DHCP_START              = 0;
    public static final int EVENT_CONFIGURATION_SUCCEEDED = 1;
    public static final int EVENT_CONFIGURATION_FAILED    = 2;
    public static final int EVENT_ADD_ADDR                = 3;
    public static final int EVENT_DEL_ADDR                = 4;
    public static final int EVENT_PHY_DISCONNECTED        = 5;
    public static final int EVENT_PHY_CONNECTED           = 6;
    public static final int EVENT_INIT                    = 7;


	private static final boolean		localLOGV = true;
	private boolean				mSystemReady = false;
	private boolean				mInitialBroadcast;
	private AtomicBoolean				mTeardownRequested = new AtomicBoolean(false);
	private AtomicBoolean				mPrivateDnsRouteSet = new AtomicBoolean(false);
	private AtomicBoolean				mDefaultRouteSet = new AtomicBoolean(false);
	private EthernetManager				mEM;
	private boolean						mServiceStarted;
	private NetworkInfo					mNetworkInfo;
	private boolean						mInterfaceStopped;
	private boolean						mPhyConnected;
	private boolean						mHWConfigured;
	private INetworkManagementService	mNwService;
	private DhcpHandler					mDhcpTarget;
	private String						mInterfaceName;
	private DhcpResults			mDhcpResults;
	private EthernetMonitor				mMonitor;
	private String[]					sDnsPropNames;
	private NotificationManager			mNotificationManager;
	private Notification				mNotification;
	private Handler						mTrackerTarget;
	private BroadcastReceiver			mEthernetStateReceiver;
	private LinkProperties				mLinkProperties;
	private LinkCapabilities mLinkCapabilities;

	/* For sending events to connectivity service handler */
	private Handler						mCsHandler;
	private Context						mContext;

	private EthernetStateTracker(Context context) {
		mNetworkInfo = new NetworkInfo(ConnectivityManager.TYPE_ETHERNET, 0, NETWORKTYPE, "");
		if (localLOGV)
			Slog.v(TAG, "Starts...");
		mLinkProperties = new LinkProperties();
		mLinkCapabilities = new LinkCapabilities();
		mContext = context;

		if (EthernetNative.initEthernetNative() != 0) {
			Slog.e(TAG, "Can not init ethernet device layers");
			return;
		}

		mPhyConnected = false;
		mHWConfigured = false;

		IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
		mNwService = INetworkManagementService.Stub.asInterface(b);

		if (localLOGV)
			Slog.v(TAG, "Successed");
		mServiceStarted = true;
		HandlerThread dhcpThread = new HandlerThread("DHCP Handler Thread");
		dhcpThread.start();
		mDhcpTarget = new DhcpHandler(dhcpThread.getLooper(), this);
		mMonitor = new EthernetMonitor(this);
		mDhcpResults = new DhcpResults();
	}

	private static EthernetStateTracker sInstance;

	public static synchronized EthernetStateTracker getInstance(Context context) {
        	if (sInstance == null) {
			sInstance = new EthernetStateTracker(context);
		}
		return sInstance;
	}

	/**
	 * Stop etherent interface
	 * 
	 * @param suspend
	 *            {@code false} disable the interface {@code true} only reset
	 *            the connection without disable the interface
	 * @return true
	 */
	public boolean stopInterface(boolean suspend) {
		if (mEM != null) {
			EthernetDevInfo info = mEM.getSavedConfig();
			if (info != null && mEM.isConfigured()) {
				synchronized (mDhcpTarget) {
					mInterfaceStopped = true;
					if (localLOGV)
						Slog.i(TAG, "stop dhcp and interface");
					mDhcpTarget.removeMessages(EVENT_DHCP_START);
					String ifname = info.getIfName();

					if (!NetworkUtils.stopDhcp(ifname)) {
						if (localLOGV)
							Slog.w(TAG, "Could not stop DHCP");
					}
					NetworkUtils.resetConnections(ifname, NetworkUtils.RESET_ALL_ADDRESSES);

					try {
						mNwService.clearInterfaceAddresses(mInterfaceName);
					} catch (Exception e) {
						Slog.e(TAG, "Failed to clear addresses" + e);
					}

					if (!suspend)
						NetworkUtils.disableInterface(ifname);
				}
			}
		}
		return true;
	}


	private boolean configureInterface(EthernetDevInfo info) throws UnknownHostException {
		mInterfaceStopped = false;

		if (info.getConnectMode().equals(EthernetDevInfo.ETHERNET_CONN_MODE_DHCP)) {
			if (localLOGV)
				Slog.i(TAG, "trigger dhcp for device " + info.getIfName());
			mLinkProperties.clear();
			sDnsPropNames = new String[] { "dhcp." + mInterfaceName + ".dns1", "dhcp." + mInterfaceName + ".dns2" };

			mDhcpTarget.sendEmptyMessage(EVENT_DHCP_START);
		} else {

			this.sendEmptyMessage(EVENT_CONFIGURATION_FAILED);
			Slog.e(TAG, "Static IP configuration succeeded not implemented!");
		}
		return true;
	}

	/**
	 * reset ethernet interface
	 * 
	 * @return true
	 * @throws UnknownHostException
	 */
	public boolean resetInterface() throws UnknownHostException {
		/*
		 * This will guide us to enabled the enabled device
		 */
		if (mEM != null) {
			EthernetDevInfo info = mEM.getSavedConfig();
			if (info != null && mEM.isConfigured()) {
				synchronized (this) {
					mInterfaceName = info.getIfName();
					if (localLOGV)
						Slog.i(TAG, "reset device " + mInterfaceName);
					NetworkUtils.enableInterface(mInterfaceName);
					NetworkUtils.resetConnections(mInterfaceName, NetworkUtils.RESET_ALL_ADDRESSES);
					// Stop DHCP
					if (mDhcpTarget != null) {
						mDhcpTarget.removeMessages(EVENT_DHCP_START);
					}
					if (!NetworkUtils.stopDhcp(mInterfaceName)) {
						if (localLOGV)
							Slog.w(TAG, "Could not stop DHCP");
					}
					if (mPhyConnected)
						configureInterface(info);
				}
			}
		}
		return true;
	}

	/*
	 * HFM
	 * @Override public String[] getNameServers() { return
	 * getNameServerList(sDnsPropNames); }
	 */
	@Override
	public String getTcpBufferSizesPropName() {
		return "net.tcp.buffersize.default";
	}

	public void StartPolling() {
		mMonitor.startMonitoring();
	}

	@Override
	public boolean isAvailable() {
		// Only say available if we have interfaces and user did not disable us.
		return ((mEM.getTotalInterface() != 0) && (mEM.getState() != EthernetManager.ETHERNET_STATE_DISABLED));
	}

	@Override
	public boolean reconnect() {
		try {
			synchronized (this) {
				if (mHWConfigured && mPhyConnected)
					return true;
			}
			if (mEM.getState() != EthernetManager.ETHERNET_STATE_DISABLED) {
				// maybe this is the first time we run, so set it to enabled
				mEM.setEnabled(true);
				if (!mEM.isConfigured()) {
					mEM.setDefaultConf();
				}
				return resetInterface();
			}
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return false;

	}

	@Override
	public boolean setRadio(boolean turnOn) {
		return false;
	}

	@Override
	public void startMonitoring(Context context, Handler target) {
		if (localLOGV)
			Slog.v(TAG, "start to monitor the ethernet devices");
		if (mServiceStarted) {
			mEM = (EthernetManager) context.getSystemService(Context.ETHERNET_SERVICE);
			mContext = context;
			mCsHandler = target;

			// IntentFilter filter = new IntentFilter();
			// filter.addAction(EthernetManager.NETWORK_STATE_CHANGED_ACTION);

			// mEthernetStateReceiver = new EthernetStateReceiver();
			// mContext.registerReceiver(mEthernetStateReceiver, filter);
			int state = mEM.getState();
			if (state != mEM.ETHERNET_STATE_DISABLED) {
				if (state == mEM.ETHERNET_STATE_UNKNOWN) {
					Slog.v(TAG, "state == mEM.ETHERNET_STATE_UNKNOWN");
					// maybe this is the first time we run, so set it to enabled
					mEM.setEnabled(mEM.getDeviceNameList() != null);
				} else {
					Slog.v(TAG, "state == mEM.ETHERNET_STATE_ENABLED");
					try {
						updateState(EVENT_INIT);
						resetInterface();
					} catch (UnknownHostException e) {
						Slog.e(TAG, "Wrong ethernet configuration");
					}
				}
			}
		}
	}

	/*
	 * HFM
	 * @Override public int startUsingNetworkFeature(String feature, int
	 * callingPid, int callingUid) { return 0; }
	 * @Override public int stopUsingNetworkFeature(String feature, int
	 * callingPid, int callingUid) { return 0; }
	 */
	@Override
	public boolean teardown() {
		return (mEM != null) ? stopInterface(false) : false;
	}

	private void postNotification(int event) {
		Message msg = mCsHandler.obtainMessage(EVENT_STATE_CHANGED, new NetworkInfo(mNetworkInfo));
		msg.sendToTarget();
	}

	private void updateState(int event) {
		DetailedState newState;

		switch (event) {
		case EVENT_CONFIGURATION_SUCCEEDED:
		case EVENT_ADD_ADDR:
			mHWConfigured = true;
			newState = DetailedState.CONNECTED;
			break;
		case EVENT_CONFIGURATION_FAILED:
			mHWConfigured = false;
			newState = DetailedState.FAILED;
			break;
		case EVENT_PHY_DISCONNECTED:
			mHWConfigured = false;
			mPhyConnected = false;
			newState = DetailedState.DISCONNECTED;
			stopInterface(true);
			break;
		case EVENT_PHY_CONNECTED:
			mPhyConnected = true;
			newState = DetailedState.OBTAINING_IPADDR;
			break;
		case EVENT_INIT:
			newState = DetailedState.IDLE;
			break;
		default:
			newState = DetailedState.FAILED;
			Slog.e(TAG, "Unexpected nevent " + event);
			return;
		}

		if ((newState != mNetworkInfo.getDetailedState()) || (event == EVENT_INIT)) {
			if (localLOGV)
				Slog.i(TAG, "event: " + event + "  " + mNetworkInfo.getDetailedState() + " ==> " + newState);
			mNetworkInfo.setDetailedState(newState, null, null);
			mNetworkInfo.setIsAvailable(mNetworkInfo.getState() == State.CONNECTED);
			broadcastState();
			postNotification(event);
		}
	}

	public void handleMessage(Message msg) {

		synchronized (this) {
			switch (msg.what) {
			case EVENT_CONFIGURATION_SUCCEEDED:
			case EVENT_CONFIGURATION_FAILED:
			case EVENT_ADD_ADDR:
			case EVENT_PHY_DISCONNECTED:
				updateState(msg.what);
				break;

			case EVENT_PHY_CONNECTED:
				try {
					resetInterface();
				} catch (UnknownHostException e) {
					Slog.e(TAG, "Failed to reset Ethernet");
				}

				mPhyConnected = true;
				if (mNetworkInfo.getDetailedState() != DetailedState.OBTAINING_IPADDR) {
					int state = mEM.getState();
					if (state != mEM.ETHERNET_STATE_DISABLED) {
						EthernetDevInfo info = mEM.getSavedConfig();
						if (info != null && mEM.isConfigured()) {
							try {
								updateState(msg.what);
								configureInterface(info);
							} catch (UnknownHostException e) {
								// TODO Auto-generated catch block
								// e.printStackTrace();
								Slog.e(TAG, "Cannot configure interface");
							}
						} else {
							Slog.e(TAG, "Failed to get saved IP configuration");
						}
					}
				}
				break;
			}
		}
	}

	private class DhcpHandler extends Handler {
		public DhcpHandler(Looper looper, Handler target) {
			super(looper);
			mTrackerTarget = target;
		}

		public void handleMessage(Message msg) {
		   int event;

		   switch (msg.what) {
		   case EVENT_DHCP_START:
			synchronized (mDhcpTarget) {
				if (!mInterfaceStopped) {
					if (localLOGV)
						Slog.d(TAG, "DhcpHandler: DHCP request started");
					if (NetworkUtils.runDhcp(mInterfaceName, mDhcpResults)) {
						mLinkProperties = mDhcpResults.linkProperties;
						mLinkProperties.setInterfaceName(mInterfaceName);
						event = EVENT_CONFIGURATION_SUCCEEDED;
						if (localLOGV)
							Slog.d(TAG, "DhcpHandler: DHCP request succeeded: " + mDhcpResults.toString());
					} else {
						event = EVENT_CONFIGURATION_FAILED;
						Slog.e(TAG, "DhcpHandler: DHCP request failed: " + NetworkUtils.getDhcpError());
					}
					mTrackerTarget.sendEmptyMessage(event);
				} else {
					mInterfaceStopped = false;
				}
			} /* synchronized */
			break;
		   } /* switch */
		} /* handleMessage */
	}

	public void notifyStateChange(String ifname, int event) {
		if (localLOGV)
			Slog.i(TAG, "report event " + event + " on dev " + ifname);
		if (ifname.equals(mInterfaceName)) {
			if (localLOGV)
				Slog.v(TAG, "update network state tracker");
			synchronized (this) {
				this.sendEmptyMessage(event);
			}
		}
	}

	private static int lookupHost(String hostname) {
		InetAddress inetAddress;
		try {
			inetAddress = InetAddress.getByName(hostname);
		} catch (UnknownHostException e) {
			return -1;
		}
		byte[] addrBytes;
		int addr;
		addrBytes = inetAddress.getAddress();
		addr = ((addrBytes[3] & 0xff) << 24) | ((addrBytes[2] & 0xff) << 16) | ((addrBytes[1] & 0xff) << 8)
				| (addrBytes[0] & 0xff);
		return addr;
	}

	public void setDependencyMet(boolean met) {
		// not supported on this network
	}

	/* HFM stubs */
	public void setUserDataEnable(boolean enabled) {
		Slog.w(TAG, "ignoring setUserDataEnable(" + enabled + ")");
	}

	public void setDataEnable(boolean enabled) {
	}

	public void setPolicyDataEnable(boolean enabled) {
	}

	public void setTeardownRequested(boolean isRequested) {
		mTeardownRequested.set(isRequested);
	}

	public boolean isTeardownRequested() {
		return mTeardownRequested.get();
	}

	/**
	 * Check if private DNS route is set for the network
	 */
	public boolean isPrivateDnsRouteSet() {
		return mPrivateDnsRouteSet.get();
	}

	/**
	 * Set a flag indicating private DNS route is set
	 */
	public void privateDnsRouteSet(boolean enabled) {
		mPrivateDnsRouteSet.set(enabled);
	}

	/**
	 * Fetch NetworkInfo for the network
	 */
	public NetworkInfo getNetworkInfo() {
		return new NetworkInfo(mNetworkInfo);
	}

	/**
	 * Fetch LinkProperties for the network
	 */
	public LinkProperties getLinkProperties() {
		return new LinkProperties(mLinkProperties);
	}

	/**
	 * A capability is an Integer/String pair, the capabilities are defined in
	 * the class LinkSocket#Key.
	 * 
	 * @return a copy of this connections capabilities, may be empty but never
	 *         null.
	 */
	public LinkCapabilities getLinkCapabilities() {
		return new LinkCapabilities();
	}

	/**
	 * Check if default route is set
	 */
	public boolean isDefaultRouteSet() {
		return mDefaultRouteSet.get();
	}

	/**
	 * Set a flag indicating default route is set for the network
	 */
	public void defaultRouteSet(boolean enabled) {
		mDefaultRouteSet.set(enabled);
	}

	public void systemReady() {
		mSystemReady = true;
		if (mInitialBroadcast) {
			mInitialBroadcast = false;
			broadcastState();
		}
	}

	public void broadcastState() {
		if (mSystemReady) {
			Slog.i(TAG, "Broadcasting Ethernet: " + mEM.getState() + " " + mNetworkInfo.getDetailedState());
			Intent intent = new Intent(EthernetManager.ETHERNET_STATE_CHANGED_ACTION);
			intent.putExtra(EthernetManager.EXTRA_NETWORK_INFO, mNetworkInfo);
			intent.putExtra(EthernetManager.EXTRA_ETHERNET_STATE, mEM.getState());
			mContext.sendStickyBroadcast(intent);
		} else {
			mInitialBroadcast = true;
		}
	}

    @Override
    public void addStackedLink(LinkProperties link) {
        mLinkProperties.addStackedLink(link);
    }

    @Override
    public void removeStackedLink(LinkProperties link) {
        mLinkProperties.removeStackedLink(link);
    }

    @Override
    public void supplyMessenger(Messenger messenger) {
        // not supported on this network
    }

    @Override
    public void startSampling(SamplingDataTracker.SamplingSnapshot s) {
        // nothing to do
    }

    @Override
    public void stopSampling(SamplingDataTracker.SamplingSnapshot s) {
        // nothing to do
    }

    @Override
    public String getNetworkInterfaceName() {
        if (mLinkProperties != null) {
            return mLinkProperties.getInterfaceName();
        } else {
            return null;
        }
    }
    /**
     * Captive check is complete, switch to network
     */
    @Override
    public void captivePortalCheckComplete() {
        // not implemented
    }

    @Override
    public void captivePortalCheckCompleted(boolean isCaptivePortal) {
        // not implemented
    }

    /**
     * Return link info
     * @return an object of type WifiLinkQualityInfo
     */
    @Override
    public LinkQualityInfo getLinkQualityInfo() {
        // not implemented
        return null;
    }

}
