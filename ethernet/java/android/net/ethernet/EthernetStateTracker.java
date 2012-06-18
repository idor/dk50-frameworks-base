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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.LinkCapabilities;
import android.net.LinkProperties;
import android.net.NetworkInfo;
import android.net.NetworkInfo.DetailedState;
import android.net.NetworkStateTracker;
import android.os.Handler;
import android.os.Message;
import android.util.Slog;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Track the state of ethernet for connectivity service.
 *
 * @hide
 */
public class EthernetStateTracker implements NetworkStateTracker {

    private static final String NETWORKTYPE = "ETHERNET";
    private static final String TAG = "EthernetStateTracker";

    private static final boolean LOGV = true;

    private AtomicBoolean mTeardownRequested = new AtomicBoolean(false);
    private AtomicBoolean mPrivateDnsRouteSet = new AtomicBoolean(false);
    private AtomicBoolean mDefaultRouteSet = new AtomicBoolean(false);

    private LinkProperties mLinkProperties;
    private LinkCapabilities mLinkCapabilities;
    private NetworkInfo mNetworkInfo;
    private NetworkInfo.State mLastState = NetworkInfo.State.UNKNOWN;

    /* For sending events to connectivity service handler */
    private Handler mCsHandler;
    private Context mContext;
    private BroadcastReceiver mEthernetStateReceiver;
    private EthernetManager mEthernetManager;

    public EthernetStateTracker(int netType, String networkName) {
        mNetworkInfo = new NetworkInfo(netType, 0, networkName, "");
        mLinkProperties = new LinkProperties();
        mLinkCapabilities = new LinkCapabilities();

        mNetworkInfo.setIsAvailable(false);
        setTeardownRequested(false);
    }


    public void setTeardownRequested(boolean isRequested) {
        mTeardownRequested.set(isRequested);
    }

    public boolean isTeardownRequested() {
        return mTeardownRequested.get();
    }

    /**
     * Begin monitoring ethernet connectivity
     */
    public void startMonitoring(Context context, Handler target) {
        mCsHandler = target;
        mContext = context;

        mEthernetManager = (EthernetManager) mContext.getSystemService(Context.ETHERNET_SERVICE);
        IntentFilter filter = new IntentFilter();
        filter.addAction(EthernetManager.NETWORK_STATE_CHANGED_ACTION);
        filter.addAction(EthernetManager.LINK_CONFIGURATION_CHANGED_ACTION);

        mEthernetStateReceiver = new EthernetStateReceiver();
        mContext.registerReceiver(mEthernetStateReceiver, filter);
    }

    /**
     * Disable connectivity to a network
     */
    public boolean teardown() {
        mTeardownRequested.set(true);
        mEthernetManager.stopEthernet();
        return true;
    }

    /**
     * Re-enable connectivity to a network after a {@link #teardown()}.
     */
    public boolean reconnect() {
        mTeardownRequested.set(false);
        mEthernetManager.startEthernet();
        return true;
    }

    /**
     * Captive check is complete, switch to network
     */
    @Override
    public void captivePortalCheckComplete() {
        mEthernetManager.captivePortalCheckComplete();
    }

    /**
     * Turn the wireless radio off for a network.
     * @param turnOn {@code true} to turn the radio on, {@code false}
     */
    public boolean setRadio(boolean turnOn) {
	mEthernetManager.setEthernetEnabled(turnOn);	
	return true;
    }

    /**
     * Ethernet is considered available as long as there is at least one
     * enabled network. If a teardown was explicitly requested, then Ethernet
     * can be restarted with a reconnect request, so it is considered available.
     * If the driver has been stopped for any reason other than a teardown
     * request, Ethernet is considered unavailable.
     * @return {@code true} if Ethernet connections are possible
     */
    public boolean isAvailable() {
        return mNetworkInfo.isAvailable();
    }

    @Override
    public void setUserDataEnable(boolean enabled) {
        Slog.w(TAG, "ignoring setUserDataEnable(" + enabled + ")");
    }

    @Override
    public void setPolicyDataEnable(boolean enabled) {
        // ignored
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
     * A capability is an Integer/String pair, the capabilities
     * are defined in the class LinkSocket#Key.
     *
     * @return a copy of this connections capabilities, may be empty but never null.
     */
    public LinkCapabilities getLinkCapabilities() {
        return new LinkCapabilities(mLinkCapabilities);
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

    /**
     * Return the system properties name associated with the tcp buffer sizes
     * for this network.
     */
    public String getTcpBufferSizesPropName() {
        return "net.tcp.buffersize.ethernet";
    }

    private class EthernetStateReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {

            if (intent.getAction().equals(EthernetManager.NETWORK_STATE_CHANGED_ACTION)) {
                mNetworkInfo = (NetworkInfo) intent.getParcelableExtra(
                        EthernetManager.EXTRA_NETWORK_INFO);
                mLinkProperties = intent.getParcelableExtra(
                        EthernetManager.EXTRA_LINK_PROPERTIES);
                if (mLinkProperties == null) {
                    mLinkProperties = new LinkProperties();
                }
                mLinkCapabilities = intent.getParcelableExtra(
                        EthernetManager.EXTRA_LINK_CAPABILITIES);
                if (mLinkCapabilities == null) {
                    mLinkCapabilities = new LinkCapabilities();
                }
                // don't want to send redundent state messages
                // but send portal check detailed state notice
                NetworkInfo.State state = mNetworkInfo.getState();
                if (mLastState == state &&
                        mNetworkInfo.getDetailedState() != DetailedState.CAPTIVE_PORTAL_CHECK) {
                    return;
                } else {
                    mLastState = state;
                }
                Message msg = mCsHandler.obtainMessage(EVENT_STATE_CHANGED,
                        new NetworkInfo(mNetworkInfo));
                msg.sendToTarget();
            } else if (intent.getAction().equals(EthernetManager.LINK_CONFIGURATION_CHANGED_ACTION)) {
                mLinkProperties = (LinkProperties) intent.getParcelableExtra(
                        EthernetManager.EXTRA_LINK_PROPERTIES);
                Message msg = mCsHandler.obtainMessage(EVENT_CONFIGURATION_CHANGED, mNetworkInfo);
                msg.sendToTarget();
            }
        }
    }

    public void setDependencyMet(boolean met) {
        // not supported on this network
    }
}
