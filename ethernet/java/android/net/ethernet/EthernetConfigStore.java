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

import android.content.Context;
import android.content.Intent;
import android.net.DhcpInfoInternal;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.NetworkUtils;
import android.net.NetworkInfo.DetailedState;
import android.net.ProxyProperties;
import android.net.RouteInfo;
import android.net.ethernet.EthernetConfiguration.IpAssignment;
import android.net.ethernet.EthernetConfiguration.ProxySettings;
import android.net.ethernet.NetworkUpdateResult;
import static android.net.ethernet.EthernetConfiguration.INVALID_NETWORK_ID;
import android.os.Environment;
import android.os.Message;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.UserHandle;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class provides the API to manage configured
 * ethernet networks. The API is not thread safe is being
 * used only from EthernetStateMachine.
 *
 * It deals with the following
 * - Add/update/remove a EthernetConfiguration
 *   The configuration contains the following type of information.
 *     = IP and proxy configuration that is handled by EthernetConfigStore and
 *       is saved to disk on any change.
 *
 *       The format of configuration file is as follows:
 *       <version>
 *       <netA_key1><netA_value1><netA_key2><netA_value2>...<EOS>
 *       <netB_key1><netB_value1><netB_key2><netB_value2>...<EOS>
 *       ..
 *
 *       (key, value) pairs for a given network are grouped together and can
 *       be in any order. A EOS at the end of a set of (key, value) pairs
 *       indicates that the next set of (key, value) pairs are for a new
 *       network. A network is identified by a unique ID_KEY. If there is no
 *       ID_KEY in the (key, value) pairs, the data is discarded.
 *
 *       An invalid version on read would result in discarding the contents of
 *       the file. On the next write, the latest version is written to file.
 *
 *       Any failures during read or write to the configuration file are ignored
 *       without reporting to the user since the likelihood of these errors are
 *       low and the impact on connectivity is low.
 *
 *       We have two kinds of APIs exposed:
 *        > public API calls that provide fine grained control
 *          - enableNetwork, disableNetwork, addOrUpdateNetwork(),
 *          removeNetwork(). For these calls, the config is not persisted
 *          to the disk. (TODO: deprecate these calls in EthernetManager)
 *        > The new API calls - selectNetwork(), saveNetwork() & forgetNetwork().
 *          These calls persist the supplicant config to disk.
 *
 * - Maintain a list of configured networks for quick access
 *
 */
class EthernetConfigStore {

    private Context mContext;
    private static final String TAG = "EthernetConfigStore";
    private static final boolean DBG = false;

    /* configured networks with network id as the key */
    private HashMap<Integer, EthernetConfiguration> mConfiguredNetworks =
            new HashMap<Integer, EthernetConfiguration>();

    /* A network id is a unique identifier for a configured network.
     * We store the IP configuration for networks along with a unique id
     * that is generated from network name.
     */
    private HashMap<Integer, Integer> mNetworkIds =
            new HashMap<Integer, Integer>();

    /* Tracks the highest priority of configured networks */
    private int mLastPriority = -1;

    private static final String ipConfigFile = Environment.getDataDirectory() +
            "/misc/ethernet/ipconfig.txt";

    private static final int IPCONFIG_FILE_VERSION = 2;

    /* IP and proxy configuration keys */
    private static final String ID_KEY = "id";
    private static final String IP_ASSIGNMENT_KEY = "ipAssignment";
    private static final String LINK_ADDRESS_KEY = "linkAddress";
    private static final String GATEWAY_KEY = "gateway";
    private static final String DNS_KEY = "dns";
    private static final String PROXY_SETTINGS_KEY = "proxySettings";
    private static final String PROXY_HOST_KEY = "proxyHost";
    private static final String PROXY_PORT_KEY = "proxyPort";
    private static final String EXCLUSION_LIST_KEY = "exclusionList";
    private static final String EOS = "eos";

    private EthernetNative mEthernetNative;

    EthernetConfigStore(Context c, EthernetNative wn) {
        mContext = c;
        mEthernetNative = wn;
    }

    /**
     * Fetch the list of configured networks
     * and enable all stored networks in supplicant.
     */
    void initialize() {
        if (DBG) log("Loading config and enabling all networks");
        loadConfiguredNetworks();
        enableAllNetworks();
    }

    /**
     * Fetch the list of currently configured networks
     * @return List of networks
     */
    List<EthernetConfiguration> getConfiguredNetworks() {
        List<EthernetConfiguration> networks = new ArrayList<EthernetConfiguration>();
        for(EthernetConfiguration config : mConfiguredNetworks.values()) {
            networks.add(new EthernetConfiguration(config));
        }
        return networks;
    }

    /**
     * enable all networks and save config. This will be a no-op if the list
     * of configured networks indicates all networks as being enabled
     */
    void enableAllNetworks() {
        boolean networkEnabledStateChanged = false;
        for(EthernetConfiguration config : mConfiguredNetworks.values()) {
            if(config != null && config.status == Status.DISABLED) {
                if(mEthernetNative.enableNetwork(config.networkId, false)) {
                    networkEnabledStateChanged = true;
                    config.status = Status.ENABLED;
                } else {
                    loge("Enable network failed on " + config.networkId);
                }
            }
        }

        if (networkEnabledStateChanged) {
            mEthernetNative.saveConfig();
            sendConfiguredNetworksChangedBroadcast();
        }
    }


    /**
     * Selects the specified network for connection. This involves
     * updating the priority of all the networks and enabling the given
     * network while disabling others.
     *
     * Selecting a network will leave the other networks disabled and
     * a call to enableAllNetworks() needs to be issued upon a connection
     * or a failure event from supplicant
     *
     * @param netId network to select for connection
     * @return false if the network id is invalid
     */
    boolean selectNetwork(int netId) {
        if (netId == INVALID_NETWORK_ID) return false;

        // Reset the priority of each network at start or if it goes too high.
        if (mLastPriority == -1 || mLastPriority > 1000000) {
            for(EthernetConfiguration config : mConfiguredNetworks.values()) {
                if (config.networkId != INVALID_NETWORK_ID) {
                    config.priority = 0;
                    addOrUpdateNetworkNative(config);
                }
            }
            mLastPriority = 0;
        }

        // Set to the highest priority and save the configuration.
        EthernetConfiguration config = new EthernetConfiguration();
        config.networkId = netId;
        config.priority = ++mLastPriority;

        addOrUpdateNetworkNative(config);
        mEthernetNative.saveConfig();

        /* Enable the given network while disabling all other networks */
        enableNetworkWithoutBroadcast(netId, true);

       /* Avoid saving the config & sending a broadcast to prevent settings
        * from displaying a disabled list of networks */
        return true;
    }

    /**
     * Add/update the specified configuration and save config
     *
     * @param config EthernetConfiguration to be saved
     * @return network update result
     */
    NetworkUpdateResult saveNetwork(EthernetConfiguration config) {
        // A new network cannot have null name
        if (config == null || (config.networkId == INVALID_NETWORK_ID &&
                config.networkName == null)) {
            return new NetworkUpdateResult(INVALID_NETWORK_ID);
        }

        boolean newNetwork = (config.networkId == INVALID_NETWORK_ID);
        NetworkUpdateResult result = addOrUpdateNetworkNative(config);
        int netId = result.getNetworkId();
        /* enable a new network */
        if (newNetwork && netId != INVALID_NETWORK_ID) {
            mEthernetNative.enableNetwork(netId, false);
            mConfiguredNetworks.get(netId).status = Status.ENABLED;
        }
        mEthernetNative.saveConfig();
        sendConfiguredNetworksChangedBroadcast(config, result.isNewNetwork() ?
                EthernetManager.CHANGE_REASON_ADDED : EthernetManager.CHANGE_REASON_CONFIG_CHANGE);
        return result;
    }

    void updateStatus(int netId, DetailedState state) {
        if (netId != INVALID_NETWORK_ID) {
            EthernetConfiguration config = mConfiguredNetworks.get(netId);
            if (config == null) return;
            switch (state) {
                case CONNECTED:
                    config.status = Status.CURRENT;
                    break;
                case DISCONNECTED:
                    //If network is already disabled, keep the status
                    if (config.status == Status.CURRENT) {
                        config.status = Status.ENABLED;
                    }
                    break;
                default:
                    //do nothing, retain the existing state
                    break;
            }
        }
    }

    /**
     * Forget the specified network and save config
     *
     * @param netId network to forget
     * @return {@code true} if it succeeds, {@code false} otherwise
     */
    boolean forgetNetwork(int netId) {
        if (mEthernetNative.removeNetwork(netId)) {
            mEthernetNative.saveConfig();
            EthernetConfiguration target = null;
            EthernetConfiguration config = mConfiguredNetworks.get(netId);
            if (config != null) {
                target = mConfiguredNetworks.remove(netId);
                mNetworkIds.remove(configKey(config));
            }
            if (target != null) {
                writeIpAndProxyConfigurations();
                sendConfiguredNetworksChangedBroadcast(target, EthernetManager.CHANGE_REASON_REMOVED);
            }
            return true;
        } else {
            loge("Failed to remove network " + netId);
            return false;
        }
    }

    /**
     * Add/update a network. Note that there is no saveConfig operation.
     * This function is retained for compatibility with the public
     * API. The more powerful saveNetwork() is used by the
     * state machine
     *
     * @param config ethernet configuration to add/update
     * @return network Id
     */
    int addOrUpdateNetwork(EthernetConfiguration config) {
        NetworkUpdateResult result = addOrUpdateNetworkNative(config);
        if (result.getNetworkId() != EthernetConfiguration.INVALID_NETWORK_ID) {
            sendConfiguredNetworksChangedBroadcast(mConfiguredNetworks.get(result.getNetworkId()),
                    result.isNewNetwork ? EthernetManager.CHANGE_REASON_ADDED :
                        EthernetManager.CHANGE_REASON_CONFIG_CHANGE);
        }
        return result.getNetworkId();
    }

    /**
     * Remove a network. Note that there is no saveConfig operation.
     * This function is retained for compatibility with the public
     * API. The more powerful forgetNetwork() is used by the
     * state machine for network removal
     *
     * @param netId network to be removed
     * @return {@code true} if it succeeds, {@code false} otherwise
     */
    boolean removeNetwork(int netId) {
        boolean ret = mEthernetNative.removeNetwork(netId);
        EthernetConfiguration config = null;
        if (ret) {
            config = mConfiguredNetworks.get(netId);
            if (config != null) {
                config = mConfiguredNetworks.remove(netId);
                mNetworkIds.remove(configKey(config));
            }
        }
        if (config != null) {
            sendConfiguredNetworksChangedBroadcast(config, EthernetManager.CHANGE_REASON_REMOVED);
        }
        return ret;
    }

    /**
     * Enable a network. Note that there is no saveConfig operation.
     * This function is retained for compatibility with the public
     * API. The more powerful selectNetwork()/saveNetwork() is used by the
     * state machine for connecting to a network
     *
     * @param netId network to be enabled
     * @return {@code true} if it succeeds, {@code false} otherwise
     */
    boolean enableNetwork(int netId, boolean disableOthers) {
        boolean ret = enableNetworkWithoutBroadcast(netId, disableOthers);
        if (disableOthers) {
            sendConfiguredNetworksChangedBroadcast();
        } else {
            EthernetConfiguration enabledNetwork = null;
            synchronized(mConfiguredNetworks) {
                enabledNetwork = mConfiguredNetworks.get(netId);
            }
            // check just in case the network was removed by someone else.
            if (enabledNetwork != null) {
                sendConfiguredNetworksChangedBroadcast(enabledNetwork,
                        EthernetManager.CHANGE_REASON_CONFIG_CHANGE);
            }
        }
        return ret;
    }

    boolean enableNetworkWithoutBroadcast(int netId, boolean disableOthers) {
        boolean ret = mEthernetNative.enableNetwork(netId, disableOthers);

        EthernetConfiguration config = mConfiguredNetworks.get(netId);
        if (config != null) config.status = Status.ENABLED;

        if (disableOthers) {
            markAllNetworksDisabledExcept(netId);
        }
        return ret;
    }

    /**
     * Disable a network. Note that there is no saveConfig operation.
     * @param netId network to be disabled
     * @return {@code true} if it succeeds, {@code false} otherwise
     */
    boolean disableNetwork(int netId) {
        return disableNetwork(netId, EthernetConfiguration.DISABLED_UNKNOWN_REASON);
    }

    /**
     * Disable a network. Note that there is no saveConfig operation.
     * @param netId network to be disabled
     * @param reason reason code network was disabled
     * @return {@code true} if it succeeds, {@code false} otherwise
     */
    boolean disableNetwork(int netId, int reason) {
        boolean ret = mEthernetNative.disableNetwork(netId);
        EthernetConfiguration network = null;
        EthernetConfiguration config = mConfiguredNetworks.get(netId);
        /* Only change the reason if the network was not previously disabled */
        if (config != null && config.status != Status.DISABLED) {
            config.status = Status.DISABLED;
            config.disableReason = reason;
            network = config;
        }
        if (network != null) {
            sendConfiguredNetworksChangedBroadcast(network,
                    EthernetManager.CHANGE_REASON_CONFIG_CHANGE);
        }
        return ret;
    }

    /**
     * Save the configured networks in supplicant to disk
     * @return {@code true} if it succeeds, {@code false} otherwise
     */
    boolean saveConfig() {
        return mEthernetNative.saveConfig();
    }

    /**
     * Fetch the link properties for a given network id
     * @return LinkProperties for the given network id
     */
    LinkProperties getLinkProperties(int netId) {
        EthernetConfiguration config = mConfiguredNetworks.get(netId);
        if (config != null) return new LinkProperties(config.linkProperties);
        return null;
    }

    /**
     * get IP configuration for a given network id
     * TODO: We cannot handle IPv6 addresses for configuration
     *       right now until NetworkUtils is fixed. When we do
     *       that, we should remove handling DhcpInfo and move
     *       to using LinkProperties
     * @return DhcpInfoInternal for the given network id
     */
    DhcpInfoInternal getIpConfiguration(int netId) {
        DhcpInfoInternal dhcpInfoInternal = new DhcpInfoInternal();
        LinkProperties linkProperties = getLinkProperties(netId);

        if (linkProperties != null) {
            Iterator<LinkAddress> iter = linkProperties.getLinkAddresses().iterator();
            if (iter.hasNext()) {
                LinkAddress linkAddress = iter.next();
                dhcpInfoInternal.ipAddress = linkAddress.getAddress().getHostAddress();
                for (RouteInfo route : linkProperties.getRoutes()) {
                    dhcpInfoInternal.addRoute(route);
                }
                dhcpInfoInternal.prefixLength = linkAddress.getNetworkPrefixLength();
                Iterator<InetAddress> dnsIterator = linkProperties.getDnses().iterator();
                dhcpInfoInternal.dns1 = dnsIterator.next().getHostAddress();
                if (dnsIterator.hasNext()) {
                    dhcpInfoInternal.dns2 = dnsIterator.next().getHostAddress();
                }
            }
        }
        return dhcpInfoInternal;
    }

    /**
     * set IP configuration for a given network id
     */
    void setIpConfiguration(int netId, DhcpInfoInternal dhcpInfo) {
        LinkProperties linkProperties = dhcpInfo.makeLinkProperties();

        EthernetConfiguration config = mConfiguredNetworks.get(netId);
        if (config != null) {
            // add old proxy details
            if(config.linkProperties != null) {
                linkProperties.setHttpProxy(config.linkProperties.getHttpProxy());
            }
            config.linkProperties = linkProperties;
        }
    }

    /**
     * clear IP configuration for a given network id
     * @param network id
     */
    void clearIpConfiguration(int netId) {
        EthernetConfiguration config = mConfiguredNetworks.get(netId);
        if (config != null && config.linkProperties != null) {
            // Clear everything except proxy
            ProxyProperties proxy = config.linkProperties.getHttpProxy();
            config.linkProperties.clear();
            config.linkProperties.setHttpProxy(proxy);
        }
    }

    /**
     * Fetch the proxy properties for a given network id
     * @param network id
     * @return ProxyProperties for the network id
     */
    ProxyProperties getProxyProperties(int netId) {
        LinkProperties linkProperties = getLinkProperties(netId);
        if (linkProperties != null) {
            return new ProxyProperties(linkProperties.getHttpProxy());
        }
        return null;
    }

    /**
     * Return if the specified network is using static IP
     * @param network id
     * @return {@code true} if using static ip for netId
     */
    boolean isUsingStaticIp(int netId) {
        EthernetConfiguration config = mConfiguredNetworks.get(netId);
        if (config != null && config.ipAssignment == IpAssignment.STATIC) {
            return true;
        }
        return false;
    }

    /**
     * Should be called when a single network configuration is made.
     * @param network The network configuration that changed.
     * @param reason The reason for the change, should be one of EthernetManager.CHANGE_REASON_ADDED,
     * EthernetManager.CHANGE_REASON_REMOVED, or EthernetManager.CHANGE_REASON_CHANGE.
     */
    private void sendConfiguredNetworksChangedBroadcast(EthernetConfiguration network,
            int reason) {
        Intent intent = new Intent(EthernetManager.CONFIGURED_NETWORKS_CHANGED_ACTION);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        intent.putExtra(EthernetManager.EXTRA_MULTIPLE_NETWORKS_CHANGED, false);
        intent.putExtra(EthernetManager.EXTRA_ETHERNET_CONFIGURATION, network);
        intent.putExtra(EthernetManager.EXTRA_CHANGE_REASON, reason);
        mContext.sendBroadcastAsUser(intent, UserHandle.ALL);
    }

    /**
     * Should be called when multiple network configuration changes are made.
     */
    private void sendConfiguredNetworksChangedBroadcast() {
        Intent intent = new Intent(EthernetManager.CONFIGURED_NETWORKS_CHANGED_ACTION);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        intent.putExtra(EthernetManager.EXTRA_MULTIPLE_NETWORKS_CHANGED, true);
        mContext.sendBroadcastAsUser(intent, UserHandle.ALL);
    }

    void loadConfiguredNetworks() {
        String listStr = mEthernetNative.listNetworks();
        mLastPriority = 0;

        mConfiguredNetworks.clear();
        mNetworkIds.clear();

        if (listStr == null)
            return;

        String[] lines = listStr.split("\n");
        // Skip the first line, which is a header
        for (int i = 1; i < lines.length; i++) {
            String[] result = lines[i].split("\t");
            // network-id | ssid | bssid | flags
            EthernetConfiguration config = new EthernetConfiguration();
            try {
                config.networkId = Integer.parseInt(result[0]);
            } catch(NumberFormatException e) {
                continue;
            }
            if (result.length > 3) {
                if (result[3].indexOf("[CURRENT]") != -1)
                    config.status = EthernetConfiguration.Status.CURRENT;
                else if (result[3].indexOf("[DISABLED]") != -1)
                    config.status = EthernetConfiguration.Status.DISABLED;
                else
                    config.status = EthernetConfiguration.Status.ENABLED;
            } else {
                config.status = EthernetConfiguration.Status.ENABLED;
            }
            readNetworkVariables(config);
            if (config.priority > mLastPriority) {
                mLastPriority = config.priority;
            }
            mConfiguredNetworks.put(config.networkId, config);
            mNetworkIds.put(configKey(config), config.networkId);
        }

        readIpAndProxyConfigurations();
        sendConfiguredNetworksChangedBroadcast();
    }

    /* Mark all networks except specified netId as disabled */
    private void markAllNetworksDisabledExcept(int netId) {
        for(EthernetConfiguration config : mConfiguredNetworks.values()) {
            if(config != null && config.networkId != netId) {
                if (config.status != Status.DISABLED) {
                    config.status = Status.DISABLED;
                    config.disableReason = EthernetConfiguration.DISABLED_UNKNOWN_REASON;
                }
            }
        }
    }

    private void markAllNetworksDisabled() {
        markAllNetworksDisabledExcept(INVALID_NETWORK_ID);
    }

    private void writeIpAndProxyConfigurations() {

        /* Make a copy */
        List<EthernetConfiguration> networks = new ArrayList<EthernetConfiguration>();
        for(EthernetConfiguration config : mConfiguredNetworks.values()) {
            networks.add(new EthernetConfiguration(config));
        }

        DelayedDiskWrite.write(networks);
    }

    private static class DelayedDiskWrite {

        private static HandlerThread sDiskWriteHandlerThread;
        private static Handler sDiskWriteHandler;
        /* Tracks multiple writes on the same thread */
        private static int sWriteSequence = 0;
        private static final String TAG = "DelayedDiskWrite";

        static void write (final List<EthernetConfiguration> networks) {

            /* Do a delayed write to disk on a seperate handler thread */
            synchronized (DelayedDiskWrite.class) {
                if (++sWriteSequence == 1) {
                    sDiskWriteHandlerThread = new HandlerThread("EthernetConfigThread");
                    sDiskWriteHandlerThread.start();
                    sDiskWriteHandler = new Handler(sDiskWriteHandlerThread.getLooper());
                }
            }

            sDiskWriteHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        onWriteCalled(networks);
                    }
                });
        }

        private static void onWriteCalled(List<EthernetConfiguration> networks) {

            DataOutputStream out = null;
            try {
                out = new DataOutputStream(new BufferedOutputStream(
                            new FileOutputStream(ipConfigFile)));

                out.writeInt(IPCONFIG_FILE_VERSION);

                for(EthernetConfiguration config : networks) {
                    boolean writeToFile = false;

                    try {
                        LinkProperties linkProperties = config.linkProperties;
                        switch (config.ipAssignment) {
                            case STATIC:
                                out.writeUTF(IP_ASSIGNMENT_KEY);
                                out.writeUTF(config.ipAssignment.toString());
                                for (LinkAddress linkAddr : linkProperties.getLinkAddresses()) {
                                    out.writeUTF(LINK_ADDRESS_KEY);
                                    out.writeUTF(linkAddr.getAddress().getHostAddress());
                                    out.writeInt(linkAddr.getNetworkPrefixLength());
                                }
                                for (RouteInfo route : linkProperties.getRoutes()) {
                                    out.writeUTF(GATEWAY_KEY);
                                    LinkAddress dest = route.getDestination();
                                    if (dest != null) {
                                        out.writeInt(1);
                                        out.writeUTF(dest.getAddress().getHostAddress());
                                        out.writeInt(dest.getNetworkPrefixLength());
                                    } else {
                                        out.writeInt(0);
                                    }
                                    if (route.getGateway() != null) {
                                        out.writeInt(1);
                                        out.writeUTF(route.getGateway().getHostAddress());
                                    } else {
                                        out.writeInt(0);
                                    }
                                }
                                for (InetAddress inetAddr : linkProperties.getDnses()) {
                                    out.writeUTF(DNS_KEY);
                                    out.writeUTF(inetAddr.getHostAddress());
                                }
                                writeToFile = true;
                                break;
                            case DHCP:
                                out.writeUTF(IP_ASSIGNMENT_KEY);
                                out.writeUTF(config.ipAssignment.toString());
                                writeToFile = true;
                                break;
                            case UNASSIGNED:
                                /* Ignore */
                                break;
                            default:
                                loge("Ignore invalid ip assignment while writing");
                                break;
                        }

                        switch (config.proxySettings) {
                            case STATIC:
                                ProxyProperties proxyProperties = linkProperties.getHttpProxy();
                                String exclusionList = proxyProperties.getExclusionList();
                                out.writeUTF(PROXY_SETTINGS_KEY);
                                out.writeUTF(config.proxySettings.toString());
                                out.writeUTF(PROXY_HOST_KEY);
                                out.writeUTF(proxyProperties.getHost());
                                out.writeUTF(PROXY_PORT_KEY);
                                out.writeInt(proxyProperties.getPort());
                                out.writeUTF(EXCLUSION_LIST_KEY);
                                out.writeUTF(exclusionList);
                                writeToFile = true;
                                break;
                            case NONE:
                                out.writeUTF(PROXY_SETTINGS_KEY);
                                out.writeUTF(config.proxySettings.toString());
                                writeToFile = true;
                                break;
                            case UNASSIGNED:
                                /* Ignore */
                                break;
                            default:
                                loge("Ignthisore invalid proxy settings while writing");
                                break;
                        }
                        if (writeToFile) {
                            out.writeUTF(ID_KEY);
                            out.writeInt(configKey(config));
                        }
                    } catch (NullPointerException e) {
                        loge("Failure in writing " + config.linkProperties + e);
                    }
                    out.writeUTF(EOS);
                }

            } catch (IOException e) {
                loge("Error writing data file");
            } finally {
                if (out != null) {
                    try {
                        out.close();
                    } catch (Exception e) {}
                }

                //Quit if no more writes sent
                synchronized (DelayedDiskWrite.class) {
                    if (--sWriteSequence == 0) {
                        sDiskWriteHandler.getLooper().quit();
                        sDiskWriteHandler = null;
                        sDiskWriteHandlerThread = null;
                    }
                }
            }
        }

        private static void loge(String s) {
            Log.e(TAG, s);
        }
    }

    private void readIpAndProxyConfigurations() {

        DataInputStream in = null;
        try {
            in = new DataInputStream(new BufferedInputStream(new FileInputStream(
                    ipConfigFile)));

            int version = in.readInt();
            if (version != 2 && version != 1) {
                loge("Bad version on IP configuration file, ignore read");
                return;
            }

            while (true) {
                int id = -1;
                IpAssignment ipAssignment = IpAssignment.UNASSIGNED;
                ProxySettings proxySettings = ProxySettings.UNASSIGNED;
                LinkProperties linkProperties = new LinkProperties();
                String proxyHost = null;
                int proxyPort = -1;
                String exclusionList = null;
                String key;

                do {
                    key = in.readUTF();
                    try {
                        if (key.equals(ID_KEY)) {
                            id = in.readInt();
                        } else if (key.equals(IP_ASSIGNMENT_KEY)) {
                            ipAssignment = IpAssignment.valueOf(in.readUTF());
                        } else if (key.equals(LINK_ADDRESS_KEY)) {
                            LinkAddress linkAddr = new LinkAddress(
                                    NetworkUtils.numericToInetAddress(in.readUTF()), in.readInt());
                            linkProperties.addLinkAddress(linkAddr);
                        } else if (key.equals(GATEWAY_KEY)) {
                            LinkAddress dest = null;
                            InetAddress gateway = null;
                            if (version == 1) {
                                // only supported default gateways - leave the dest/prefix empty
                                gateway = NetworkUtils.numericToInetAddress(in.readUTF());
                            } else {
                                if (in.readInt() == 1) {
                                    dest = new LinkAddress(
                                            NetworkUtils.numericToInetAddress(in.readUTF()),
                                            in.readInt());
                                }
                                if (in.readInt() == 1) {
                                    gateway = NetworkUtils.numericToInetAddress(in.readUTF());
                                }
                            }
                            linkProperties.addRoute(new RouteInfo(dest, gateway));
                        } else if (key.equals(DNS_KEY)) {
                            linkProperties.addDns(
                                    NetworkUtils.numericToInetAddress(in.readUTF()));
                        } else if (key.equals(PROXY_SETTINGS_KEY)) {
                            proxySettings = ProxySettings.valueOf(in.readUTF());
                        } else if (key.equals(PROXY_HOST_KEY)) {
                            proxyHost = in.readUTF();
                        } else if (key.equals(PROXY_PORT_KEY)) {
                            proxyPort = in.readInt();
                        } else if (key.equals(EXCLUSION_LIST_KEY)) {
                            exclusionList = in.readUTF();
                        } else if (key.equals(EOS)) {
                            break;
                        } else {
                            loge("Ignore unknown key " + key + "while reading");
                        }
                    } catch (IllegalArgumentException e) {
                        loge("Ignore invalid address while reading" + e);
                    }
                } while (true);

                if (id != -1) {
                    EthernetConfiguration config = mConfiguredNetworks.get(
                            mNetworkIds.get(id));

                    if (config == null) {
                        loge("configuration found for missing network, ignored");
                    } else {
                        config.linkProperties = linkProperties;
                        switch (ipAssignment) {
                            case STATIC:
                            case DHCP:
                                config.ipAssignment = ipAssignment;
                                break;
                            case UNASSIGNED:
                                //Ignore
                                break;
                            default:
                                loge("Ignore invalid ip assignment while reading");
                                break;
                        }

                        switch (proxySettings) {
                            case STATIC:
                                config.proxySettings = proxySettings;
                                ProxyProperties proxyProperties =
                                    new ProxyProperties(proxyHost, proxyPort, exclusionList);
                                linkProperties.setHttpProxy(proxyProperties);
                                break;
                            case NONE:
                                config.proxySettings = proxySettings;
                                break;
                            case UNASSIGNED:
                                //Ignore
                                break;
                            default:
                                loge("Ignore invalid proxy settings while reading");
                                break;
                        }
                    }
                } else {
                    if (DBG) log("Missing id while parsing configuration");
                }
            }
        } catch (EOFException ignore) {
        } catch (IOException e) {
            loge("Error parsing configuration" + e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception e) {}
            }
        }
    }

    private NetworkUpdateResult addOrUpdateNetworkNative(EthernetConfiguration config) {
        /*
         * If the supplied networkId is INVALID_NETWORK_ID, we create a new empty
         * network configuration. Otherwise, the networkId should
         * refer to an existing configuration.
         */
        int netId = config.networkId;
        boolean newNetwork = false;
        // networkId of INVALID_NETWORK_ID means we want to create a new network
        if (netId == INVALID_NETWORK_ID) {
            Integer savedNetId = mNetworkIds.get(configKey(config));
            if (savedNetId != null) {
                netId = savedNetId;
            } else {
                newNetwork = true;
                netId = mEthernetNative.addNetwork();
                if (netId < 0) {
                    loge("Failed to add a network!");
                    return new NetworkUpdateResult(INVALID_NETWORK_ID);
                }
            }
        }

        boolean updateFailed = true;

        setVariables: {

            if (config.networkName != null &&
                    !mEthernetNative.setNetworkVariable(
                        netId,
                        EthernetConfiguration.networkNameVarName,
                        config.networkName)) {
                loge("failed to set network name: " + config.networkName);
                break setVariables;
            }

            if (!mEthernetNative.setNetworkVariable(
                        netId,
                        EthernetConfiguration.priorityVarName,
                        Integer.toString(config.priority))) {
                loge(config.networkName + ": failed to set priority: "
                        + config.priority);
                break setVariables;
            }

            updateFailed = false;
        }

        if (updateFailed) {
            if (newNetwork) {
                mEthernetNative.removeNetwork(netId);
                loge("Failed to set a network variable, removed network: " + netId);
            }
            return new NetworkUpdateResult(INVALID_NETWORK_ID);
        }

        EthernetConfiguration currentConfig = mConfiguredNetworks.get(netId);
        if (currentConfig == null) {
            currentConfig = new EthernetConfiguration();
            currentConfig.networkId = netId;
        }

        readNetworkVariables(currentConfig);

        mConfiguredNetworks.put(netId, currentConfig);
        mNetworkIds.put(configKey(currentConfig), netId);

        NetworkUpdateResult result = writeIpAndProxyConfigurationsOnChange(currentConfig, config);
        result.setIsNewNetwork(newNetwork);
        result.setNetworkId(netId);
        return result;
    }

    /* Compare current and new configuration and write to file on change */
    private NetworkUpdateResult writeIpAndProxyConfigurationsOnChange(
            EthernetConfiguration currentConfig,
            EthernetConfiguration newConfig) {
        boolean ipChanged = false;
        boolean proxyChanged = false;
        LinkProperties linkProperties = new LinkProperties();

        switch (newConfig.ipAssignment) {
            case STATIC:
                Collection<LinkAddress> currentLinkAddresses = currentConfig.linkProperties
                        .getLinkAddresses();
                Collection<LinkAddress> newLinkAddresses = newConfig.linkProperties
                        .getLinkAddresses();
                Collection<InetAddress> currentDnses = currentConfig.linkProperties.getDnses();
                Collection<InetAddress> newDnses = newConfig.linkProperties.getDnses();
                Collection<RouteInfo> currentRoutes = currentConfig.linkProperties.getRoutes();
                Collection<RouteInfo> newRoutes = newConfig.linkProperties.getRoutes();

                boolean linkAddressesDiffer =
                        (currentLinkAddresses.size() != newLinkAddresses.size()) ||
                        !currentLinkAddresses.containsAll(newLinkAddresses);
                boolean dnsesDiffer = (currentDnses.size() != newDnses.size()) ||
                        !currentDnses.containsAll(newDnses);
                boolean routesDiffer = (currentRoutes.size() != newRoutes.size()) ||
                        !currentRoutes.containsAll(newRoutes);

                if ((currentConfig.ipAssignment != newConfig.ipAssignment) ||
                        linkAddressesDiffer ||
                        dnsesDiffer ||
                        routesDiffer) {
                    ipChanged = true;
                }
                break;
            case DHCP:
                if (currentConfig.ipAssignment != newConfig.ipAssignment) {
                    ipChanged = true;
                }
                break;
            case UNASSIGNED:
                /* Ignore */
                break;
            default:
                loge("Ignore invalid ip assignment during write");
                break;
        }

        switch (newConfig.proxySettings) {
            case STATIC:
                ProxyProperties newHttpProxy = newConfig.linkProperties.getHttpProxy();
                ProxyProperties currentHttpProxy = currentConfig.linkProperties.getHttpProxy();

                if (newHttpProxy != null) {
                    proxyChanged = !newHttpProxy.equals(currentHttpProxy);
                } else {
                    proxyChanged = (currentHttpProxy != null);
                }
                break;
            case NONE:
                if (currentConfig.proxySettings != newConfig.proxySettings) {
                    proxyChanged = true;
                }
                break;
            case UNASSIGNED:
                /* Ignore */
                break;
            default:
                loge("Ignore invalid proxy configuration during write");
                break;
        }

        if (!ipChanged) {
            addIpSettingsFromConfig(linkProperties, currentConfig);
        } else {
            currentConfig.ipAssignment = newConfig.ipAssignment;
            addIpSettingsFromConfig(linkProperties, newConfig);
            log("IP config changed network name = " + currentConfig.networkName + " linkProperties: " +
                    linkProperties.toString());
        }

        if (!proxyChanged) {
            linkProperties.setHttpProxy(currentConfig.linkProperties.getHttpProxy());
        } else {
            currentConfig.proxySettings = newConfig.proxySettings;
            linkProperties.setHttpProxy(newConfig.linkProperties.getHttpProxy());
            log("proxy changed network name = " + currentConfig.networkName);
            if (linkProperties.getHttpProxy() != null) {
                log(" proxyProperties: " + linkProperties.getHttpProxy().toString());
            }
        }

        if (ipChanged || proxyChanged) {
            currentConfig.linkProperties = linkProperties;
            writeIpAndProxyConfigurations();
            sendConfiguredNetworksChangedBroadcast(currentConfig,
                    EthernetManager.CHANGE_REASON_CONFIG_CHANGE);
        }
        return new NetworkUpdateResult(ipChanged, proxyChanged);
    }

    private void addIpSettingsFromConfig(LinkProperties linkProperties,
            EthernetConfiguration config) {
        for (LinkAddress linkAddr : config.linkProperties.getLinkAddresses()) {
            linkProperties.addLinkAddress(linkAddr);
        }
        for (RouteInfo route : config.linkProperties.getRoutes()) {
            linkProperties.addRoute(route);
        }
        for (InetAddress dns : config.linkProperties.getDnses()) {
            linkProperties.addDns(dns);
        }
    }

    /**
     * Read the variables that are needed to
     * fill in the EthernetConfiguration object.
     *
     * @param config the {@link EthernetConfiguration} object to be filled in.
     */
    private void readNetworkVariables(EthernetConfiguration config) {

        int netId = config.networkId;
        if (netId < 0)
            return;

        /*
         * TODO: maybe should have a native method that takes an array of
         * variable names and returns an array of values. But we'd still
         * be doing a round trip to the supplicant daemon for each variable.
         */
        String value;

        value = mEthernetNative.getNetworkVariable(netId, EthernetConfiguration.networkNameVarName);
        if (!TextUtils.isEmpty(value)) {
	    config.networkName = value;
        } else {
            config.networkName = null;
        }

        value = mEthernetNative.getNetworkVariable(netId, EthernetConfiguration.priorityVarName);
        config.priority = -1;
        if (!TextUtils.isEmpty(value)) {
            try {
                config.priority = Integer.parseInt(value);
            } catch (NumberFormatException ignore) {
            }
        }
    }

    /* Returns a unique for a given configuration */
    private static int configKey(EthernetConfiguration config) {

        String key = config.networkName;

        return key.hashCode();
    }

    String dump() {
        StringBuffer sb = new StringBuffer();
        String LS = System.getProperty("line.separator");
        sb.append("mLastPriority ").append(mLastPriority).append(LS);
        sb.append("Configured networks ").append(LS);
        for (EthernetConfiguration conf : getConfiguredNetworks()) {
            sb.append(conf).append(LS);
        }
        return sb.toString();
    }

    public String getConfigFile() {
        return ipConfigFile;
    }

    private void loge(String s) {
        Log.e(TAG, s);
    }

    private void log(String s) {
        Log.d(TAG, s);
    }
}
