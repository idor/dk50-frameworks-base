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

import android.net.NetworkInfo;

import android.util.Config;
import android.util.Slog;
import java.util.StringTokenizer;

import com.android.internal.util.Protocol;
import com.android.internal.util.StateMachine;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Listens for events from kernel, and passes them on
 * to the {@link StateMachine} for handling. Runs in its own thread.
 *
 * @hide
 */
public class EthernetMonitor {

    private static final String TAG = "EthernetMonitor";

    /** Internal events */
    private static final int EVENT_UNKNOWN = 0;
    private static final int EVENT_PHY_UP = 1;
    private static final int EVENT_PHY_DOWN = 2;
    private static final int EVENT_CONNECTED = 3;
    private static final int EVENT_DISCONNECTED = 4;

    private static final String EVENT_PHY_UP_STR = "PHY_UP";
    private static final String EVENT_PHY_DOWN_STR = "PHY_DOWN";
    private static final String EVENT_CONNECTED_STR = "CONNECTED";
    private static final String EVENT_DISCONNECTED_STR = "DISCONNECTED";

    private final StateMachine mStateMachine;
    private final EthernetNative mEthernetNative;

    /* Kernel events reported to a state machine */
    private static final int BASE = Protocol.BASE_ETHERNET_MONITOR;

    /* Network connection completed */
    public static final int NETWORK_CONNECTION_EVENT             = BASE + 1;
    /* Network disconnection completed */
    public static final int NETWORK_DISCONNECTION_EVENT          = BASE + 2;

    public EthernetMonitor(StateMachine ethernetStateMachine, EthernetNative ethernetNative) {
	mStateMachine = ethernetStateMachine;
	mEthernetNative = ethernetNative;
    }

    public void startMonitoring() {
        new MonitorThread().start();
    }

    class MonitorThread extends Thread {
        public MonitorThread() {
            super("EthernetMonitor");
        }

        public void run() {

            //noinspection InfiniteLoopStatement
            for (;;) {
                Log.d(TAG, "Poll Ethernet netlink events");

                String eventStr = mEthernetNative.waitForEvent();

                if (eventStr == null) {
                    continue;
                }

                Log.d(TAG, "Event [" + eventStr + "]");

		if (EVENT_PHY_UP_STR.isEqual(eventStr)) {
		    mStateMachine.sendMessage(EVENT_PHY_UP);
                    //mTracker.notifyPhyConnected();
		}
		else if (EVENT_PHY_DOWN_STR.isEqual(eventStr)) {
		    mStateMachine.sendMessage(EVENT_PHY_DOWN);
                    //mTracker.notifyPhyDisconnected();
		}
		else if (EVENT_CONNECTED_STR.isEqual(eventStr)) {
		    mStateMachine.sendMessage(EVENT_CONNECTED);
                    //mTracker.notifyStateChange(NetworkInfo.DetailedState.CONNECTED);
		}
		else if (EVENT_DISCONNECTED_STR.isEqual(eventStr)) {
		    mStateMachine.sendMessage(EVENT_DISCONNECTED);
                    //mTracker.notifyStateChange(NetworkInfo.DetailedState.DISCONNECTED);
		} else {
                    //mTracker.notifyStateChange(NetworkInfo.DetailedState.FAILED);
		}
            }
        }
    }
}
