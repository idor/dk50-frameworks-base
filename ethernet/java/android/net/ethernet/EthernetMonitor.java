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

import java.util.regex.Matcher;

import android.net.NetworkInfo;
import android.util.Config;
import android.util.Slog;
import java.util.StringTokenizer;

/**
 * Listens for events from kernel, and passes them on to the
 * {@link EtherentStateTracker} for handling. Runs in its own thread.
 * 
 * @hide
 */
public class EthernetMonitor {
	private static final String		TAG = "EthernetMonitor";
	private static final int		CONNECTED			= 1;
	private static final int		DISCONNECTED		= 2;
	private static final int		PHYUP				= 3;
	private static final String		connectedEvent		= "CONNECTED";
	private static final String		disconnectedEvent	= "DISCONNECTED";
	private static final int		ADD_ADDR			= 20;
	private static final int		RM_ADDR				= 21;
	private static final int		NEW_LINK			= 16;
	private static final int		DEL_LINK			= 17;
	private static final boolean	localLOGV = true;

	private EthernetStateTracker	mTracker;

	public EthernetMonitor(EthernetStateTracker tracker) {
		mTracker = tracker;
	}

	public void startMonitoring() {
		new MonitorThread().start();
	}

	class MonitorThread extends Thread {
		public MonitorThread() {
			super("EthMonitor");
		}

		public void run() {
			// noinspection InfiniteLoopStatement
			for (;;) {
				int index;
				int i;
				int cmd;
				String dev;

				if (localLOGV)
					Slog.v(TAG, "go poll events");

				String eventName = EthernetNative.waitForEvent();

				if (eventName == null) {
					continue;
				}

				if (localLOGV)
					Slog.v(TAG, "get event " + eventName);

				/*
				 * Map event name into event enum
				 */
				i = 0;
				while (i < eventName.length()) {
					index = eventName.substring(i).indexOf(":");
					if (index == -1)
						break;
					dev = eventName.substring(i, index);
					i += index + 1;
					index = eventName.substring(i).indexOf(":");
					if (index == -1)
						break;
					cmd = Integer.parseInt(eventName.substring(i, i + index));
					i += index + 1;
					if (localLOGV)
						Slog.v(TAG, "dev: " + dev + " ev " + cmd);
					switch (cmd) {
					case NEW_LINK:
						mTracker.notifyStateChange(dev, EthernetStateTracker.EVENT_PHY_CONNECTED);
						break;
					case DEL_LINK:
						mTracker.notifyStateChange(dev, EthernetStateTracker.EVENT_PHY_DISCONNECTED);
						break;
					case ADD_ADDR:
						mTracker.notifyStateChange(dev, EthernetStateTracker.EVENT_ADD_ADDR);
						break;
					}
				}
			}
		}

	}
}
