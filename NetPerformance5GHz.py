import pyshark
import math
from collections import defaultdict
import matplotlib.pyplot as plt

def pcap_parser(pcap_file):
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter='wlan.sa == 3c:ab:72:13:26:55 and wlan.ta == 04:71:53:5e:f2:bb and wlan.da == dc:45:46:54:0d:e9 and radiotap.dbm_antsignal != 0'
    )
    parsed_frames = []

    for pkt in cap:
        try:
                frame_number = int(pkt.frame_info.number)
                print(frame_number)
                timestamp = float(pkt.sniff_timestamp)
                print(f"Timestamp: {timestamp:.6f}")

                frame_length_bytes = int(pkt.length)
                frame_length_bits = frame_length_bytes * 8

                retry_raw = getattr(pkt.wlan, 'fc_retry', 'False') # retry flags
                retry = 1 if retry_raw.lower() == 'true' else 0

                # rssi, data rate
                if 'wlan_radio' in pkt:
                    radio = pkt['wlan_radio']
                    # rssi in dBm (as a float, if present)
                    rssi = getattr(radio, 'signal_dbm', None)

                    # data_rate in Mbps (round to 1 decimal place)
                    raw_rate = getattr(radio, 'data_rate', None)
                    data_rate = round(float(raw_rate), 1) if raw_rate is not None else None

                parsed_frames.append({
                    'retry': retry,
                    'rssi': rssi,
                    'data_rate': data_rate,
                    'length': frame_length_bits,
                    'timestamp': timestamp
                })
        except Exception as e:
            # skip malformed frames
            continue
    cap.close()
    return parsed_frames

def frameloss_calculation (parsed_frames):

    total = len(parsed_frames)
    counter = sum(1 for frame in parsed_frames if frame['retry'] == 1)

    if total == 0:
        return 0

    return counter / total

def throughput_calculation(parsed_frames):

    frame_loss = frameloss_calculation(parsed_frames)
    print(f"frameloss: {frame_loss}\n\n")

    channel_utilization = channel_util_calculation(parsed_frames)

    for frame in parsed_frames:
        if frame['data_rate']:
            data_rate = float(frame['data_rate'])
            frame_throughput = data_rate * (1 - frame_loss)
            new_throughput = data_rate * (1 - frame_loss) * (1-channel_utilization)
            frame['throughput'] = frame_throughput
            frame['new_throughput'] = new_throughput


def rateGap_calculation(parsed_frames):
    for frame in parsed_frames:
            frame['rategap'] = frame['data_rate'] - frame['throughput']

def channel_util_calculation(parsed_frames):
    utilization_aggregated = 0
    for frame in parsed_frames:
        utilization_aggregated += frame['length']/(frame['data_rate'] * 10**6)

    start_time = parsed_frames[0]['timestamp']
    end_time = parsed_frames[-1]['timestamp']
    observation_time = (end_time - start_time)

    utilization = utilization_aggregated / observation_time
    return utilization




import matplotlib.pyplot as plt
from collections import defaultdict

import matplotlib.pyplot as plt
from collections import defaultdict

def plot_windowed_throughput_by_index(frames, total_duration=30, window_size=2):
    N = len(frames)
    if N == 0:
        print("No frames to plot.")
        return

    # Calculate synthetic time for each frame
    time_per_frame = total_duration / N
    for i, frame in enumerate(frames):
        frame['synthetic_time'] = i * time_per_frame

    # Aggregate throughput data in windows
    windowed_old = defaultdict(list)
    windowed_new = defaultdict(list)

    for frame in frames:
        window = int(frame['synthetic_time'] // window_size)

        if frame.get('throughput') is not None:
            windowed_old[window].append(frame['throughput'])

        if frame.get('new_throughput') is not None:
            windowed_new[window].append(frame['new_throughput'])

    # Calculate average throughput per window
    window_times = []
    avg_old_throughputs = []
    avg_new_throughputs = []

    for w in sorted(set(windowed_old.keys()).union(windowed_new.keys())):
        window_start = w * window_size
        window_times.append(window_start)

        if windowed_old.get(w):
            avg_old = sum(windowed_old[w]) / len(windowed_old[w])
        else:
            avg_old = 0

        if windowed_new.get(w):
            avg_new = sum(windowed_new[w]) / len(windowed_new[w])
        else:
            avg_new = 0

        avg_old_throughputs.append(avg_old)
        avg_new_throughputs.append(avg_new)

    # Plot both throughput lines
    plt.figure(figsize=(10, 5))
    plt.plot(window_times, avg_old_throughputs, marker='o', linestyle='-', color='blue', label='Old Throughput')
    plt.plot(window_times, avg_new_throughputs, marker='x', linestyle='--', color='red', label='New Throughput')
    plt.title("Average Throughput in 2s Windows (Index-Based)")
    plt.xlabel("Time (s)")
    plt.ylabel("Throughput (Mbps)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def plot_windowed_data_rate_by_index(frames, total_duration=30, window_size=2):
    N = len(frames)
    if N == 0:
        print("No frames to plot.")
        return

    time_per_frame = total_duration / N
    for i, frame in enumerate(frames):
        frame['synthetic_time'] = i * time_per_frame

    # Group by time window
    windowed = defaultdict(list)
    for frame in frames:
        if frame['data_rate'] is not None:
            window = int(frame['synthetic_time'] // window_size)
            windowed[window].append(frame['data_rate'])

    # Prepare for plotting
    window_times = []
    avg_datarates = []

    for w in sorted(windowed.keys()):
        avg = sum(windowed[w]) / len(windowed[w])
        window_times.append(w * window_size)
        avg_datarates.append(avg)

    # Plot
    plt.figure(figsize=(10, 5))
    plt.plot(window_times, avg_datarates, marker='o', linestyle='-')
    plt.title("Average Data Rate in 2s Windows (Index-Based)")
    plt.xlabel("Time (s)")
    plt.ylabel("Data Rate (Mbps)")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def plot_windowed_frameloss_by_index(frames, total_duration=30, window_size=2):
    from collections import defaultdict

    N = len(frames)
    if N == 0:
        print("No frames to plot.")
        return

    # Assign synthetic time per frame
    time_per_frame = total_duration / N
    for i, frame in enumerate(frames):
        frame['synthetic_time'] = i * time_per_frame

    # Group retries per window
    retry_counts = defaultdict(int)
    total_counts = defaultdict(int)

    for frame in frames:
        window = int(frame['synthetic_time'] // window_size)
        total_counts[window] += 1
        if frame['retry'] == 1:
            retry_counts[window] += 1

    # Calculate frame loss per window
    window_times = []
    framelosses = []

    for w in sorted(total_counts.keys()):
        retries = retry_counts[w]
        total = total_counts[w]
        loss = retries / total if total > 0 else 0
        window_times.append(w * window_size)
        framelosses.append(loss)

    # Plot
    plt.figure(figsize=(10, 5))
    plt.plot(window_times, framelosses, marker='o', linestyle='-')
    plt.title("Frame Loss Rate in 2s Windows")
    plt.xlabel("Time (s)")
    plt.ylabel("Frame Loss Rate")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def plot_windowed_rssi_by_index(frames, total_duration=30, window_size=2):
    from collections import defaultdict

    N = len(frames)
    if N == 0:
        print("No frames to plot.")
        return

    # Assign synthetic time per frame
    time_per_frame = total_duration / N
    for i, frame in enumerate(frames):
        frame['synthetic_time'] = i * time_per_frame

    # Group RSSI values per window
    windowed = defaultdict(list)
    for frame in frames:
        if frame['rssi'] is not None:
            try:
                rssi = float(frame['rssi'])
                window = int(frame['synthetic_time'] // window_size)
                windowed[window].append(rssi)
            except:
                continue

    # Compute averages
    window_times = []
    avg_rssis = []

    for w in sorted(windowed.keys()):
        avg = sum(windowed[w]) / len(windowed[w])
        window_times.append(w * window_size)
        avg_rssis.append(avg)

    # Plot
    plt.figure(figsize=(10, 5))
    plt.plot(window_times, avg_rssis, marker='o', linestyle='-')
    plt.title("Average RSSI in 2s Windows")
    plt.xlabel("Time (s)")
    plt.ylabel("RSSI (dBm)")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def plot_windowed_rategap_by_index(frames, total_duration=30, window_size=2):
    from collections import defaultdict

    N = len(frames)
    if N == 0:
        print("No frames to plot.")
        return

    time_per_frame = total_duration / N
    for i, frame in enumerate(frames):
        frame['synthetic_time'] = i * time_per_frame

    # Group rategaps per window
    windowed = defaultdict(list)
    for frame in frames:
        if frame.get('rategap') is not None:
            try:
                rg = float(frame['rategap'])
                window = int(frame['synthetic_time'] // window_size)
                windowed[window].append(rg)
            except:
                continue

    # Compute averages
    window_times = []
    avg_rategaps = []

    for w in sorted(windowed.keys()):
        avg = sum(windowed[w]) / len(windowed[w])
        window_times.append(w * window_size)
        avg_rategaps.append(avg)

    # Plot
    plt.figure(figsize=(10, 5))
    plt.plot(window_times, avg_rategaps, marker='o', linestyle='-')
    plt.title("Average RateGap in 2s Windows")
    plt.xlabel("Time (s)")
    plt.ylabel("RateGap (Mbps)")
    plt.grid(True)
    plt.tight_layout()
    plt.show()


def main():
    filepath = "5ghz_good_repaired.pcap"
    print(f"... Reading .pcap file {filepath}...\n")
    frames = pcap_parser(filepath)

    throughput_calculation(frames)
    rateGap_calculation(frames)
    channel_util_calculation(frames)

    plot_windowed_throughput_by_index(frames)
    plot_windowed_data_rate_by_index(frames)
    plot_windowed_frameloss_by_index(frames)
    plot_windowed_rssi_by_index(frames)
    plot_windowed_rategap_by_index(frames)

    for frame in frames:
        print(frame)


if __name__ == '__main__':
    main()
