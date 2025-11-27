# PCAP Analyzer - A tool to analyze PCAP files and extract various network statistics and data
from scapy.all import rdpcap, TCP, UDP, ICMP, ARP, IP, Raw, DNS, DNSQR, DNSRR
from collections import defaultdict, Counter
import os, datetime, errno, re, sys
import threading, itertools, time

class PCAPAnalyzer: #class 썼음!
    def __init__(self, path):
        self.path = path
        base = os.path.basename(path)
        name, _ = os.path.splitext(base)
        self.base_name = name
        self.output_file = f"{name}_analysed.log"
        self.stream_dir = f"{name}_streams"

        spinner_done = False

        def spinner(): #심심해서 넣은 기능 ㅎ
            for c in itertools.cycle(['|', '/', '-', '\\']):
                if spinner_done:
                    break
                print(f"\r위이이이이잉 {c}", end="", flush=True)
                time.sleep(0.1)

        t = threading.Thread(target=spinner)
        t.start()
        try:
            self.packets = rdpcap(path)
        except Exception as e:
            spinner_done = True
            t.join()
            print(f"\n[!] 이런 젠장! 로딩이 되지 않아!: {e}")
            raise

        spinner_done = True
        t.join()
        print(f"\r[+] 로딩 성공!: {path}   ")

        # 자료 넣을 곳 만들기 (대부분 다 list)
        self.protocols = defaultdict(list)
        self.ip_stats_src = defaultdict(int)
        self.ip_stats_dst = defaultdict(int)
        self.large_packets = []
        self.http_candidates = []
        self.packet_summaries = []

        self.tcp_streams = defaultdict(list)
        self.dns_queries = []
        self.dns_answers = []
        self.tcp_flag_counts = Counter()
        self.first_ts = None
        self.last_ts = None

        try:
            os.makedirs(self.stream_dir, exist_ok=True)
        except OSError:
            pass

    def format_ts(self, ts): #그 ts아님 timestamp임
        if ts is None:
            return "N/A"
        try:
            t = float(ts)
            return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")
        except Exception:
            try:
                return str(ts)
            except Exception:
                return "N/A"

    def _update_time_range(self, ts): #timestamp 업데이트
        if ts is None:
            return
        try:
            t = float(ts)
        except Exception:
            return
        if self.first_ts is None or t < self.first_ts:
            self.first_ts = t
        if self.last_ts is None or t > self.last_ts:
            self.last_ts = t

    def _tcp_flag_string(self, tcp_layer): #tcp에서 flag 추출
        try:
            f = tcp_layer.flags
            return str(f)
        except Exception:
            return ""

    def fmt_row(self, values, widths): 
        out = []
        for v, w in zip(values, widths):
            s = "" if v is None else str(v)
            if len(s) > w:
                s = s[:w-3] + "..."
            out.append(f"{s:<{w}}")
        return "".join(out)

    def analyze(self):
        for idx, pkt in enumerate(self.packets):
            ts = getattr(pkt, "time", None)
            tstr = self.format_ts(ts)
            self._update_time_range(ts)

            proto = "OTHER"
            if pkt.haslayer(TCP):
                proto = "TCP"
                self.protocols["TCP"].append(pkt)
            if pkt.haslayer(UDP):
                proto = "UDP" if proto == "OTHER" else proto
                self.protocols["UDP"].append(pkt)
            if pkt.haslayer(ICMP):
                proto = "ICMP"
                self.protocols["ICMP"].append(pkt)
            if pkt.haslayer(ARP):
                proto = "ARP"
                self.protocols["ARP"].append(pkt)
            if pkt.haslayer(IP) and not (pkt.haslayer(TCP) or pkt.haslayer(UDP) or pkt.haslayer(ICMP)):
                proto = "IP"
                self.protocols["IP"].append(pkt)

            src = dst = "N/A"
            if pkt.haslayer(IP):
                try:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                except Exception:
                    src = dst = "N/A"
                self.ip_stats_src[src] += 1
                self.ip_stats_dst[dst] += 1

            src_port = dst_port = ""
            try:
                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
            except Exception:
                src_port = dst_port = ""

            length = len(pkt)

            if length > 800:
                self.large_packets.append((idx, pkt))

            raw_text = None
            raw_bytes = None
            if pkt.haslayer(Raw):
                try:
                    raw_bytes = bytes(pkt[Raw].load)
                    raw_text = pkt[Raw].load.decode(errors="ignore")
                except Exception:
                    try:
                        raw_bytes = bytes(pkt[Raw].load)
                    except Exception:
                        raw_bytes = None
                    raw_text = None

                if raw_text and any(k in raw_text for k in ("HTTP/", "GET ", "POST ", "Content-Disposition", "Content-Type:", "filename=")):
                    self.http_candidates.append((idx, src, dst, src_port, dst_port, length, tstr, raw_text))

            if pkt.haslayer(TCP):
                flags_str = self._tcp_flag_string(pkt[TCP])
                self.tcp_flag_counts.update([flags_str])
                if raw_bytes:
                    try:
                        sport_i = int(src_port) if src_port != "" else 0
                        dport_i = int(dst_port) if dst_port != "" else 0
                    except Exception:
                        sport_i = 0
                        dport_i = 0
                    key = (src, dst, sport_i, dport_i)
                    seq = getattr(pkt[TCP], "seq", 0)
                    try:
                        tsf = float(ts) if ts is not None else 0.0
                    except Exception:
                        tsf = 0.0
                    self.tcp_streams[key].append((seq, tsf, raw_bytes))

            if pkt.haslayer(DNS):
                try:
                    dns_layer = pkt[DNS]
                    if dns_layer.qdcount and dns_layer.qd:
                        qd = dns_layer.qd
                        cur = qd
                        while cur:
                            qname = getattr(cur, "qname", None)
                            if qname:
                                try:
                                    qn = qname.decode() if isinstance(qname, bytes) else str(qname)
                                except Exception:
                                    qn = str(qname)
                                self.dns_queries.append((tstr, src, dst, qn))
                            if hasattr(cur, "payload") and cur.payload and isinstance(cur.payload, DNSQR):
                                cur = cur.payload
                                continue
                            break
                    if dns_layer.ancount and dns_layer.an:
                        cur = dns_layer.an
                        while cur:
                            rrname = getattr(cur, "rrname", None)
                            rdata = getattr(cur, "rdata", None)
                            try:
                                rrn_s = rrname.decode() if isinstance(rrname, bytes) else str(rrname)
                            except Exception:
                                rrn_s = str(rrname)
                            try:
                                rd_s = rdata.decode() if isinstance(rdata, bytes) else str(rdata)
                            except Exception:
                                rd_s = str(rdata)
                            self.dns_answers.append((tstr, src, dst, rrn_s, rd_s))
                            if hasattr(cur, "payload") and cur.payload and isinstance(cur.payload, DNSRR):
                                cur = cur.payload
                                continue
                            break
                except Exception:
                    pass

            summary = {
                "no": idx,
                "time": tstr,
                "src": src,
                "dst": dst,
                "sport": src_port,
                "dport": dst_port,
                "proto": proto,
                "len": length,
            }
            self.packet_summaries.append(summary)

    def reassemble_streams(self):
        saved = []
        for i, (key, segs) in enumerate(self.tcp_streams.items()):
            segs_sorted = sorted(segs, key=lambda x: (x[0], x[1]))
            data = b"".join([s[2] for s in segs_sorted if s[2]])
            if not data:
                continue
            src, dst, sport, dport = key
            def safe(s): return re.sub(r'[^0-9A-Za-z\.\_\-]', '_', str(s))
            fname = f"stream_{i}_{safe(src)}_{safe(dst)}_{safe(sport)}_{safe(dport)}.bin"
            outpath = os.path.join(self.stream_dir, fname)
            try:
                with open(outpath, "wb") as f:
                    f.write(data)
                saved.append((key, outpath, len(data)))
            except Exception:
                pass
        return saved

    def save_to_log(self, outname):
        packet_info = []
        for p in self.packet_summaries:
            packet_info.append({
                "index": p["no"],
                "timestamp": p["time"],
                "src": p["src"],
                "dst": p["dst"],
                "proto": p["proto"],
                "length": p["len"],
                "sport": p["sport"],
                "dport": p["dport"],
            })

        protocol_count = {k: len(v) for k, v in self.protocols.items()}
        length_sorted = sorted(packet_info, key=lambda x: x["length"], reverse=True)
        ip_count = dict(sorted(self.ip_stats_src.items(), key=lambda x: x[1], reverse=True))

        with open(outname, "w", encoding="utf-8") as f:
            f.write("==== PCAP ANALYSIS LOG ====\n")
            f.write(f"File:\t{self.path}\n")
            f.write(f"Total Packets:\t{len(self.packets)}\n")
            if self.first_ts and self.last_ts:
                t_first = datetime.datetime.fromtimestamp(self.first_ts).strftime("%Y-%m-%d %H:%M:%S.%f")
                t_last  = datetime.datetime.fromtimestamp(self.last_ts).strftime("%Y-%m-%d %H:%M:%S.%f")
                f.write(f"Capture Start:\t{t_first}\n")
                f.write(f"Capture End:\t{t_last}\n")
                f.write(f"Duration(s):\t{(self.last_ts - self.first_ts):.6f}\n")
            f.write("\n\n")

            f.write("[1] PACKET LIST\n")
            hdr_w = [6, 26, 20, 20, 8, 8]
            hdr = self.fmt_row(["Index","Timestamp","Source","Destination","Proto","Length"], hdr_w)
            f.write(hdr + "\n")
            f.write("-" * sum(hdr_w) + "\n")
            for p in packet_info:
                row = self.fmt_row([p["index"], p["timestamp"], p["src"], p["dst"], p["proto"], p["length"]], hdr_w)
                f.write(row + "\n")
            f.write("\n\n")

            f.write("[2] PROTOCOL SUMMARY\n")
            hdr_w = [12, 8]
            f.write(self.fmt_row(["Protocol","Count"], hdr_w) + "\n")
            f.write("-" * sum(hdr_w) + "\n")
            for proto, cnt in sorted(protocol_count.items(), key=lambda x: x[0]):
                f.write(self.fmt_row([proto, cnt], hdr_w) + "\n")
            f.write("\n\n")

            f.write("[3] PACKETS SORTED BY LENGTH (DESC)\n")
            hdr_w = [6, 10, 8, 20, 20]
            f.write(self.fmt_row(["Idx","Length","Proto","Source","Destination"], hdr_w) + "\n")
            f.write("-" * sum(hdr_w) + "\n")
            for p in length_sorted:
                f.write(self.fmt_row([p["index"], p["length"], p["proto"], p["src"], p["dst"]], hdr_w) + "\n")
            f.write("\n\n")

            f.write("[4] IP SUMMARY (Source counts)\n")
            hdr_w = [20, 8]
            f.write(self.fmt_row(["IP","Count"], hdr_w) + "\n")
            f.write("-" * sum(hdr_w) + "\n")
            for ip, cnt in ip_count.items():
                f.write(self.fmt_row([ip, cnt], hdr_w) + "\n")
            f.write("\n\n")

            f.write("[5] TCP FLAGS SUMMARY\n")
            hdr_w = [10, 8]
            f.write(self.fmt_row(["Flag","Count"], hdr_w) + "\n")
            f.write("-" * sum(hdr_w) + "\n")
            for flag, cnt in self.tcp_flag_counts.most_common():
                f.write(self.fmt_row([flag, cnt], hdr_w) + "\n")
            f.write("\n\n")

            f.write("[6] LARGE PACKETS (>800 bytes)\n")
            for idx, pkt in self.large_packets:
                t = getattr(pkt, "time", None)
                tstr = self.format_ts(t)
                f.write(f"--- Packet No: {idx} ---\n")
                f.write(f"Time:\t{tstr}\n")
                if pkt.haslayer(IP):
                    f.write(f"IP:\t{pkt[IP].src} -> {pkt[IP].dst}\n")
                if pkt.haslayer(TCP):
                    try:
                        f.write(f"TCP Ports:\t{pkt[TCP].sport} -> {pkt[TCP].dport}\n")
                    except Exception:
                        pass
                f.write(f"Len:\t{len(pkt)}\n")
                if pkt.haslayer(Raw):
                    try:
                        payload = pkt[Raw].load.decode(errors="ignore")
                        f.write("Raw Payload (first 1000 chars):\n")
                        f.write(payload[:1000] + ("\n...[truncated]\n" if len(payload) > 1000 else "\n"))
                    except Exception:
                        f.write("Raw Payload: (binary, cannot decode)\n")
                f.write("\n")
            f.write("\n\n")

            f.write("[7] HTTP / File-transfer Candidates (partial payload shown)\n")
            for entry in self.http_candidates:
                idx, src, dst, sport, dport, length, tstr, raw_text = entry
                f.write(f"--- Packet No: {idx} ---\n")
                f.write(f"Time:\t{tstr}\n")
                f.write(f"Src:\t{src}:{sport}\n")
                f.write(f"Dst:\t{dst}:{dport}\n")
                f.write(f"Len:\t{length}\n")
                f.write("---- Payload Begin ----\n")
                f.write((raw_text[:2000] + ("\n...[truncated]\n" if len(raw_text) > 2000 else "\n")) if raw_text else "None\n")
                f.write("---- Payload End ----\n\n")
            f.write("\n\n")

            f.write("[8] DNS Queries\n")
            if not self.dns_queries:
                f.write("None\n\n")
            else:
                hdr_w = [26,16,16,50]
                f.write(self.fmt_row(["Time","Src","Dst","QueryName"], hdr_w) + "\n")
                f.write("-" * sum(hdr_w) + "\n")
                for rec in self.dns_queries:
                    f.write(self.fmt_row([rec[0], rec[1], rec[2], rec[3]], hdr_w) + "\n")
                f.write("\n\n")

            f.write("[9] DNS Answers\n")
            if not self.dns_answers:
                f.write("None\n\n")
            else:
                hdr_w = [26,16,16,30,30]
                f.write(self.fmt_row(["Time","Src","Dst","RRName","RData"], hdr_w) + "\n")
                f.write("-" * sum(hdr_w) + "\n")
                for rec in self.dns_answers:
                    f.write(self.fmt_row([rec[0], rec[1], rec[2], rec[3], rec[4]], hdr_w) + "\n")
                f.write("\n\n")

            f.write("[10] Reassembled TCP Streams (files)\n")
            f.write(self.fmt_row(["FilePath","Flow","Size(bytes)"], [60,40,12]) + "\n")
            f.write("-" * (60+40+12) + "\n")
            try:
                streams = sorted(os.listdir(self.stream_dir))
            except Exception:
                streams = []
            if not streams:
                f.write("None\n\n")
            else:
                for s in streams:
                    full = os.path.join(self.stream_dir, s)
                    size = os.path.getsize(full) if os.path.isfile(full) else 0
                    f.write(self.fmt_row([full, s, size], [60,40,12]))
                f.write("\n\n")

            f.write("=== END OF REPORT ===\n")

        print(f"[+] 분석 완료! 이곳에 저장됨!: {outname}")

    def run(self):
        self.analyze()
        saved_streams = self.reassemble_streams()
        print(f"[+] Packets parsed: {len(self.packets)}")
        print(f"[+] Protocols: {', '.join(sorted(self.protocols.keys()))}")
        if self.first_ts and self.last_ts:
            print(f"[+] Capture range: {self.format_ts(self.first_ts)} - {self.format_ts(self.last_ts)}")
        try:
            self.save_to_log(self.output_file)
        except Exception as e:
            print(f"[!] 이런 젠장! 로그가 저장되지 않아!: {e}")


if __name__ == "__main__":
    path = input("분석할 PCAP 파일 경로 입력: ").strip()
    if not os.path.isfile(path):
        print("없어요.")
        sys.exit(1)
    analyzer = PCAPAnalyzer(path)
    analyzer.run()
    print("""
    How to use:

    1. packet list
    2. protocol summary
    3. packets sorted by length
    4. ip summary
    5. tcp flags summary
    6. large packets
    7. http/file-transfer candidates
    8. dns queries
    9. dns answers
    10. reassembled tcp streams
        """)
