#!/usr/bin/env python3
"""Gera os graficos e uma analise inicial de um capture TCP."""

from __future__ import annotations

import argparse
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
from scapy.all import IP, IPv6, TCP, rdpcap

ALPHA = 0.125
WINDOW_SECONDS = 1.0


def flow_endpoints(packet: Any) -> tuple[tuple[str, int], tuple[str, int]]:
    # Identifica o fluxo TCP pela tupla (IP, porta) de origem e destino.
    tcp = packet[TCP]
    if IP in packet:
        ip_layer = packet[IP]
    else:
        ip_layer = packet[IPv6]
    return (ip_layer.src, int(tcp.sport)), (ip_layer.dst, int(tcp.dport))


def packet_end_sequence(packet: Any) -> int:
    # Calcula o fim lógico do segmento usando seq + payload + 1 no Syn.
    tcp = packet[TCP]
    payload_length = len(bytes(tcp.payload))
    return int(tcp.seq) + payload_length + (1 if tcp.flags & 0x02 else 0)


def choose_flow(packets: list[Any]) -> tuple[tuple[str, int], tuple[str, int]]:
    syn_clients: list[tuple[tuple[str, int], tuple[str, int]]] = []
    payload_counts: dict[tuple[tuple[str, int], tuple[str, int]], int] = defaultdict(int)

    for packet in packets:
        if TCP not in packet or not (IP in packet or IPv6 in packet):
            continue
        tcp = packet[TCP]
        source, destination = flow_endpoints(packet)
        flow = (source, destination)
        payload_counts[flow] += len(bytes(tcp.payload))
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            syn_clients.append(flow)

    if syn_clients:
        return max(syn_clients, key=lambda flow: payload_counts[flow])
    if not payload_counts:
        raise RuntimeError("Nenhum fluxo TCP/IP foi encontrado no capture.")
    return max(payload_counts, key=payload_counts.get)


def analyze(capture_path: Path, output_dir: Path) -> None:
    packets = rdpcap(str(capture_path))
    client, server = choose_flow(packets)
    first_time = float(packets[0].time)

    # Mantém apenas os dados do fluxo escolhido: pacotes do cliente com payload e ACKs do servidor.
    client_packets: list[dict[str, float | int]] = []
    server_acks: list[tuple[float, int]] = []
    for packet in packets:
        if TCP not in packet or not (IP in packet or IPv6 in packet):
            continue
        tcp = packet[TCP]
        source, destination = flow_endpoints(packet)
        timestamp = float(packet.time) - first_time
        if (source, destination) == (client, server):
            payload_length = len(bytes(tcp.payload))
            if payload_length:
                client_packets.append({
                    "time": timestamp,
                    "seq": int(tcp.seq),
                    "end": packet_end_sequence(packet),
                    "length": payload_length,
                })
        elif (source, destination) == (server, client) and (tcp.flags & 0x10):
            server_acks.append((timestamp, int(tcp.ack)))

    if not client_packets:
        pass

    client_packets.sort(key=lambda item: float(item["time"]))
    server_acks.sort()
    base_sequence = int(client_packets[0]["seq"])

    # Associa cada segmento de dados ao primeiro ACK cumulativ que confirma o final do segmento.
    rtt_samples: list[tuple[float, float]] = []
    used_ack_index = -1
    for segment in client_packets:
        matching = next(
            ((index, ack_time) for index, (ack_time, ack) in enumerate(server_acks)
             if index > used_ack_index and ack >= int(segment["end"]) and ack_time >= float(segment["time"])),
            None,
        )
        if matching is not None:
            used_ack_index, ack_time = matching
            rtt_samples.append((float(segment["time"]), ack_time - float(segment["time"])))

    # EstimatedRTT.
    estimated: list[float] = []
    if rtt_samples:
        current = rtt_samples[0][1]
        for _, sample in rtt_samples:
            current = (1 - ALPHA) * current + ALPHA * sample
            estimated.append(current)

    duration = max(float(client_packets[-1]["time"]), 1e-9)
    max_time = math.ceil(duration) or 1
    throughput: list[tuple[float, float]] = []
    for window_start in range(max_time):
        window_end = window_start + WINDOW_SECONDS
        total = sum(
            int(segment["length"])
            for segment in client_packets
            if window_start <= float(segment["time"]) < window_end
        )
        throughput.append((window_start + WINDOW_SECONDS / 2, total / WINDOW_SECONDS))

    output_dir.mkdir(parents=True, exist_ok=True)
    plot_sequence(client_packets, base_sequence, output_dir / "01_sequencia_fleets.png")
    plot_rtt(rtt_samples, estimated, output_dir / "02_rtt_estimated_rtt.png")
    plot_throughput(throughput, output_dir / "03_throughput.png")
    print(f"Fluxo cliente: {client[0]}:{client[1]} -> {server[0]}:{server[1]}")
    print(f"Segmentos de dados do cliente: {len(client_packets)}")
    print(f"Amostras de RTT: {len(rtt_samples)}")
    print(f"Arquivos gerados em: {output_dir}")


def plot_sequence(segments: list[dict[str, float | int]], base: int, path: Path) -> None:
    # Esse gráfico mostra a evolução da janela de envio, não apenas o número bruto de sequência.
    x = [float(item["time"]) for item in segments]
    y = [int(item["seq"]) - base for item in segments]
    plt.figure(figsize=(11, 5.5))
    plt.scatter(x, y, s=16, alpha=0.75, label="Segmentos de dados do cliente")
    plt.xlabel("Tempo desde o inicio do capture (s)")
    plt.ylabel("Numero de sequencia relativo (bytes)")
    plt.title("TCP: numero de sequencia versus tempo (Stevens)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def plot_rtt(samples: list[tuple[float, float]], estimated: list[float], path: Path) -> None:
    plt.figure(figsize=(11, 5.5))
    if samples:
        times = [sample[0] for sample in samples]
        values_ms = [sample[1] * 1000 for sample in samples]
        plt.scatter(times, values_ms, s=16, alpha=0.7, label="RTT por segmento")
        plt.plot(times, [value * 1000 for value in estimated], color="tab:red", linewidth=2, label="EstimatedRTT (alpha=0.125)")
    plt.xlabel("Tempo desde o inicio do capture (s)")
    plt.ylabel("RTT (ms)")
    plt.title("TCP: RTT por segmento e EstimatedRTT")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def plot_throughput(points: list[tuple[float, float]], path: Path) -> None:
    plt.figure(figsize=(11, 5.5))
    plt.bar([point[0] for point in points], [point[1] for point in points], width=0.9, color="tab:green", alpha=0.8)
    plt.xlabel("Tempo desde o inicio do capture (s)")
    plt.ylabel("Throughput do cliente (bytes/s)")
    plt.title("TCP: taxa de transferencia em janelas de 1 segundo")
    plt.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="arquivo .pcap ou .pcapng")
    parser.add_argument("-o", "--output", type=Path, default=Path("graficos_tcp"), help="diretorio de saida")
    args = parser.parse_args()
    analyze(args.capture, args.output)


if __name__ == "__main__":
    main()