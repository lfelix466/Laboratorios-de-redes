#!/usr/bin/env python3
"""Gera os graficos e uma analise do trafego DNS sobre UDP. """

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
from scapy.all import DNS, IP, IPv6, TCP, UDP, rdpcap


UDP_FIELDS = ["Porta origem", "Porta destino", "Comprimento", "Checksum"]
TCP_FIELDS = [
    "Porta origem",
    "Porta destino",
    "Sequencia",
    "ACK",
    "Flags/reservado",
    "Janela",
    "Checksum",
    "Ponteiro urgente",
    "Opcoes",
]


def ip_layer(packet: Any) -> Any:
    return packet[IP] if IP in packet else packet[IPv6]


def query_name(packet: Any) -> str:
    question = packet[DNS].qd
    if question is None or not hasattr(question, "qname"):
        return "?"
    return question.qname.decode(errors="replace").rstrip("./")


def select_target_names(packets: list[Any]) -> list[str]:
    names: list[str] = []
    for packet in packets:
        if UDP not in packet or DNS not in packet or packet[DNS].qr:
            continue
        name = query_name(packet)
        if name.startswith("https://") and name not in names:
            names.append(name)
    if len(names) < 3:
        raise RuntimeError("Nao foram encontradas tres consultas DNS alvo no capture.")
    return names[:3]


def find_rtt_samples(packets: list[Any], target_names: list[str]) -> list[tuple[str, float]]:
    # A chave da análise DNS é emparelhar cada consulta com a resposta correta usando ID, nome,
    queries: dict[tuple[int, str, str, str, int, int], float] = {}
    samples: list[tuple[str, float]] = []
    target_set = set(target_names)

    for packet in packets:
        if UDP not in packet or DNS not in packet:
            continue
        dns = packet[DNS]
        name = query_name(packet)
        ip = ip_layer(packet)
        udp = packet[UDP]
        key = (int(dns.id), name, ip.src, ip.dst, int(udp.sport), int(udp.dport))
        if not dns.qr and name in target_set:
            queries[key] = float(packet.time)
            continue
        if dns.qr:
            reverse_key = (int(dns.id), name, ip.dst, ip.src, int(udp.dport), int(udp.sport))
            if reverse_key in queries:
                samples.append((name, (float(packet.time) - queries.pop(reverse_key)) * 1000))

    missing = target_set - {name for name, _ in samples}
    if missing:
        raise RuntimeError(f"Nao foi encontrada resposta para: {', '.join(sorted(missing))}")
    return [(name, next(rtt for candidate, rtt in samples if candidate == name)) for name in target_names]


def tcp_option_size(packets: list[Any]) -> tuple[int, int]:
    # A análise do TCP usa dataofs para medir o tamanho do cabecalho e subtrai os 20 bytes fixos
    sizes = [int(packet[TCP].dataofs) * 4 for packet in packets if TCP in packet and packet[TCP].dataofs]
    if not sizes:
        raise RuntimeError("Nenhum cabecalho TCP com tamanho decodificado foi encontrado.")
    header_size = Counter(sizes).most_common(1)[0][0]
    return header_size, header_size - 20


def plot_rtt(samples: list[tuple[str, float]], path: Path) -> None:
    labels = [name.removeprefix("https://") for name, _ in samples]
    values = [rtt for _, rtt in samples]
    plt.figure(figsize=(10, 5.5))
    bars = plt.bar(labels, values, color="tab:blue", alpha=0.85)
    plt.bar_label(bars, fmt="%.2f ms", padding=3)
    plt.xlabel("Dominio consultado")
    plt.ylabel("RTT (ms)")
    plt.title("UDP/DNS: tempo de resposta por dominio")
    plt.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def plot_header_sizes(tcp_options: int, path: Path) -> None:
    labels = [
        "Porta\norigem", "Porta\ndestino", "Comprimento/\nsequencia", "Checksum",
        "ACK", "Flags/\nreservado", "Janela", "Ponteiro\nurgente", "Opcoes",
    ]
    udp_values = [2, 2, 2, 2, 0, 0, 0, 0, 0]
    tcp_values = [2, 2, 4, 2, 4, 2, 2, 2, tcp_options]
    positions = range(len(labels))
    width = 0.38
    plt.figure(figsize=(11, 5.5))
    plt.bar([position - width / 2 for position in positions], udp_values, width, label="UDP", color="tab:orange")
    plt.bar([position + width / 2 for position in positions], tcp_values, width, label="TCP", color="tab:green")
    plt.xticks(list(positions), labels)
    plt.xlabel("Campo do cabecalho")
    plt.ylabel("Tamanho (bytes)")
    plt.title("UDP x TCP: tamanho dos campos do cabecalho")
    plt.legend()
    plt.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def analyze(capture_path: Path, output_dir: Path, tcp_capture: Path) -> None:
    packets = rdpcap(str(capture_path))
    tcp_packets = rdpcap(str(tcp_capture))
    target_names = select_target_names(packets)
    samples = find_rtt_samples(packets, target_names)
    tcp_header, tcp_options = tcp_option_size(tcp_packets)
    # A geração do relatório depende de três peças: filtragem do alvo, medição de RTT DNS e comparação
    # do overhead do cabeçalho TCP em relação ao UDP. Essas são as informações relevantes do experimento.
    output_dir.mkdir(parents=True, exist_ok=True)
    plot_rtt(samples, output_dir / "01_rtt_dns.png")
    plot_header_sizes(tcp_options, output_dir / "02_tamanho_campos_udp_tcp.png")
    print("RTTs: " + ", ".join(f"{name}={rtt:.2f} ms" for name, rtt in samples))
    print(f"Cabecalho TCP mais frequente: {tcp_header} bytes ({tcp_options} bytes de opcoes)")
    print(f"Arquivos gerados em: {output_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="arquivo UDP .pcap ou .pcapng")
    parser.add_argument("--tcp-capture", type=Path, default=Path("files/tcp-capture-lucas-felix.pcapng"))
    parser.add_argument("-o", "--output", type=Path, default=Path("graficos_udp"))
    args = parser.parse_args()
    analyze(args.capture, args.output, args.tcp_capture)


if __name__ == "__main__":
    main()