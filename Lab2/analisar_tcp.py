#!/usr/bin/env python3
"""Gera os graficos e uma analise inicial de um capture TCP.

Uso:
    python analisar_tcp.py files/tcp-capture-lucas-felix.pcapng
"""

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
    tcp = packet[TCP]
    if IP in packet:
        ip_layer = packet[IP]
    else:
        ip_layer = packet[IPv6]
    return (ip_layer.src, int(tcp.sport)), (ip_layer.dst, int(tcp.dport))


def packet_end_sequence(packet: Any) -> int:
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
        raise RuntimeError("O fluxo TCP escolhido nao possui segmentos de dados enviados pelo cliente.")

    client_packets.sort(key=lambda item: float(item["time"]))
    server_acks.sort()
    base_sequence = int(client_packets[0]["seq"])

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
    write_report(capture_path, output_dir / "analise_tcp.md", client, server, client_packets, rtt_samples, estimated, throughput)

    print(f"Fluxo cliente: {client[0]}:{client[1]} -> {server[0]}:{server[1]}")
    print(f"Segmentos de dados do cliente: {len(client_packets)}")
    print(f"Amostras de RTT: {len(rtt_samples)}")
    print(f"Arquivos gerados em: {output_dir}")


def plot_sequence(segments: list[dict[str, float | int]], base: int, path: Path) -> None:
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


def write_report(capture_path: Path, path: Path, client: tuple[str, int], server: tuple[str, int], segments: list[dict[str, float | int]], rtt: list[tuple[float, float]], estimated: list[float], throughput: list[tuple[float, float]]) -> None:
    total_bytes = sum(int(segment["length"]) for segment in segments)
    duration = max(float(segments[-1]["time"]), 1e-9)
    rates = [rate for _, rate in throughput if rate > 0]
    mean_rtt = (sum(value for _, value in rtt) / len(rtt) * 1000) if rtt else float("nan")
    max_rtt = (max(value for _, value in rtt) * 1000) if rtt else float("nan")
    first_rate = rates[0] if rates else 0
    last_rate = rates[-1] if rates else 0
    peak_rate = max(rates, default=0)
    peak_time = next((time for time, rate in throughput if rate == peak_rate), 0)

    phase_note = "A inspeção visual do gráfico 1 deve confirmar slow start (fleets crescentes) e a possível entrada em congestion avoidance (crescimento aproximadamente linear)."
    if len(rates) >= 2 and last_rate > first_rate * 1.5:
        phase_note = "O throughput termina acima do início, comportamento compatível com a expansão inicial da janela de congestionamento; use o gráfico 1 para separar slow start de congestion avoidance."
    elif len(rates) >= 2 and last_rate < first_rate * 0.7:
        phase_note = "O throughput termina abaixo do início, sugerindo perda, redução da janela ou fim da transferência; compare com os gaps/fleets do gráfico 1."

    outlier_note = "Nao foi possivel calcular RTT por ACK no fluxo selecionado."
    if rtt:
        outlier_note = f"O RTT medio foi {mean_rtt:.2f} ms e o maior valor foi {max_rtt:.2f} ms. Valores muito acima da media sao candidatos a outliers; a curva EstimatedRTT reage lentamente por usar alpha={ALPHA}."

    path.write_text(f"""# Analise da conexao TCP

Arquivo analisado: `{capture_path}`  
Ferramenta: Python com `scapy` para decodificacao do PCAPNG e `matplotlib` para os graficos. A escolha permite automatizar a identificacao do fluxo, o calculo de RTT e a reproducibilidade do relatorio.

Fluxo analisado: `{client[0]}:{client[1]}` -> `{server[0]}:{server[1]}`  
Segmentos de dados do cliente: {len(segments)}  
Bytes transferidos pelo cliente: {total_bytes}  
Duracao ate o ultimo segmento de dados: {duration:.3f} s

## 1. Numero de sequencia e fleets

![Sequencia](01_sequencia_fleets.png)

O grafico mostra os segmentos de dados enviados pelo cliente, com o numero de sequencia relativo ao primeiro segmento no eixo vertical. Agrupamentos quase verticais representam fleets: varios segmentos transmitidos em um intervalo curto. Espacos maiores entre agrupamentos indicam espera, por exemplo, devido ao ACK clocking, ao controle de congestionamento ou a uma retransmissao.

{phase_note} A periodicidade dos fleets deve ser relacionada ao RTT: em TCP, os ACKs liberam novos dados e a janela de congestionamento controla quantos bytes podem permanecer em voo. O grafico nao prova sozinho a fase exata, pois perdas, delayed ACK e limitacoes do emissor tambem podem produzir padroes semelhantes.

## 2. RTT e EstimatedRTT

![RTT](02_rtt_estimated_rtt.png)

O RTT por segmento foi estimado associando cada segmento de dados ao primeiro ACK posterior que confirma seu numero de sequencia final, aceitando ACK cumulativo. Foram obtidas {len(rtt)} amostras. {outlier_note} Pela formula do livro-texto, EstimatedRTT = (1 - alpha) * EstimatedRTT anterior + alpha * SampleRTT, com alpha = 0,125; portanto, a curva filtrada suaviza picos e atrasos isolados, mas tambem demora a acompanhar uma mudanca persistente.

## 3. Throughput

![Throughput](03_throughput.png)

O throughput foi calculado somando os bytes de dados enviados pelo cliente em janelas de 1 segundo. O total foi {total_bytes} bytes. A primeira janela nao nula foi {first_rate:.0f} bytes/s, o pico foi {peak_rate:.0f} bytes/s por volta de {peak_time:.1f} s e a ultima janela nao nula foi {last_rate:.0f} bytes/s.

A leitura conjunta deve comparar as barras com o grafico de sequencia: fleets mais densos e maiores tendem a elevar a taxa; gaps e fleets menores tendem a reduzi-la. Crescimento inicial e posterior estabilizacao sao coerentes com slow start seguido de congestion avoidance, enquanto quedas abruptas podem indicar perda ou esgotamento da aplicacao. A janela de 1 segundo reduz ruido, mas pode esconder variacoes em escala de RTT.

## Observacao metodologica

O script analisa apenas dados enviados pelo cliente detectado pelo primeiro SYN e ignora retransmissoes na contagem de bytes do throughput apenas na medida em que elas aparecem como bytes capturados; por isso, o valor representa bytes observados no capture, nao necessariamente bytes entregues unicos na aplicacao.
""", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="arquivo .pcap ou .pcapng")
    parser.add_argument("-o", "--output", type=Path, default=Path("graficos_tcp"), help="diretorio de saida")
    args = parser.parse_args()
    analyze(args.capture, args.output)


if __name__ == "__main__":
    main()
