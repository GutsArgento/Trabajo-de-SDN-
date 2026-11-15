#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import time
import random
from scapy.all import IP, TCP, UDP, ICMP, send

def generar_trafico_normal(ip_destino, duracion=15):
    print("[*] Iniciando trafico normal (intervalos aleatorios) hacia {} por {}s...".format(ip_destino, duracion))
    tiempo_fin = time.time() + duracion
    paquetes_enviados = 0
    
    while time.time() < tiempo_fin:
        # Paquete TCP hacia puerto 80 o 443 con intervalos irregulares
        puerto = random.choice([80, 443, 8080])
        pkt = IP(dst=ip_destino)/TCP(dport=puerto, flags="S")
        send(pkt, verbose=False)
        paquetes_enviados += 1
        # Espera aleatoria entre 0.05s y 0.8s (sin periodicidad fija)
        time.sleep(random.uniform(0.05, 0.8))
        
    print("[+] Trafico normal finalizado. Paquetes enviados: {}".format(paquetes_enviados))

def generar_trafico_anomalo_periodico(ip_destino, frecuencia_hz=2.0, duracion=15):
    periodo = 1.0 / frecuencia_hz
    print("[*] Iniciando trafico automatizado periodico (f = {} Hz, T = {} s) hacia {}...".format(
        frecuencia_hz, periodo, ip_destino))
    tiempo_fin = time.time() + duracion
    paquetes_enviados = 0
    
    while time.time() < tiempo_fin:
        inicio_ciclo = time.time()
        # Rafaga de 5 paquetes UDP/ICMP simulando baliza de exfiltracion o C2
        for _ in range(5):
            pkt = IP(dst=ip_destino)/UDP(dport=5353)/b"BEACON_DATA_PAYLOAD"
            send(pkt, verbose=False)
            paquetes_enviados += 1
            
        # Ajustar el tiempo de espera para mantener el periodo exacto
        transcurrido = time.time() - inicio_ciclo
        if transcurrido < periodo:
            time.sleep(periodo - transcurrido)
            
    print("[+] Trafico periodico finalizado. Paquetes enviados: {}".format(paquetes_enviados))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 generador_trafico.py <normal|periodico> <IP_DESTINO> [duracion_seg]")
        sys.exit(1)
        
    modo = sys.argv[1].lower()
    destino = sys.argv[2]
    duracion = int(sys.argv[3]) if len(sys.argv) > 3 else 15
    
    if modo == "normal":
        generar_trafico_normal(destino, duracion)
    elif modo == "periodico":
        generar_trafico_anomalo_periodico(destino, frecuencia_hz=2.0, duracion=duracion)
    else:
        print("Modo no reconocido. Use 'normal' o 'periodico'.")
