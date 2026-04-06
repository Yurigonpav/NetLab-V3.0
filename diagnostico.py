# diagnostico.py
# Testa TODAS as interfaces disponíveis e identifica quais capturam tráfego.
# Execute como Administrador.

import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

from scapy.all import get_if_list, AsyncSniffer, conf
conf.verb     = 0
conf.use_pcap = True

print("=" * 60)
print("DIAGNÓSTICO NETLAB EDUCACIONAL — TODAS AS INTERFACES")
print("=" * 60)

interfaces = get_if_list()
print(f"\n{len(interfaces)} interface(s) encontrada(s).\n")
print("Testando cada interface por 4 segundos...")
print("IMPORTANTE: enquanto cada teste roda, abra um site no navegador.\n")

interfaces_com_trafego = []

for i, iface in enumerate(interfaces):
    print(f"[{i}] Testando: {iface} ... ", end="", flush=True)
    try:
        sniffer = AsyncSniffer(iface=iface, store=True, quiet=True)
        sniffer.start()
        time.sleep(4)
        sniffer.stop()
        qtd = len(sniffer.results) if sniffer.results else 0
        if qtd > 0:
            print(f"{qtd} pacote(s) capturado(s) — INTERFACE ATIVA")
            interfaces_com_trafego.append((i, iface, qtd))
        else:
            print(f"❌ 0 pacotes — interface inativa ou sem tráfego")
    except Exception as e:
        print(f"Erro: {e}")

print("\n" + "=" * 60)
print("RESULTADO FINAL")
print("=" * 60)

if interfaces_com_trafego:
    print("\nInterfaces com tráfego detectado:")
    for idx, iface, qtd in interfaces_com_trafego:
        print(f"  [{idx}] {iface}  ({qtd} pacotes)")
    print("\nUse a interface acima no combo 'Interface de Rede' do NetLab.")
    print("Copie o nome exato incluindo '\\Device\\NPF_...'")
else:
    print("\nNenhuma interface capturou pacotes.")
    print("\nVerifique:")
    print("  1. Este script está sendo executado como Administrador?")
    print("  2. O Npcap está instalado? Baixe em: https://npcap.com")
    print("  3. Durante a instalação do Npcap, 'WinPcap API-compatible")
    print("     mode' estava marcado?")
    print("  4. Tente reinstalar o Npcap marcando essa opção.")

input("\nPressione Enter para sair...")


