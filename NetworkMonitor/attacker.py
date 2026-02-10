from scapy.all import IP, ICMP, send
import time

print("Запуск имитации атаки...")
# Цель — твой собственный компьютер
target_ip = "127.0.0.1"

for i in range(200):  # Увеличим до 200 для надежности
    send(IP(dst=target_ip)/ICMP(), verbose=0)
    if i % 10 == 0:
        print(f"Отправлено {i} пакетов...")
    time.sleep(0.01) # Очень маленькая пауза для высокой интенсивности

print("Атака завершена.")