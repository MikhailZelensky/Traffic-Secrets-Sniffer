# Traffic Secrets Sniffer

## Описание проекта

Этот проект представляет собой программу для перехвата сетевого трафика и извлечения конфиденциальных данных из популярных протоколов, таких как Telnet, FTP, HTTP, IMAP, POP3, SMTP, NTLM и Kerberos. Программа анализирует трафик в реальном времени или из файлов PCAP и пытается извлечь логины, пароли и хеши.

## Возможности

- Перехват логинов и паролей из:
  - Telnet
  - FTP
  - HTTP (включая Basic Authentication и POST-запросы)
  - IMAP
  - POP3
  - SMTP
- Извлечение посещенных URLs и поисковых запросов HTTP.
- Извлечение хэшей NTLM (v1 и v2) и Kerberos (etype 23 и 18).
- Поддержка анализа в реальном времени и загрузка из файлов PCAP.

## Примеры
```bash
# Выбрать интерфейс eth0
sudo python3 traffic_sniffer.py -i eth0
# Выбрать pcap файл
python3 traffic_sniffer.py -p pcapfile
```
## Требования

Для работы программы требуется Python 3.7+ и следующие библиотеки:

- `scapy>=2.4.5`


### Установка зависимостей

Убедитесь, что у вас установлены все зависимости. Вы можете установить их с помощью команды:

```bash
pip install -r requirements.txt
