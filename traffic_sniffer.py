import asyncio
from scapy.all import sniff, PcapReader, IP, TCP, Raw
import re
import logging
import argparse
import struct
import binascii
import base64
from urllib.parse import unquote
from scapy.layers.kerberos import KRB_AS_REQ

logging.basicConfig(filename='secrets_found.txt', level=logging.INFO)

telnet_sessions = {}

imap_session = {}

ntlm_challenges = {}

smtp_sessions = {}

pop3_failure_list = []

# Регулярные выражения для извлечения данных Telnet
telnet_login = re.compile(r'login:\s*$', re.IGNORECASE)
telnet_password = re.compile(r'password:\s*$', re.IGNORECASE)

# Регулярные выражения для FTP, SMTP
ftp_login = re.compile(r'USER\s+(\S+)', re.IGNORECASE)
ftp_pass = re.compile(r'PASS\s+(\S+)', re.IGNORECASE)
smtp_login = re.compile(r'AUTH\s+LOGIN\s+(\S+)', re.IGNORECASE)

# Регулярные выражения для HTTP
http_basic_auth = re.compile(r'Authorization:\s*Basic\s+(\S+)', re.IGNORECASE)
http_url_pattern = re.compile(r'(GET|POST|HEAD)\s+(\S+)\s+HTTP\/1\.\d', re.IGNORECASE)
htt_url_host = re.compile(r'Host:\s+(\S+)', re.IGNORECASE)
http_post_data_pattern = re.compile(r'([^&]+)=([^&]+)')

# Регулярное выражение для поисковых запросов
search_query_pattern = re.compile(
    r'(?:[\?&](q|query|search|searchterm|keywords|keyword|searchPhrase|search\?p|terms|keys|kwd|question)=([^&]+))')

# Регулярные выражения для POP3
pop3_user = re.compile(r'USER\s(\S+)', re.IGNORECASE)
pop3_pass = re.compile(r'PASS\s+(\S+)', re.IGNORECASE)

# Регулярные выражения для проверки авторизации
ftp_success = re.compile(r'230\s', re.IGNORECASE)
ftp_failure = re.compile(r'530\s', re.IGNORECASE)
smtp_success = re.compile(r'235\s', re.IGNORECASE)
smtp_failure = re.compile(r'535|501\s', re.IGNORECASE)
pop3_success = re.compile(r'\+OK Logged in', re.IGNORECASE)
pop3_failure = re.compile(r'\-ERR \[AUTH\]', re.IGNORECASE)

# Регулярные выражения для поиска NTLM
ntlm_challenge_pattern = re.compile(rb'NTLMSSP\x00\x02\x00\x00\x00', re.IGNORECASE)  # NTLM Challenge
ntlm_authenticate_pattern = re.compile(rb'NTLMSSP\x00\x03\x00\x00\x00', re.IGNORECASE)  # NTLM Authenticate
ntlm_http_auth_pattern = re.compile(rb'NTLM\s+([A-Za-z0-9+/=]+)', re.IGNORECASE)


async def process_telnet_session(src, dst, payload):
    """Обработка и отслеживание сессий Telnet"""
    if (src, dst) not in telnet_sessions:
        telnet_sessions[src, dst] = {
            "login": "", 
            "password": "", 
            "stage": "waiting_for_login",
        }

    session = telnet_sessions[src, dst]

    if session["stage"] == "waiting_for_login" and telnet_login.search(payload):
        session["stage"] = "waiting_for_password"
        if (dst, src) not in telnet_sessions:
            telnet_sessions[dst, src] = {
            "login": "", 
            "password": "", 
            "stage": "",
            }
        telnet_sessions[dst, src]["stage"] = "collecting_login"
        telnet_sessions[dst, src]["login"] = ""
        

    elif session["stage"] == "collecting_login":
        session["login"] += payload
        if "\r" in session["login"] or "\n" in session["login"]:
            session["login"] = session["login"].strip("\r\n")
            print(f"[+] Telnet login найден: {session['login']} src:{src} dst:{dst}")
            logging.info(f"telnet_login: {session['login']} src:{src} dst:{dst}")
            session["stage"] = ""
            

    elif session["stage"] == "waiting_for_password" and telnet_password.search(payload):
        telnet_sessions[dst, src]["stage"] = "collecting_password"
        del telnet_sessions[src, dst]
        telnet_sessions[dst, src]["password"] = ""
        

    elif session["stage"] == "collecting_password":
        session["password"] += payload
        if "\r" in session["password"] or "\n" in session["password"]:
            session["password"] = session["password"].strip("\r\n")
            print(f"[+] Telnet пароль найден для {session['login']}: {session['password']}   src:{src} dst:{dst}")
            logging.info(f"telnet_login: {session['login']}, telnet_pass: {session['password']} src:{src} dst:{dst}")
            del telnet_sessions[src, dst]
            
    

async def process_ftp_packet(src, dst, payload):
    """Обработка FTP пакетов для извлечения логинов и паролей"""
    user_match = ftp_login.search(payload)
    pass_match = ftp_pass.search(payload)

    if user_match:
        user = user_match.group(1)
        print(f"[+] FTP User найден: {user} src:{src} dst:{dst}")
        logging.info(f"ftp_user: {user} src:{src} dst:{dst}")

    elif pass_match:
        password = pass_match.group(1)
        print(f"[+] FTP Password найден: {password} src:{src} dst:{dst}")
        logging.info(f"ftp_pass: {password} src:{src} dst:{dst}")

    elif ftp_success.search(payload):
        print(f"[+] FTP авторизация прошла успешна для src:{dst} dst:{src}")
        logging.info(f"ftp_auth_success: src:{dst} dst:{src}")
    elif ftp_failure.search(payload):
        print(f"[+] FTP авторизация не прошла для src:{dst} dst:{src}")
        logging.info(f"ftp_auth_failure: src:{dst} dst:{src}")

async def process_smtp_packet(src, dst, payload):
    """Обработка SMTP пакетов для извлечения данных авторизации"""
    login_match = smtp_login.search(payload)
    if 'AUTH LOGIN' == payload.strip("\r\n"):
        smtp_sessions[src, dst] = 'next_pkt'
    elif (src, dst) in smtp_sessions and smtp_sessions[src, dst] == 'next_pkt':
        login = decode_payload(payload)
        smtp_sessions[src, dst] = {'login' : login, 'passwd':''}
    elif login_match:
        login = decode_payload(login_match.group(1))
        smtp_sessions[src, dst] = {'login' : login, 'passwd':''}
    elif (src, dst) in smtp_sessions:
        login = smtp_sessions[src, dst]['login']
        passwd = decode_payload(payload)
        smtp_sessions[src, dst]['passwd'] = passwd
        print(f"[+] SMTP Auth найдено: login:{login} pass:{passwd} src:{src} dst:{dst}")
        logging.info(f"smtp_auth: login:{login} pass:{passwd} src:{src} dst:{dst}")
    if smtp_success.search(payload) and (dst, src) in smtp_sessions:
        print(f"[+] SMTP авторизация прошла успешна для src:{dst} dst:{src}")
        logging.info(f"smtp_auth_success: src:{dst} dst:{src}")
        del smtp_sessions[dst, src]
    if smtp_failure.search(payload) and (dst, src) in smtp_sessions:
        if smtp_sessions[dst, src]['passwd']:
            print(f"[+] SMTP авторизация не прошла для src:{dst} dst:{src}")
            logging.info(f"smtp_auth_failure: src:{dst} dst:{src}")
        del smtp_sessions[dst, src]

async def process_pop3_packet(src, dst, payload):
    """Обработка POP3 пакетов для извлечения логинов и паролей"""
    user_match = pop3_user.search(payload)
    pass_match = pop3_pass.search(payload)

    if user_match:
        user = user_match.group(1)
        print(f"[+] POP3 User найден: {user} src:{src} dst:{dst}")
        logging.info(f"pop3_user: {user} src:{src} dst:{dst}")

    elif pass_match:
        password = pass_match.group(1)
        print(f"[+] POP3 Password найден: {password} src:{src} dst:{dst}")
        logging.info(f"pop3_pass: {password} src:{src} dst:{dst}")

    elif pop3_success.search(payload):
        print(f"[+] POP3 авторизация успешна для src:{dst} dst:{src}")
        logging.info(f"pop3_auth_success: src:{dst} dst:{src}")
    
    elif pop3_failure.search(payload):
        if src not in pop3_failure_list:
            print(f"[+] POP3 авторизация не прошла для src:{dst} dst:{src}")
            logging.info(f"pop3_auth_failure: src:{dst} dst:{src}")
            pop3_failure_list.append(src)

def decode_payload(payload):
    try:
        base64_credentials = payload.strip("\r\n")
        decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
    except Exception:
        decoded_credentials = False
    finally:
        return decoded_credentials
    
async def process_imap_packet(src, dst, payload):
    """Обработка IMAP пакетов для извлечения логинов и паролей"""
    if (src, dst) not in imap_session:
        imap_session[src, dst] = "waiting request"
    
    if imap_session[src, dst] == "waiting request":
        if "authenticate PLAIN" in payload:
            imap_session[src, dst] = "waiting credentials"
    elif imap_session[src, dst] == "waiting credentials":
        decoded_credentials = decode_payload(payload)
        if decoded_credentials:
            if '\x00' in decoded_credentials:
                login, password = decoded_credentials.split('\x00')[1:]
            else:
                login, password = decoded_credentials.split(' ')
            print(f"[+] IMAP Login найден: {login}, Password: {password} src:{src}, dst:{dst}")
            logging.info(f"imap_login: {login}, imap_pass: {password} src:{src},  dst:{dst}")
            imap_session[src, dst] = "result authenticated"
              
    if (dst, src) in imap_session and imap_session[dst, src] == "result authenticated":
        if "OK [" in payload:
            print(f"[+] IMAP авторизация успешна для src:{dst} dst:{src}")
            logging.info(f"imap_auth_success: src:{dst} dst:{src}")
            del imap_session[dst, src]
        elif "NO [" in payload:
            print(f"[+] IMAP авторизация не прошла для src:{dst} dst:{src}")
            logging.info(f"imap_auth_failure: src:{dst} dst:{src}")
            del imap_session[dst, src]

async def process_http_packet(src, dst, payload):
    """Обработка HTTP пакетов для нахождения URL, POST-запросов, логинов/паролей"""
    # Поиск посещённого URL
    url_match = http_url_pattern.search(payload)
    host_match = htt_url_host.search(payload)
    if host_match:
        host = host_match.group(1)
    if url_match:
        method = url_match.group(1)
        url = url_match.group(2)
        exclude_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.woff', '.woff2', '.ttf', '.svg')
        if not url.endswith(exclude_extensions) and 'ocsp' not in payload:
            full_url = host + url
            print(f"[+] HTTP {method} запрос на URL: {full_url} src:{src}")
            logging.info(f"http_{method.lower()}_url: {full_url} src:{src}")
        
        # Нахождение поисковых запросов
        if "GET" in payload:
            search_query = re.search(search_query_pattern, url)
            if search_query:
                query = unquote(search_query.group(2))
                print(f"[+] Найден поисковый запрос: {query} src:{src}")
                logging.info(f"http_search_query: {query} src:{src}")

    # Поиск базовой HTTP аутентификации
    auth_match = http_basic_auth.search(payload)
    if auth_match:
        encoded_credentials = auth_match.group(1)
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8', errors='ignore')
        print(f"[+] HTTP Basic Auth найдено: {decoded_credentials} src:{src}, dst:{dst}")
        logging.info(f"http_basic_auth: {decoded_credentials} src:{src}, dst:{dst}")

    # Анализ POST-запросов и нахождение логинов/паролей в формах
    if "POST" in payload:
        headers_end = payload.find("\r\n\r\n")
        if headers_end != -1:
            post_data = payload[headers_end+4:]
            post_fields = http_post_data_pattern.findall(post_data)
            if post_fields:
               print(f"[+] Найдены данные POST-запроса: {post_fields} src:{src}, dst:{dst}")
               logging.info(f"http_post_data: {post_fields} src:{src}, dst:{dst}")
               for key, value in post_fields:
                  if "user" in key.lower() or "login" in key.lower():
                        print(f"[+] Найден логин: {value} {src} {dst}")
                        logging.info(f"http_login: {value} {src} {dst}")
                  if "pass" in key.lower() or "pwd" in key.lower():
                        print(f"[+] Найден пароль: {value} src:{src}, dst:{dst}")
                        logging.info(f"http_password: {value} src:{src}, dst:{dst}")



async def extract_ntlm_challenge(src, dst, payload):
    """Извлечение NTLM Challenge из сообщения."""
    start = ntlm_challenge_pattern.search(payload).start()
    server_challenge = payload[start+24:start+32]
    ntlm_challenges[dst, src] = binascii.hexlify(server_challenge).decode()
    

async def extract_ntlm_response(src, dst, payload):
    """Извлечение NTLM Response, имени пользователя и домена из NTLMSSP_AUTH сообщения"""
    start = ntlm_authenticate_pattern.search(payload).start()
    lm_len, lm_max_len, lm_offset = struct.unpack("<HHI", payload[start+12:start+20])
    nt_len, nt_max_len, nt_offset = struct.unpack("<HHI", payload[start+20:start+28])
    dom_len, dom_max_len, dom_offset = struct.unpack("<HHI", payload[start+28:start+36])
    user_len, user_max_len, user_offset = struct.unpack("<HHI", payload[start+36:start+44])

    lm_hash = binascii.hexlify(payload[start + lm_offset:start + lm_offset + lm_len]).decode()
    nt_hash = binascii.hexlify(payload[start + nt_offset:start + nt_offset + nt_len]).decode()
    domain = payload[start+ dom_offset:start + dom_offset + dom_len].decode('utf-16le', errors='ignore')
    user = payload[start + user_offset:start + user_offset + user_len].decode('utf-16le', errors='ignore')
    if (src, dst) in ntlm_challenges:
        challenge = ntlm_challenges[src, dst]
        del ntlm_challenges[src, dst]
    else:
        challenge = 'challenge not found'
    if not user:
        return
    if nt_len == 24:
        print(f"[+] Найден NTLMv1 от {src} -> {dst}:\n{user}::{domain}:{lm_hash}:{nt_hash}:{challenge}")
        logging.info(f"NTLMv1 {src} -> {dst}:\n{user}::{domain}:{lm_hash}:{nt_hash}:{challenge}")
    elif nt_len > 24:
        print(f"[+] Найден NTLMv2 от {src} -> {dst}:\n{user}::{domain}:{challenge}:{nt_hash[:32]}:{nt_hash[32:]}")
        logging.info(f"NTLMv2 {src} -> {dst}:\n{user}::{domain}:{challenge}:{nt_hash[:32]}:{nt_hash[32:]}")
    else:
        print(f"[+] Неизвестный тип хэша от {src} -> {dst}:\n LM Hash: {lm_hash}\n NT Hash: {nt_hash}\n Domain: {domain}\n User: {user}")
        logging.info(f"Unknown NTLM {src} -> {dst}:\n LM Hash: {lm_hash}\n NT Hash: {nt_hash}\n Domain: {domain}\n User: {user}")



async def extract_kerberos_as_req(payload, src, dst):
    """Парсинг Kerberos AS-REQ пакета и извлечение хеша"""
    MsgType = payload[17:18]
    EncType = payload[39:40]
    MessageType = payload[28:29]

    if MsgType == b"\x0a" and EncType == b"\x17" and MessageType == b"\x02":
        HashLen = struct.unpack('<B', payload[43:44])[0]
        Hash = payload[44:44 + HashLen]
        SwitchHash = Hash[16:] + Hash[:16]

        NameLen = struct.unpack('<B', payload[144:145])[0]
        Name = payload[145:145 + NameLen].decode('utf-8', errors='ignore')

        DomainLen = struct.unpack('<B', payload[145 + NameLen + 3:145 + NameLen + 4])[0]
        Domain = payload[145 + NameLen + 4:145 + NameLen + 4 + DomainLen].decode('utf-8', errors='ignore')

        BuildHash = f"$krb5pa$23${Name}${Domain}$dummy${SwitchHash.hex()}"
        print(f"[+] Перехвачен хэш Kerberos 5, etype 23: {BuildHash}, src: {src}, dst: {dst}")
        logging.info(f"MS Kerberos Hash (etype 23): {BuildHash}, src: {src}, dst: {dst}")

    if MsgType == b"\x0a" and EncType == b"\x12" and MessageType == b"\x02":
        HashLen = struct.unpack('<B', payload[43:44])[0]
        Hash = payload[44:44 + HashLen]

        NameLen = struct.unpack('<B', payload[148:149])[0]
        Name = payload[149:149 + NameLen].decode('utf-8', errors='ignore')

        DomainLen = struct.unpack('<B', payload[149 + NameLen + 3:149 + NameLen + 4])[0]
        Domain = payload[149 + NameLen + 4:149 + NameLen + 4 + DomainLen].decode('utf-8', errors='ignore')

        BuildHash = f"$krb5pa$18${Name}${Domain}${Hash.hex()}"
        print(f"[+] Перехвачен хэш Kerberos 5, etype 18: {BuildHash}, src: {src}, dst: {dst}")
        logging.info(f"MS Kerberos Hash (etype 18): {BuildHash}, src: {src}, dst: {dst}")


async def process_packet(packet):
    """Обработка пакетов для поиска секретов"""
    try:
        if packet.haslayer(TCP):
            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst =f"{packet[IP].dst}:{packet[TCP].dport}"
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                # Обработка Telnet
                if "telnet" in packet.summary().lower():
                    await process_telnet_session(src, dst, payload.decode('utf-8', errors='ignore'))

                # Обработка FTP
                elif "ftp" in packet.summary().lower():
                    await process_ftp_packet(src, dst, payload.decode('utf-8', errors='ignore'))

                # Обработка SMTP
                elif "smtp" in packet.summary().lower():
                    await process_smtp_packet(src, dst, payload.decode('utf-8', errors='ignore'))

                # Обработка POP3
                elif "pop" in packet.summary().lower():
                    await process_pop3_packet(src, dst, payload.decode('utf-8', errors='ignore'))

                # Обработка IMAP
                elif "imap" in packet.summary().lower():
                    await process_imap_packet(src, dst, payload.decode('utf-8', errors='ignore'))

                # Обработка NTLM
                elif ntlm_authenticate_pattern.search(bytes(payload)):
                    await extract_ntlm_response(src, dst, payload)
                elif ntlm_challenge_pattern.search(bytes(payload)):
                    await extract_ntlm_challenge(src, dst, payload)  

                elif "smb" in packet.summary().lower():
                    name = packet.getlayer(-2)
                    payload = bytes(packet[name])
                    if ntlm_authenticate_pattern.search(payload):
                        await extract_ntlm_response(src, dst, payload)

                    if ntlm_challenge_pattern.search(payload):
                        await extract_ntlm_challenge(src, dst, payload)
                
                # Обработка HTTP
                elif "http" in packet.summary().lower() and "https" not in packet.summary().lower():
                    if b'WWW-Authenticate: NTLM' in payload:
                        ntlm_msg = ntlm_http_auth_pattern.search(payload).group(1)
                        ntlm_msg = base64.b64decode(ntlm_msg)
                        if ntlm_challenge_pattern.search(ntlm_msg):
                            await extract_ntlm_challenge(src, dst, ntlm_msg)
                    elif b'Authorization: NTLM' in payload:
                        ntlm_msg = ntlm_http_auth_pattern.search(payload).group(1)
                        ntlm_msg = base64.b64decode(ntlm_msg)
                        if ntlm_authenticate_pattern.search(ntlm_msg):
                            await extract_ntlm_response(src, dst, ntlm_msg)
                    else:
                        await process_http_packet(src, dst, payload.decode('utf-8', errors='ignore'))
            
            # Обработка Kerberos
            elif packet.haslayer(KRB_AS_REQ):
                await extract_kerberos_as_req(bytes(packet[KRB_AS_REQ]), src, dst)
            
            # Обработка NTLM
            elif "smb" in packet.summary().lower() or "ldap" in packet.summary().lower():
                name = packet.getlayer(-1)
                payload = bytes(packet[name])
                if ntlm_authenticate_pattern.search(payload):
                    await extract_ntlm_response(src, dst, payload)

                if ntlm_challenge_pattern.search(payload):
                    await extract_ntlm_challenge(src, dst, payload)
                    
            
    except Exception as e:
        logging.error(f"Ошибка при обработке пакета: {str(e)}, {packet}")

async def sniff_packets(interface=None):
    """Захват пакетов с интерфейса"""
    # Список задач для обработки пакетов
    tasks = []
    try:
        def handle_packet(packet):
            # Создаем задачу для каждого пакета
            task = asyncio.create_task(process_packet(packet))
            tasks.append(task)

        # Захват пакетов с интерфейса
        sniff(iface=interface, prn=handle_packet, store=False)

    except Exception as e:
        print(f"Ошибка при захвате пакетов: {e}")
    
    # Ожидание завершения всех задач
    if tasks:
        await asyncio.gather(*tasks)

async def read_pcap_file(pcap_file):
    """Чтение и обработка пакетов из PCAP файла"""
    with PcapReader(pcap_file) as packets:
        for packet in packets:
            await process_packet(packet)

def parse_args():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(description="Анализатор трафика для поиска секретов.")
    parser.add_argument("-i", "--interface", help="Сетевой интерфейс для захвата пакетов.")
    parser.add_argument("-p", "--pcap", help="Файл PCAP для анализа.")
    return parser.parse_args()


def main():
    """Основная функция"""
    args = parse_args()
    loop = asyncio.get_event_loop()

    try:
        if args.pcap:
            loop.run_until_complete(read_pcap_file(args.pcap))
        elif args.interface:
            loop.run_until_complete(sniff_packets(args.interface))
        else:
            print("[-] Укажите либо интерфейс (-i), либо PCAP файл (-p).")
    except KeyboardInterrupt:
        print("Сниффер остановлен.")
    finally:
        loop.close()

if __name__ == "__main__":
    main()
