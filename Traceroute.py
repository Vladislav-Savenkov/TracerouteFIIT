from scapy.all import IP, ICMP, sr1, RandString
from ipwhois import IPWhois
import socket
class Traceroute:
    def __init__(self,
                 packet_info: dict,
                 ttl: int,
                 interval_between_seconds: int,
                 max_ttl: int,
                 check_as: bool):
        self.packet_info = packet_info
        self.ttl = ttl
        self.interval_between_seconds = interval_between_seconds
        self.max_ttl = max_ttl
        self.check_as = check_as

    @staticmethod
    def format_output_row(ttl, response, check_as):
        formatted_ttl = str(ttl).ljust(6)
        result = formatted_ttl
        ip, response_time = response

        if ip is None:
            formatted_address = "*".ljust(18)
        else:
            formatted_address = ip.ljust(18)
        result += formatted_address

        if response_time is None:
            formatted_time = "*".ljust(6)
        else:
            formatted_time = str(response_time).ljust(6)
        result += formatted_time

        if check_as and ip is not None:
            as_number = Traceroute.perform_whois_query(ip)
            if as_number == '' or as_number == None:
                result += '*'
            else:
                result += str(as_number).ljust(6)
        else:
            result += "*".ljust(6)

        return result


    @staticmethod
    def get_whois_server(ip_address):
        """Определяет подходящий WHOIS сервер на основе первого октета IP адреса."""
        first_octet = int(ip_address.split('.')[0])
        if 0 <= first_octet <= 127:
            # ARIN
            return 'whois.arin.net'
        elif 128 <= first_octet <= 191:
            # RIPE NCC
            return 'whois.ripe.net'
        elif 192 <= first_octet <= 223:
            # APNIC
            return 'whois.apnic.net'
        else:
            # Остальные случаи
            return 'whois.arin.net'

    @staticmethod
    def perform_whois_query(ip_address):
        """
        Выполняет WHOIS запрос и извлекает номер автономной системы.

        Args:
            ip_address (str): IP адрес для выполнения WHOIS запроса.

        Returns:
            str: Номер автономной системы или None, если информация не найдена.
        """
        whois_server = Traceroute.get_whois_server(ip_address)
        port = 43
        try:
            # Создаем TCP/IP сокет и подключаемся к WHOIS серверу
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((whois_server, port))
                # Отправляем форматированный запрос
                query = f'n + {ip_address}\r\n' if 'arin' in whois_server else f'-V Md5.5.7 {ip_address}\r\n'
                sock.send(query.encode('utf-8'))

                # Получаем и собираем ответ
                response = b''
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data

                return Traceroute.parse_asn(response.decode('utf-8'))
        except Exception as e:
            return None

    @staticmethod
    def parse_asn(whois_data):
        """Парсит данные WHOIS для извлечения номера автономной системы."""
        for line in whois_data.splitlines():
            if 'OriginAS' in line or 'origin:' in line:
                return line.split(': ')[1].strip()[2:]
        return None

    def create_icmp_packet(self, ttl):
        destination_ip = self.packet_info['ip']
        payload_length = self.packet_info['length']
        sequence_number = self.packet_info['seq']
        random_payload = RandString(payload_length - 28)

        return IP(dst=destination_ip, ttl=ttl) / ICMP(seq=sequence_number) / str(random_payload)

    def send_icmp_and_measure_response_time(self, icmp_packet):
        response = sr1(icmp_packet, timeout=self.ttl, verbose=0)
        if response:
            response_time = round((response.time - icmp_packet.sent_time) * 1000)
            source_address = response[IP].src
        else:
            response_time = None
            source_address = None

        return source_address, response_time

    def execute_traceroute(self):
        target_ip = self.packet_info['ip']
        last_responding_ip = None

        for current_ttl in range(1, self.max_ttl + 1):
            icmp_packet = self.create_icmp_packet(current_ttl)
            current_response = self.send_icmp_and_measure_response_time(icmp_packet)
            current_ip, _ = current_response

            print(self.format_output_row(current_ttl, current_response, self.check_as))
            if current_ip == target_ip or current_ip == last_responding_ip and current_ip:
                break

