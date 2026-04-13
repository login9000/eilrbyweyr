# -*- coding: utf-8 -*-

import sys
import time
import random
from scapy.all import bind_layers, IP, TCP, sr1, send, Raw, AsyncSniffer, Packet # pip3 install scapy
from scapy.layers.tls.all import *
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization
import socket
import gzip
import struct


bind_layers(TCP, TLS, sport = 443)
bind_layers(TCP, TLS, dport = 443)

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

# по результатам тестов в wireshark определил что mss = 1452 обычно означает если мы НЕ С ПРОКСИ отправляем запрос, 
# ... 1460 - если мы с прокси
mss = 1452

# ... window = 64240 - если мы НЕ С ПРОКСИ а WScale при этом обычно равен 256 а так же отсуствуют Timestamp
# ... window = 29200 -  если мы с прокси WScale при этом равен 128 и используются Timestamp (в chrome по крайней мере, в Firefox он есть)
window = 64240 # можно подставить None и в таком случае OS сама определит это значение

# при значении равном 7 , WScale по факту в tcp пакете будет виден как равный 128
# при значении равном 8  , WScale по факту в tcp пакете будет виден как равный 256
wscale = 8

iface = 'ens3'
source_port = random.randint(1024, 65535)
dist_port = 443
dist_ip = '109.71.247.42'
servername = 'escape-iq.com'
is_send_fin = False
is_connection_reset = False
received_data = b''
is_complete_received_data = False
headers = [
	'GET / HTTP/1.1',
	'Accept: */*',
	'Accept-Encoding: gzip',
	'Accept-Language: ru,en-US;q=0.9,en;q=0.8,en-GB;q=0.7',
	'Connection: keep-alive',
	f'Host: {dist_ip}',
	'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
	'',
	''
]
private_key = b''
session_id_tls = b''
ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]

def is_port_free(port: int) -> bool:
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		try:
			s.bind(('0.0.0.0', port))
			return True
		except socket.error:
			return False

attempts = 0

while not is_port_free(source_port):

	source_port = random.randint(1024, 65535)
	attempts += 1
	if attempts > 100:
		print('\n[!] ОШИБКА: Не удалось найти свободный порт!')
		sys.exit(1)

print(f'[*] Выбран свободный порт: {source_port}')

def get_options(packet: Packet) -> list:
	
	tcp_options = dict(packet[TCP].options)
	srv_ts_data = tcp_options.get('Timestamp')
	if srv_ts_data:
		return [('Timestamp', (int(time.time() * 1000) & 0xFFFFFFFF, srv_ts_data[0]))]
	return []

def is_http_complete(data: bytes) -> bool:
	
	if b'\r\n\r\n' not in data:
		return False
	
	header_part, body_part = data.split(b'\r\n\r\n', 1)
	headers = header_part.decode(errors = 'ignore')
	
	if 'Transfer-Encoding: chunked' in headers:
		return body_part.endswith(b'0\r\n\r\n')
	
	if 'Content-Length:' in headers:
		try:
			content_length = int(headers.split('Content-Length:')[1].split('\r\n')[0].strip())
			return len(body_part) >= content_length
		except:
			return False
				
	return False

def check_hrr_group(packet: Packet) -> list:

	if packet.haslayer(TLS) and packet.haslayer(Raw):

		raw_data = packet[Raw].load

		if b'\xcf!\xadt\xe5\x9aa\x11\xbe\x1d\x8c\x02\x1e' in raw_data:

			index = raw_data.find(b'\x00\x33\x00\x02')
			if index != -1:
				
				group_id = int.from_bytes(raw_data[index + 4:index + 6], byteorder='big')
				groups = {0x001d: 'x25519', 0x0017: 'secp256r1', 0x0018: 'secp384r1'}
				group_name = groups.get(group_id, 'Unknown')
				return [group_name, group_id]
			
			else:

				return [None, '?']
			
		else:
			return [None, '?']
		
	return ['Unknown', '?']

def handle_server_packet(packet: Packet) -> None:
	
	global is_send_fin, received_data, is_connection_reset, next_seq, next_ack, is_complete_received_data

	if not packet.haslayer(TCP) or (packet[TCP].flags & SYN):
		return

	if packet.haslayer(TLS):
		
		group_name, group_id = check_hrr_group(packet)
		if group_name:

			if group_name == 'Unknown':
				return

			payload_len = len(packet[Raw].load) if packet.haslayer(Raw) else 0
			next_seq = packet[TCP].ack
			next_ack = packet[TCP].seq + payload_len
			create_tls_packet(packet, next_seq, next_ack, group_name)

			return
			
	if packet[TCP].flags & RST:
		print(f'\n[!] ОШИБКА: Сервер принудительно разорвал соединение (RST)!')
		is_connection_reset = True
		return 'stop'

	payload = packet[Raw].load if packet.haslayer(Raw) else b''
	payload_len = len(payload)
	if payload:
		received_data += payload

	current_ack = packet[TCP].seq + payload_len
	current_seq = packet[TCP].ack if packet[TCP].flags & ACK else next_seq

	if not is_complete_received_data and is_http_complete(received_data):

		options = get_options(packet)
		is_complete_received_data = True

		res = TCP(sport = source_port, dport = dist_port, flags = 'FA', seq = current_seq, ack = current_ack, window = window, options = options)
		send(ip / res, verbose = False)
		
		is_send_fin = True
		return 'stop'

	if packet[TCP].flags & FIN:
		current_ack += 1

	if (packet[TCP].flags & PSH) or (packet[TCP].flags & FIN):
		
		options = get_options(packet)
		flags = 'FA' if (packet[TCP].flags & FIN) else 'A'
		
		res = TCP(sport = source_port, dport = dist_port, flags = flags, seq = current_seq, ack = current_ack, window = window, options = options)
		send(ip / res, verbose = False)
		
		if packet[TCP].flags & FIN:
			is_send_fin = True
			return 'stop'

def _IP(dst: str):

	return IP(
		dst = dst
	)

	# return IP(
	# 	version = 4,              # Версия IP (обычно 4)
	# 	ihl = 5,                  # Internet Header Length (обычно 5, если нет опций)
	# 	tos = 0x0,                # Type of Service (приоритет трафика)
	# 	len = None,               # Общая длина (Scapy вычислит автоматически, если оставить None)
	# 	id = random.randint(1, 65535), # Идентификатор пакета
	# 	flags = 'DF',             # Флаги (DF - Don't Fragment, MF - More Fragments)
	# 	frag = 0,                 # Смещение фрагмента
	# 	ttl = 128,                # Time to Live (у Windows обычно 128, у Linux 64)
	# 	proto = 'tcp',            # Протокол верхнего уровня
	# 	src = '192.168.1.5',      # Твой реальный IP (можно подменить/спуфить)
	# 	dst = dst                 # IP сервера
	# )

def decode_chunked(data: bytes) -> bytes:

	chunks = b''
	offset = 0

	while offset < len(data):
		
		line_end = data.find(b'\r\n', offset)
		if line_end == -1:
			break
		
		try:
			chunk_size = int(data[offset:line_end], 16)
		except ValueError:
			break
				
		if chunk_size == 0:
			break
		
		offset = line_end + 2
		chunks += data[offset : offset + chunk_size]
		
		offset += chunk_size + 2

	return chunks

def prepare_received_data() -> None:

	print('\n--- ОТВЕТ СЕРВЕРА ---')

	header_end = received_data.find(b'\r\n\r\n')

	if header_end != -1:

		headers_raw = received_data[:header_end].decode(errors = 'ignore')
		body_raw = received_data[header_end + 4:]

		if 'Transfer-Encoding: chunked' in headers_raw:
			body_raw = decode_chunked(body_raw)

		print('\n--- ЗАГОЛОВКИ СЕРВЕРА ---')
		print(headers_raw)
		print('\n--- ТЕЛО ОТВЕТА ---')

		if 'Content-Encoding: gzip' in headers_raw:
			try:
				print( gzip.decompress(body_raw).decode(errors = 'ignore'))
			except Exception:
				print( body_raw.decode(errors = 'ignore'))
		else:
			print( body_raw.decode(errors = 'ignore'))

	else:
		print( received_data.decode(errors = 'ignore'))

	print('--------------------')
	print('Done.')

def generate_x25519_keyshare():

	private_key = x25519.X25519PrivateKey.generate()
	public_key_bytes = private_key.public_key().public_bytes_raw()
	key_share_data = b"\x00\x1d" + b"\x00\x20" + public_key_bytes
	key_share_data = (len(key_share_data)).to_bytes(2, byteorder='big') + key_share_data

	return private_key, key_share_data

def generate_secp256r1_keyshare():

	private_key = ec.generate_private_key(ec.SECP256R1())
	public_key_bytes = private_key.public_key().public_bytes(
			encoding = serialization.Encoding.X962,
			format = serialization.PublicFormat.UncompressedPoint
	)
	key_share_data = b"\x00\x17" + len(public_key_bytes).to_bytes(2, "big") + public_key_bytes
	key_share_data = (len(key_share_data)).to_bytes(2, byteorder='big') + key_share_data

	return private_key, key_share_data

def generate_secp384r1_keyshare():

	private_key = ec.generate_private_key(ec.SECP384R1())
	public_key_bytes = private_key.public_key().public_bytes(
		encoding = serialization.Encoding.X962,
		format = serialization.PublicFormat.UncompressedPoint
	)
	key_share_data = b"\x00\x18" + len(public_key_bytes).to_bytes(2, byteorder='big') + public_key_bytes
	key_share_data = (len(key_share_data)).to_bytes(2, byteorder='big') + key_share_data

	return private_key, key_share_data

def create_tls_packet(packet: Packet, next_seq: int, next_ack: int, group_name: str = 'x25519') -> None:
	
	global private_key

	version_tls = 'TLS 1.2'

	if group_name == 'x25519':
		private_key, key_share_data = generate_x25519_keyshare()
	elif group_name == 'secp256r1':
		private_key, key_share_data = generate_secp256r1_keyshare()
	elif group_name == 'secp384r1':
		private_key, key_share_data = generate_secp384r1_keyshare()
	else:
		return
	
	cookie = extract_tls_cookie(packet)

	full_random = os.urandom(32)
	time_part = struct.unpack('>I', full_random[:4])[0]
	random_part = full_random[4:]

	extensions_list = [
		TLS_Ext_ServerName(servernames = [ServerName(servername = servername)]),
		TLS_Ext_SupportedGroups(groups = ['x25519', 'secp256r1', 'secp384r1']),
		TLS_Ext_SupportedPointFormat(ecpl = ["uncompressed", 'ansiX962_compressed_prime', 'ansiX962_compressed_char2']),
		TLS_Ext_SignatureAlgorithms(sig_algs = ['sha256+ecdsa', 'sha256+rsa', 'sha384+ecdsa', 'sha384+rsa', 'sha512+rsa']),
		TLS_Ext_Unknown(type = 51, val = key_share_data),
		TLS_Ext_Unknown(type = 43, val = b"\x04\x03\x04\x03\x03"), # supported_versions
		TLS_Ext_Unknown(type = 16, val = b"\x00\x0c\x02h2\x08http/1.1"), # Application-Layer Protocol Negotiation
		TLS_Ext_Unknown(type = 65281, val = b"\x00"), # renegotiation_info 
		TLS_Ext_Unknown(type = 23, val = b""), # extended_master_secret 
		TLS_Ext_Unknown(type = 5, val = b"\x01\x00\x00\x00\x00"), # status_request
		TLS_Ext_Unknown(type = 45, val = b"\x01\x01"), # psk_key_exchange_modes  
		TLS_Ext_Unknown(type = 18, val = b"") # signed_certificate_timestamp
	]

	if cookie:
		extensions_list.append(TLS_Ext_Unknown(type = 44, val = cookie))

	temp_ch = TLSClientHello(version = version_tls, sid = session_id_tls, ext = extensions_list)
	pad_len = 512 - len(temp_ch) - 4
	if pad_len > 0:
		extensions_list.append(TLS_Ext_Unknown(type = 21, val = b"\x00" * pad_len))
	temp_ch = None

	client_hello = TLS(msg = [TLSClientHello(
		version = version_tls,
		gmt_unix_time = time_part,
		random_bytes = random_part,
		sid = session_id_tls,
		ciphers = ciphers,
		ext = extensions_list
	)])

	tls_push = TCP(sport = source_port, dport = dist_port, flags = 'PA', seq = next_seq, ack = next_ack, window = window, options = get_options(packet))
	send(ip / tls_push / client_hello, verbose = False)

def extract_tls_cookie(packet: Packet) -> Union[bytes, None]:

	if packet.haslayer(Raw):
			
			raw_data = packet[Raw].load
			search_index = 0

			while True:
				
				index = raw_data.find(b"\x00\x2c", search_index)
				if index == -1:
					break
				
				cookie_len = int.from_bytes(raw_data[index + 2:index + 4], "big")
				
				if 0 < cookie_len < 512:
					cookie_data = raw_data[index + 4 : index + 4 + cookie_len]
					print(f"[*] Cookie найден! Длина: {cookie_len} байт")
					return cookie_data
				
				search_index = index + 1
					
	return None

sniffer = AsyncSniffer(iface = iface, filter = f'tcp and src host {dist_ip} and src port {dist_port}', prn = handle_server_packet)
sniffer.start()

my_ts = int(time.time() * 1000) & 0xFFFFFFFF
ip = _IP(dst = dist_ip)

# options = [('MSS', mss), ('SAckOK', ''), ('Timestamp', (my_ts, 0)), ('WScale', wscale)]
options = [('MSS', mss), ('WScale', wscale), ('SAckOK', '')]

syn = TCP(sport = source_port, dport = dist_port, flags = 'S', seq = 10, window = window, options = options)
syn_ack = sr1(ip / syn, timeout = 2)

if not syn_ack:
	print('Не удалось дождатся SYN + ACK за 2 секунды ожидания')
	sys.exit(0)

next_seq = syn_ack.ack
next_ack = syn_ack.seq + 1

ack = TCP(sport = source_port, dport = dist_port, flags = 'A', seq = next_seq, ack = next_ack, window = window, options = get_options(syn_ack))
send(ip / ack, verbose = False)
payload = '\r\n'.join(headers)

session_id_tls = os.urandom(32)
create_tls_packet(syn_ack, next_seq, next_ack, 'x25519')

# push = TCP(sport = source_port, dport = dist_port, flags = 'PA', seq = next_seq, ack = next_ack, window = window, options = get_options(syn_ack))
# send(ip / push / payload, verbose = False)

t1 = time.time()

while time.time() - t1 < 10:

	if is_connection_reset:
		break

	if is_send_fin:
		prepare_received_data()
		time.sleep(0.5)
		break
	
	time.sleep(0.1)


