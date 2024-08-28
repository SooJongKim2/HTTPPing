import requests
import time
from datetime import datetime, timedelta
import socket
import ssl
import warnings
from urllib3.exceptions import InsecureRequestWarning
import pytz

warnings.simplefilter('ignore', InsecureRequestWarning)

seoul_tz = pytz.timezone('Asia/Seoul')

# 시간 포맷을 함수로 정의
def format_time(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-5]

def https_ping(host, host_header=None, sni=None, path='/', ip=None, protocol='https', port=None, interval=5, duration=60):
    if port is None:
        port = 443 if protocol == 'https' else 80
    
    if ip is None:
        ip = socket.gethostbyname(host)
    
    url = f"{protocol}://{ip}:{port}{path}"
    headers = {'Host': host_header if host_header is not None else host}
    
    sni = sni if sni is not None else host
    start_time = datetime.now(seoul_tz)
    end_time = start_time + timedelta(seconds=duration)
    last_success = start_time
    downtime_periods = []
    current_downtime_start = None
    
    print(f"Starting {protocol.upper()} ping to {host} (IP: {ip}) at {format_time(start_time)}")
    print(f"URL: {url}")
    print(f"Host header: {headers['Host']}")
    if protocol == 'https':
        print(f"SNI: {sni}")
        print(f"SSL version: {ssl.OPENSSL_VERSION}")
        print(f"Available ciphers: {', '.join(ssl.get_default_verify_paths())}")
    print(f"Will run for {duration} seconds, pinging every {interval} seconds")
    print("-" * 50)

    session = requests.Session()
    
    if protocol == 'https':
        class CustomHTTPSAdapter(requests.adapters.HTTPAdapter):
            def __init__(self, server_hostname):
                self.server_hostname = server_hostname
                super().__init__()
        
            def init_poolmanager(self, *args, **kwargs):
                context = ssl.create_default_context()
                context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                kwargs['ssl_context'] = context
                kwargs['server_hostname'] = self.server_hostname
                return super().init_poolmanager(*args, **kwargs)

        session.mount('https://', CustomHTTPSAdapter(server_hostname=sni))

    while datetime.now(seoul_tz) < end_time:
        try:
            print(f"{format_time(datetime.now(seoul_tz))} - Attempting connection...")
            ping_start = time.time()
            response = session.get(url, headers=headers, timeout=5, verify=True)
            ping_end = time.time()
            
            response_time = (ping_end - ping_start) * 1000
            
            content_preview = response.text[:100] if response.text else "No content"
            
            print(f"{format_time(datetime.now(seoul_tz))} - Response code: {response.status_code}, Time: {response_time:.1f} ms")
            print(f"Content preview: {content_preview}")
            print(f"Response headers: {response.headers}")
            
            if current_downtime_start:
                downtime_end = datetime.now(seoul_tz)
                downtime_duration = (downtime_end - current_downtime_start).total_seconds()
                downtime_periods.append((current_downtime_start, downtime_end, downtime_duration))
                print(f"Connection restored. Downtime: {downtime_duration:.1f} seconds")
                current_downtime_start = None
            
            last_success = datetime.now(seoul_tz)
        
        except requests.RequestException as e:
            print(f"{format_time(datetime.now(seoul_tz))} - Request failed: {str(e)}")
            if isinstance(e, requests.exceptions.SSLError):
                print(f"SSL Error details: {e.args[0]}")
            elif isinstance(e, requests.exceptions.ConnectionError):
                print(f"Connection Error details: {e.args[0]}")
            
            if not current_downtime_start:
                current_downtime_start = datetime.now(seoul_tz)
        
        except Exception as e:
            print(f"{format_time(datetime.now(seoul_tz))} - Unexpected error: {str(e)}")
            
            if not current_downtime_start:
                current_downtime_start = datetime.now(seoul_tz)
        
        print(f"{format_time(datetime.now(seoul_tz))} - Waiting for next ping...")
        print("Downtime periods:")
        for start, end, duration in downtime_periods:
            print(f"  From {format_time(start)} to {format_time(end)} (Duration: {duration:.1f} seconds)")
        if current_downtime_start:
            current_downtime_duration = (datetime.now(seoul_tz) - current_downtime_start).total_seconds()
            print(f"  Current downtime started at {format_time(current_downtime_start)} (Duration so far: {current_downtime_duration:.1f} seconds)")
        print("-" * 50)
        time.sleep(interval)

    if current_downtime_start:
        downtime_end = datetime.now(seoul_tz)
        downtime_duration = (downtime_end - current_downtime_start).total_seconds()
        downtime_periods.append((current_downtime_start, downtime_end, downtime_duration))

    print("-" * 50)
    print(f"{protocol.upper()} ping completed at {format_time(datetime.now(seoul_tz))}")
    print("Final downtime periods:")
    for start, end, duration in downtime_periods:
        print(f"  From {format_time(start)} to {format_time(end)} (Duration: {duration:.1f} seconds)")

# 사용 예:
https_ping(
    host="13.125.68.22",
    host_header="www.test.com",
    sni=None,
    path="/",
    ip=None,
    protocol="http",
    port=None,
    interval=1,
    duration=999999
)