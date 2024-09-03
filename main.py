
tee httptest.py << EOF
import requests
import time
from datetime import datetime, timedelta
import socket
import ssl
import warnings
from urllib3.exceptions import InsecureRequestWarning
import pytz
from termcolor import colored
import json

warnings.simplefilter('ignore', InsecureRequestWarning)

seoul_tz = pytz.timezone('Asia/Seoul')

def format_time(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-5]

def update_downtime_file(downtime_periods, current_downtime_start):
    with open('downtime.txt', 'w') as f:
        json.dump({
            'downtime_periods': [(format_time(start), format_time(end), duration) for start, end, duration in downtime_periods],
            'current_downtime_start': format_time(current_downtime_start) if current_downtime_start else None
        }, f, indent=2)

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
    
    print(colored(f"요청 시간: {format_time(start_time)}", "blue"))
    print(colored(f"요청 도메인정보: {host}", "blue"))
    print(colored(f"호스트 헤더 정보(옵션): {headers['Host']}", "blue"))
    print(colored(f"SNI 정보(옵션): {sni}", "blue"))
    print(colored(f"요청 ip정보 {protocol}://{ip}:{port}", "blue"))
    print(colored(f"요청주기: {interval}초", "blue"))
    print(colored("-" * 50, "white"))

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
        print(colored(f"\n🕒 현재 시간: {format_time(datetime.now(seoul_tz))}", "blue"))
        print(colored(f"🌐 요청 URL: {url}", "blue"))
        print(colored(f"📋 요청 헤더: {headers}", "blue"))

        try:
            ping_start = time.time()
            response = session.get(url, headers=headers, timeout=5, verify=True)
            ping_end = time.time()
            
            response_time = (ping_end - ping_start) * 1000
            
            content_preview = response.text[:500] if response.text else "내용 없음"
            
            print(colored(f"✅ 응답 코드: {response.status_code}", "green"))
            print(colored(f"⏱️ 응답 시간: {response_time:.1f} ms", "cyan"))
            print(colored(f"📄 응답 미리보기: {content_preview}", "yellow"))
            
            if current_downtime_start:
                downtime_end = datetime.now(seoul_tz)
                downtime_duration = (downtime_end - current_downtime_start).total_seconds()
                downtime_periods.append((current_downtime_start, downtime_end, downtime_duration))
                print(colored(f"🔄 연결 복구됨. 다운타임: {downtime_duration:.1f} 초", "green"))
                current_downtime_start = None
            
            last_success = datetime.now(seoul_tz)
            print(colored("🟢 통신 상태: 정상", "green"))
        
        except requests.RequestException as e:
            print(colored(f"❌ 요청 실패: {str(e)}", "red"))
            if isinstance(e, requests.exceptions.SSLError):
                print(colored(f"🔒 SSL 오류 상세: {e.args[0]}", "red"))
            elif isinstance(e, requests.exceptions.ConnectionError):
                print(colored(f"🔌 연결 오류 상세: {e.args[0]}", "red"))
            
            if not current_downtime_start:
                current_downtime_start = datetime.now(seoul_tz)
            print(colored("🔴 통신 상태: 비정상", "red"))
        
        except Exception as e:
            print(colored(f"❗ 예상치 못한 오류: {str(e)}", "red"))
            
            if not current_downtime_start:
                current_downtime_start = datetime.now(seoul_tz)
            print(colored("🔴 통신 상태: 비정상", "red"))
        
        print(colored("⏳ 다운타임 기간:", "magenta"))
        for start, end, duration in downtime_periods:
            print(colored(f"  {format_time(start)}부터 {format_time(end)}까지 (지속시간: {duration:.1f} 초)", "magenta"))
        if current_downtime_start:
            current_downtime_duration = (datetime.now(seoul_tz) - current_downtime_start).total_seconds()
            print(colored(f"  현재 다운타임 시작: {format_time(current_downtime_start)} (현재까지 지속시간: {current_downtime_duration:.1f} 초)", "red"))
        print(colored("-" * 50, "white"))

        # 다운타임 정보를 파일로 export
        update_downtime_file(downtime_periods, current_downtime_start)

        time.sleep(interval)

    if current_downtime_start:
        downtime_end = datetime.now(seoul_tz)
        downtime_duration = (downtime_end - current_downtime_start).total_seconds()
        downtime_periods.append((current_downtime_start, downtime_end, downtime_duration))

    print(colored("-" * 50, "white"))
    print(colored(f"{protocol.upper()} 핑 완료 시간: {format_time(datetime.now(seoul_tz))}", "blue"))
    print(colored("📊 최종 다운타임 기간:", "magenta"))
    for start, end, duration in downtime_periods:
        print(colored(f"  {format_time(start)}부터 {format_time(end)}까지 (지속시간: {duration:.1f} 초)", "magenta"))

    # 최종 다운타임 정보를 파일로 export
    update_downtime_file(downtime_periods, None)

# 사용 예:
https_ping(
    host="www.google.com",
    host_header=None,
    sni=None,
    path="/",
    ip=None,
    protocol="http",
    port=None,
    interval=1,
    duration=999999
)
EOF
sudo yum install -y python3 pip
pip install termcolor
python3 httptest.py
