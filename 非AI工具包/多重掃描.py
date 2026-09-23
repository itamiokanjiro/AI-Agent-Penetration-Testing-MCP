import requests
import json
import time
import os
from urllib.parse import urlparse
import socket
import warnings
from urllib3.exceptions import InsecureRequestWarning
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# 關閉 SSL 警告
warnings.filterwarnings('ignore', category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# 全域超時設定
CONNECTION_TIMEOUT = 3  # 連線超時
READ_TIMEOUT = 5        # 讀取超時
TOTAL_TIMEOUT = 10      # 總超時

# 常見漏洞路徑列表
VULN_PATHS = [
    # 目錄瀏覽
    ("directory", "uploads/"),
    ("directory", "upload/"),
    ("directory", "files/"),
    ("directory", "backup/"),
    ("directory", "sql/"),
    ("directory", "sqlbak/"),
    ("directory", "backups/"),
    ("directory", "logs/"),
    ("directory", "tmp/"),
    ("directory", "temp/"),
    ("directory", "data/"),
    ("directory", "assets/"),
    ("directory", "static/"),
    ("directory", "images/"),
    ("directory", "download/"),
    ("directory", "dumps/"),
    
    # Git 相關
    ("git", ".git/HEAD"),
    ("git", ".git/config"),
    ("git", ".git/index"),
    ("git", ".git/logs/HEAD"),
    
    # 環境變數文件
    ("env", ".env"),
    ("env", "env"),
    ("env", ".env.local"),
    ("env", ".env.production"),
    ("env", ".env.development"),
    ("env", ".env.staging"),
    ("env", ".env.test"),
    ("env", ".env.backup"),
    ("env", ".env.old"),
    ("env", "env.bak"),
    
    # 配置文件
    ("config", ".config"),
    ("config", "config"),
    ("config", "config.json"),
    ("config", "config.yml"),
    ("config", "config.yaml"),
    ("config", "config.php"),
    ("config", "config.ini"),
    ("config", "config.xml"),
    ("config", "config.bak"),
    ("config", "config.old"),
    ("config", "settings.py"),
    ("config", "settings.json"),
    ("config", "application.properties"),
    ("config", "application.yml"),
    ("config", "web.config"),
    ("config", "appsettings.json"),
    
    # 備份文件
    ("backup", "index.php.back"),
    ("backup", "index.php.bak"),
    ("backup", "index.html.back"),
    ("backup", "index.html.bak"),
    ("backup", "wp-config.php.back"),
    ("backup", "wp-config.php.bak"),
    ("backup", ".htaccess.back"),
    ("backup", ".htaccess.bak"),
    
    # 其他敏感路徑
    ("sensitive", "robots.txt"),
    ("sensitive", "sitemap.xml"),
    ("sensitive", "crossdomain.xml"),
    ("sensitive", "clientaccesspolicy.xml"),
    ("sensitive", "phpinfo.php"),
    ("sensitive", "info.php"),
    ("sensitive", "test.php"),
    ("sensitive", "phpmyadmin/"),
    ("sensitive", "pma/"),
    ("sensitive", "admin/"),
    ("sensitive", "administrator/"),
    ("sensitive", "wp-admin/"),
    ("sensitive", "wp-content/"),
    ("sensitive", "wp-includes/"),
    
    # 日誌文件
    ("log", "error_log"),
    ("log", "access_log"),
    ("log", "debug.log"),
    ("log", "logs/error.log"),
    ("log", "logs/access.log"),
    
    # 壓縮備份
    ("archive", "backup.zip"),
    ("archive", "backup.rar"),
    ("archive", "backup.tar.gz"),
    ("archive", "backup.tgz"),
    ("archive", "db_backup.sql"),
    ("archive", "database.sql"),
    ("archive", "dump.sql"),
    
    # 常見管理路徑
    ("admin", "cpanel/"),
    ("admin", "webmail/"),
    ("admin", "login/"),
    ("admin", "signin/"),
    ("admin", "auth/"),
    ("admin", "dashboard/"),
    ("admin", "manager/"),
    ("admin", "control/"),
]

# 目錄瀏覽關鍵詞（用於檢測目錄列表）
DIRECTORY_INDICATORS = [
    "Index of /",
    "[parent directory]",
    "Parent Directory",
    "Directory Listing",
    "Apache/",
    "nginx/",
    "IIS/",
    "Directory:",
    "Folder:",
]

# 需要跳過的內容模式（錯誤頁面、無意義內容）
SKIP_PATTERNS = [
    r'404\s+Not\s+Found',
    r'403\s+Forbidden',
    r'500\s+Internal\s+Server\s+Error',
    r'Access\s+Denied',
    r'<title>404',
    r'<title>403',
    r'<title>500',
    r'The requested URL .* was not found',
    r'Object not found',
    r'File not found',
    r'No such file',
    r'does not exist',
    r'<html>[\s\S]*</html>',  # 空 HTML
]

# 線程鎖，用於安全打印
print_lock = threading.Lock()
stats_lock = threading.Lock()

def safe_print(message):
    """線程安全的打印"""
    with print_lock:
        print(message)

def is_valid_domain(domain):
    """檢查網域是否有效"""
    if not domain or domain == 'N/A':
        return False
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_redirect_loop(location):
    """簡單檢測重定向迴圈"""
    loop_patterns = ['localhost', '127.0.0.1', '::1', '/']
    return any(p in location for p in loop_patterns)

def scan_single_target(target, index, total, output_dir='vuln_results\\OLD'):
    """
    掃描單個目標的所有路徑（一個線程處理一個目標）
    """
    ip = target.get('ip')
    port = target.get('port')
    domain = target.get('domain', '')
    
    if not ip or ip == 'N/A':
        safe_print(f"\n⚠️  [{index}/{total}] 跳過: 無 IP 資訊 ({ip})")
        return {'status': 'skipped', 'found': 0}
    
    # 決定使用哪個作為主機
    use_domain = domain and domain != 'N/A' and is_valid_domain(domain)
    host_for_url = domain if use_domain else ip
    
    # 立即顯示開始掃描
    safe_print(f"\n🔍 [{index}/{total}] 掃描: {ip}:{port}" + (f" ({domain})" if use_domain else ""))
    safe_print("-" * 60)
    
    session = requests.Session()
    session.verify = False
    
    found_paths = []
    target_found_count = 0
    target_timeout_count = 0
    path_index = 0
    total_paths = len(VULN_PATHS)
    
    # 串行掃描所有路徑（在同一個線程內）
    for path_type, path in VULN_PATHS:
        path_index += 1
        
        # 嘗試 HTTPS 和 HTTP
        for scheme in ['https', 'http']:
            url = f"{scheme}://{host_for_url}:{port}/{path}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Host': f"{host_for_url}:{port}"
            }
            
            try:
                response = session.get(
                    url,
                    headers=headers,
                    timeout=(CONNECTION_TIMEOUT, READ_TIMEOUT),
                    allow_redirects=False,
                    stream=False
                )
                
                # 檢查響應是否值得保存
                if response.status_code == 200:
                    content = response.text
                    
                    # 檢查是否為目錄瀏覽
                    is_directory = any(indicator in content for indicator in DIRECTORY_INDICATORS)
                    
                    # 檢查是否為錯誤頁面
                    is_error = False
                    for pattern in SKIP_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE):
                            is_error = True
                            break
                    
                    # 如果是目錄瀏覽，或者內容有價值（非錯誤頁面）
                    if is_directory or (not is_error and len(content.strip()) > 50):
                        target_found_count += 1
                        
                        # 保存結果
                        safe_filename = f"{ip}_{port}_{path.replace('/', '_')}_{scheme}.txt"
                        output_file = os.path.join(output_dir, safe_filename)
                        
                        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(f"目標 IP: {ip}\n")
                            f.write(f"端口: {port}\n")
                            f.write(f"網域: {domain}\n")
                            f.write(f"主機: {host_for_url}\n")
                            f.write(f"URL: {url}\n")
                            f.write(f"路徑: {path}\n")
                            f.write(f"類型: {path_type}\n")
                            f.write(f"狀態碼: {response.status_code}\n")
                            f.write(f"目錄瀏覽: {'是' if is_directory else '否'}\n")
                            f.write("=" * 80 + "\n")
                            f.write(content)
                        
                        # 記錄找到的路徑
                        tag = " [DIR]" if is_directory else ""
                        found_paths.append(f"{'📂' if is_directory else '📄'} {path}{tag}")
                        
                        # 只顯示找到的，不顯示全部（避免刷屏）
                        if target_found_count <= 10:  # 只顯示前10個
                            safe_print(f"   ✅ [{scheme}] {path}{tag}")
                        
                        # 如果找到目錄瀏覽，不再嘗試同路徑的其他協議
                        if is_directory:
                            break
                
                elif response.status_code in [301, 302, 303, 307, 308]:
                    # 重定向可能也有價值
                    location = response.headers.get('Location', '')
                    if location and not is_redirect_loop(location):
                        target_found_count += 1
                        found_paths.append(f"🔄 {path} -> {location[:30]}...")
                        
                        safe_filename = f"{ip}_{port}_{path.replace('/', '_')}_{scheme}_redirect.txt"
                        output_file = os.path.join(output_dir, safe_filename)
                        
                        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(f"目標 IP: {ip}\n")
                            f.write(f"端口: {port}\n")
                            f.write(f"網域: {domain}\n")
                            f.write(f"主機: {host_for_url}\n")
                            f.write(f"URL: {url}\n")
                            f.write(f"路徑: {path}\n")
                            f.write(f"狀態碼: {response.status_code}\n")
                            f.write(f"重定向: {location}\n")
                            f.write("=" * 80 + "\n")
                        
                        if target_found_count <= 10:
                            safe_print(f"   🔄 [{scheme}] {path} -> {location[:50]}")
                        break
                    
            except requests.exceptions.Timeout:
                target_timeout_count += 1
                # 超時就跳過這個路徑，繼續下一個
                break
            except requests.exceptions.ConnectionError:
                # 連線錯誤，跳過這個協議
                break
            except requests.exceptions.SSLError:
                continue
            except Exception as e:
                continue
            
            # 短暫延遲避免太激烈
            time.sleep(0.02)
    
    session.close()
    
    # 顯示該目標的掃描結果摘要
    if target_found_count > 0:
        safe_print(f"   ✅ 找到 {target_found_count} 個有價值路徑 (超時: {target_timeout_count})")
        # 如果找到超過10個，只顯示前10個和總數
        if len(found_paths) > 10:
            for p in found_paths[:5]:
                safe_print(f"      {p}")
            safe_print(f"      ... 還有 {len(found_paths) - 5} 個")
        else:
            for p in found_paths[:5]:
                safe_print(f"      {p}")
    else:
        safe_print(f"   ❌ 未找到有價值路徑 (超時: {target_timeout_count})")
    
    return {
        'status': 'completed',
        'found': target_found_count,
        'timeouts': target_timeout_count,
        'ip': ip,
        'port': port,
        'domain': domain
    }


def scan_vulnerable_paths(json_file, output_dir='vuln_results\\OLD', max_workers=5):
    """
    批量掃描目標伺服器的常見漏洞路徑
    每個目標使用一個線程，內部串行掃描所有路徑
    
    Args:
        json_file: zoomeye_all_5_pages_simple.json 檔案路徑
        output_dir: 儲存掃描結果的目錄
        max_workers: 最大並行數（同時掃描多少個目標）
    """
    # 讀取目標列表
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    targets = data.get('data', [])
    total = len(targets)
    
    print(f"📋 共找到 {total} 個目標")
    print(f"🧵 使用 {max_workers} 個線程併發掃描目標")
    print(f"⏱️  超時設定: 連線 {CONNECTION_TIMEOUT}s, 讀取 {READ_TIMEOUT}s")
    print(f"🔍 每個目標掃描 {len(VULN_PATHS)} 個路徑 (串行)")
    print(f"📁 輸出目錄: {output_dir}/")
    print("=" * 80)
    
    # 建立輸出目錄
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    start_time = time.time()
    
    # 統計變數
    stats = {
        'total_targets': total,
        'completed': 0,
        'skipped': 0,
        'total_found': 0,
        'total_timeouts': 0
    }
    
    # 使用線程池，每個目標一個線程
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任務
        future_to_target = {
            executor.submit(scan_single_target, target, i, total, output_dir): target
            for i, target in enumerate(targets, 1)
        }
        
        # 收集結果
        for future in as_completed(future_to_target):
            try:
                result = future.result()
                if result:
                    if result.get('status') == 'skipped':
                        stats['skipped'] += 1
                    else:
                        stats['completed'] += 1
                        stats['total_found'] += result.get('found', 0)
                        stats['total_timeouts'] += result.get('timeouts', 0)
            except Exception as e:
                safe_print(f"⚠️  任務執行異常: {e}")
                stats['skipped'] += 1
    
    elapsed_time = time.time() - start_time
    
    # 輸出統計
    print("\n" + "=" * 80)
    print(f"📊 掃描完成! 耗時: {elapsed_time:.2f}秒")
    print(f"   📋 總目標數: {stats['total_targets']}")
    print(f"   ✅ 完成掃描: {stats['completed']}")
    print(f"   ⏭️  跳過: {stats['skipped']}")
    print(f"   🔍 找到有價值路徑總數: {stats['total_found']}")
    print(f"   ⏰ 總超時次數: {stats['total_timeouts']}")
    print(f"   📁 結果目錄: {output_dir}/")
    
    # 列出找到的結果文件
    result_files = [f for f in os.listdir(output_dir) if f.endswith('.txt')]
    print(f"\n📄 共保存 {len(result_files)} 個結果文件")
    if result_files:
        print("   示例:")
        for f in result_files[:5]:
            print(f"      - {f}")
        if len(result_files) > 5:
            print(f"      ... 還有 {len(result_files) - 5} 個")


if __name__ == "__main__":
    json_file = 'zoomeye_all_5_pages_simple.json'
    
    print("🛡️  開始掃描常見漏洞路徑...")
    print("📌 模式: 每個目標一個線程，內部串行掃描")
    print("⚠️  注意: 每個路徑超時 {CONNECTION_TIMEOUT}s + {READ_TIMEOUT}s\n")
    
    scan_vulnerable_paths(
        json_file, 
        output_dir='vuln_results\\OLD',
        max_workers=30  # 同時掃描5個目標
    )