import requests
import json
import time
import os
import threading
from datetime import datetime
import queue

# 线程锁，用于安全打印
print_lock = threading.Lock()
log_lock = threading.Lock()

# 全局日志队列
log_queue = queue.Queue()

def log_worker():
    """后台日志处理线程"""
    while True:
        try:
            msg = log_queue.get(timeout=1)
            if msg is None:
                break
            with print_lock:
                print(msg)
        except queue.Empty:
            continue

def safe_print(message):
    """将日志放入队列，由后台线程处理"""
    log_queue.put(message)

def write_log(log_dir, filename, content):
    """线程安全的写入日志"""
    with log_lock:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        filepath = os.path.join(log_dir, filename)
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(content + '\n')


def check_single_target_ip(target, index, total, output_dir='git_check_results_ip', log_dir='logs'):
    """
    检查单个目标（使用 IP）
    """
    ip = target.get('ip')
    port = target.get('port')
    domain = target.get('domain', '')
    
    # 生成请求ID
    request_id = f"{datetime.now().strftime('%H%M%S')}_{index}"
    
    # 跳过没有 IP 的目标
    if not ip or ip == 'N/A':
        msg = f"[{request_id}] ⏭️  [{index}/{total}] 跳过: 无 IP 信息"
        safe_print(msg)
        write_log(log_dir, f'skipped_{datetime.now().strftime("%Y%m%d")}.log', msg)
        return {'status': 'skipped', 'reason': 'no_ip'}
    
    # 构建 URL（使用 IP）
    url = f"https://{ip}:{port}/.git/HEAD"
    
    # 准备请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Host': f"{ip}:{port}"
    }
    
    # 立即输出开始信息
    safe_print(f"[{request_id}] 🔍 [{index}/{total}] 检查 {ip}:{port}")
    safe_print(f"   IP: {ip}")
    safe_print(f"   端口: {port}")
    safe_print(f"   网域: {domain}")
    safe_print(f"   URL: {url}")
    
    # 同时写入日志
    log_lines = [
        f"[{request_id}] 🔍 [{index}/{total}] 检查 {ip}:{port}",
        f"   IP: {ip}",
        f"   端口: {port}",
        f"   网域: {domain}",
        f"   URL: {url}"
    ]
    for line in log_lines:
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', line)
    
    result = {
        'ip': ip,
        'port': port,
        'domain': domain,
        'url': url,
        'status': 'failed',
        'request_id': request_id
    }
    
    try:
        # 发送 GET 请求，超时设为20秒
        start_time = time.time()
        response = requests.get(
            url,
            headers=headers,
            verify=False,  # 忽略 SSL 证书验证
            timeout=20  # 20秒超时
        )
        elapsed = time.time() - start_time
        
        # 判断是否找到 .git/HEAD
        is_git = False
        if response.status_code == 200:
            content = response.text.strip()
            # 检查是否包含 ref: 或 commit hash
            if content.startswith('ref:') or (len(content) == 40 and all(c in '0123456789abcdef' for c in content)):
                is_git = True
                result['status'] = 'found'
                msg = f"   ✅ 发现 .git/HEAD! (状态码: {response.status_code}, 耗时: {elapsed:.2f}s)"
                safe_print(msg)
                write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
            else:
                result['status'] = f'status_{response.status_code}'
                msg = f"   ℹ️  响应 200 但内容不是 Git HEAD (耗时: {elapsed:.2f}s)"
                safe_print(msg)
                write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
                if content:
                    msg = f"   内容: {content[:100]}"
                    safe_print(msg)
                    write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
        else:
            result['status'] = f'status_{response.status_code}'
            msg = f"   ❌ HTTP {response.status_code} (耗时: {elapsed:.2f}s)"
            safe_print(msg)
            write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
        
        # 保存响应
        safe_ip = ip.replace('/', '_').replace('\\', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f'{safe_ip}_{port}_{result["status"]}.txt')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"目标 IP: {ip}\n")
            f.write(f"端口: {port}\n")
            f.write(f"网域: {domain}\n")
            f.write(f"URL: {url}\n")
            f.write(f"状态码: {response.status_code}\n")
            f.write(f"耗时: {elapsed:.2f}s\n")
            f.write("=" * 80 + "\n")
            f.write(response.text)
            
    except requests.exceptions.Timeout:
        result['status'] = 'timeout'
        msg = f"   ❌ 超时 (20秒)"
        safe_print(msg)
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
    except requests.exceptions.ConnectionError:
        result['status'] = 'connection_error'
        msg = f"   ❌ 连接失败"
        safe_print(msg)
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
    except requests.exceptions.SSLError:
        result['status'] = 'ssl_error'
        msg = f"   ❌ SSL 错误"
        safe_print(msg)
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
    except Exception as e:
        result['status'] = f'error_{str(e)[:30]}'
        msg = f"   ❌ 错误: {str(e)[:50]}"
        safe_print(msg)
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
    
    return result


def check_git_head_ip_multithreaded(json_file, output_dir='git_check_results_ip', max_workers=10, log_dir='logs'):
    """
    批量检查目标服务器的 .git/HEAD 文件（使用 IP）- 多线程版本
    
    Args:
        json_file: zoomeye_all_5_pages_simple.json 文件路径
        output_dir: 保存响应结果的目录
        max_workers: 线程数，默认10
        log_dir: 日志目录
    """
    # 读取目标列表
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    targets = data.get('data', [])
    total = len(targets)
    
    print(f"📋 共找到 {total} 个目标")
    print(f"🧵 使用 {max_workers} 个线程并发检查")
    print(f"⏱️  每个目标超时: 20秒")
    print(f"📁 输出目录: {output_dir}/")
    print(f"📁 日志目录: {log_dir}/")
    print("=" * 80)
    
    # 创建输出目录
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 启动日志处理线程
    log_thread = threading.Thread(target=log_worker, daemon=True)
    log_thread.start()
    
    # 统计变量
    stats = {
        'found': 0,
        'failed': 0,
        'skipped': 0,
        'timeout': 0,
        'error': 0
    }
    
    start_time = time.time()
    
    # 使用线程列表，手动管理
    threads = []
    results = []
    results_lock = threading.Lock()
    
    def worker(target, index):
        result = check_single_target_ip(target, index, total, output_dir, log_dir)
        with results_lock:
            results.append(result)
    
    # 启动所有线程（不等待）
    for i, target in enumerate(targets, 1):
        t = threading.Thread(target=worker, args=(target, i))
        t.daemon = True
        t.start()
        threads.append(t)
        # 稍微延迟一下，避免同时创建太多线程
        time.sleep(0.05)
    
    # 等待所有线程完成
    for t in threads:
        t.join()
    
    # 统计结果
    for result in results:
        if result:
            status = result.get('status', 'unknown')
            if status == 'found':
                stats['found'] += 1
            elif status == 'skipped':
                stats['skipped'] += 1
            elif status == 'timeout':
                stats['timeout'] += 1
                stats['failed'] += 1
            elif status.startswith('status_'):
                stats['failed'] += 1
            else:
                stats['error'] += 1
                stats['failed'] += 1
    
    elapsed_time = time.time() - start_time
    
    # 停止日志线程
    log_queue.put(None)
    log_thread.join(timeout=1)
    
    # 输出统计
    summary = []
    summary.append("=" * 80)
    summary.append(f"📊 检查完成! 耗时: {elapsed_time:.2f}秒")
    summary.append(f"   ✅ 发现 .git/HEAD: {stats['found']}")
    summary.append(f"   ❌ 未发现: {stats['failed'] - stats['timeout']}")
    summary.append(f"   ⏰ 超时 (20秒): {stats['timeout']}")
    summary.append(f"   ⏭️  跳过（无IP）: {stats['skipped']}")
    summary.append(f"   📁 结果保存在: {output_dir}/")
    summary.append(f"   📁 日志保存在: {log_dir}/")
    
    for line in summary:
        print(line)
        write_log(log_dir, f'summary_{datetime.now().strftime("%Y%m%d")}.log', line)


def check_single_target_ip_with_domain_header(target, index, total, output_dir='git_check_results_ip_domain_header', log_dir='logs'):
    """
    检查单个目标（使用 IP 但 Host 头使用网域）
    """
    ip = target.get('ip')
    port = target.get('port')
    domain = target.get('domain', '')
    
    request_id = f"{datetime.now().strftime('%H%M%S')}_{index}"
    
    if not ip or ip == 'N/A':
        msg = f"[{request_id}] ⏭️  [{index}/{total}] 跳过: 无 IP 信息"
        safe_print(msg)
        write_log(log_dir, f'skipped_{datetime.now().strftime("%Y%m%d")}.log', msg)
        return {'status': 'skipped', 'reason': 'no_ip'}
    
    # 构建 URL（使用 IP）
    url = f"https://{ip}:{port}/.git/HEAD"
    
    # 准备请求头 - Host 使用网域（如果有）
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    }
    
    # 如果有网域，使用网域作为 Host
    if domain and domain != 'N/A':
        headers['Host'] = domain
        host_display = f"Host: {domain}"
    else:
        headers['Host'] = f"{ip}:{port}"
        host_display = f"Host: {ip}:{port}"
    
    # 立即输出开始信息
    safe_print(f"[{request_id}] 🔍 [{index}/{total}] 检查 {ip}:{port} ({host_display})")
    safe_print(f"   URL: {url}")
    
    # 同时写入日志
    log_lines = [
        f"[{request_id}] 🔍 [{index}/{total}] 检查 {ip}:{port} ({host_display})",
        f"   URL: {url}"
    ]
    for line in log_lines:
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', line)
    
    result = {
        'ip': ip,
        'port': port,
        'domain': domain,
        'url': url,
        'host_header': headers.get('Host', 'N/A'),
        'status': 'failed',
        'request_id': request_id
    }
    
    try:
        start_time = time.time()
        response = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=20
        )
        elapsed = time.time() - start_time
        
        is_git = False
        if response.status_code == 200:
            content = response.text.strip()
            if content.startswith('ref:') or (len(content) == 40 and all(c in '0123456789abcdef' for c in content)):
                is_git = True
                result['status'] = 'found'
                msg = f"   ✅ 发现 .git/HEAD! (状态码: {response.status_code}, 耗时: {elapsed:.2f}s)"
                safe_print(msg)
                write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
            else:
                result['status'] = f'status_{response.status_code}'
                msg = f"   ℹ️  响应 200 但内容不是 Git HEAD (耗时: {elapsed:.2f}s)"
                safe_print(msg)
                write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
        else:
            result['status'] = f'status_{response.status_code}'
            msg = f"   ❌ HTTP {response.status_code} (耗时: {elapsed:.2f}s)"
            safe_print(msg)
            write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
        
        # 保存响应
        safe_ip = ip.replace('/', '_').replace('\\', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f'{safe_ip}_{port}_{result["status"]}.txt')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"目标 IP: {ip}\n")
            f.write(f"端口: {port}\n")
            f.write(f"网域: {domain}\n")
            f.write(f"URL: {url}\n")
            f.write(f"Host 头: {headers.get('Host', 'N/A')}\n")
            f.write(f"状态码: {response.status_code}\n")
            f.write(f"耗时: {elapsed:.2f}s\n")
            f.write("=" * 80 + "\n")
            f.write(response.text)
            
    except requests.exceptions.Timeout:
        result['status'] = 'timeout'
        msg = f"   ❌ 超时 (20秒)"
        safe_print(msg)
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
    except Exception as e:
        result['status'] = f'error_{str(e)[:30]}'
        msg = f"   ❌ 错误: {str(e)[:50]}"
        safe_print(msg)
        write_log(log_dir, f'check_{datetime.now().strftime("%Y%m%d")}.log', msg)
    
    return result


def check_git_head_ip_with_domain_header_multithreaded(json_file, output_dir='git_check_results_ip_domain_header', max_workers=10, log_dir='logs'):
    """
    使用 IP 但 Host 头使用网域 - 多线程版本
    """
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    targets = data.get('data', [])
    total = len(targets)
    
    print(f"📋 共找到 {total} 个目标")
    print(f"🧵 使用 {max_workers} 个线程并发检查")
    print(f"⏱️  每个目标超时: 20秒")
    print(f"📁 输出目录: {output_dir}/")
    print(f"📁 日志目录: {log_dir}/")
    print("=" * 80)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 启动日志处理线程
    log_thread = threading.Thread(target=log_worker, daemon=True)
    log_thread.start()
    
    stats = {
        'found': 0,
        'failed': 0,
        'timeout': 0,
        'skipped': 0,
        'error': 0
    }
    
    start_time = time.time()
    
    # 使用线程列表，手动管理
    threads = []
    results = []
    results_lock = threading.Lock()
    
    def worker(target, index):
        result = check_single_target_ip_with_domain_header(target, index, total, output_dir, log_dir)
        with results_lock:
            results.append(result)
    
    # 启动所有线程（不等待）
    for i, target in enumerate(targets, 1):
        t = threading.Thread(target=worker, args=(target, i))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(0.05)
    
    # 等待所有线程完成
    for t in threads:
        t.join()
    
    # 统计结果
    for result in results:
        if result:
            status = result.get('status', 'unknown')
            if status == 'found':
                stats['found'] += 1
            elif status == 'skipped':
                stats['skipped'] += 1
            elif status == 'timeout':
                stats['timeout'] += 1
                stats['failed'] += 1
            elif status.startswith('status_'):
                stats['failed'] += 1
            else:
                stats['error'] += 1
                stats['failed'] += 1
    
    elapsed_time = time.time() - start_time
    
    # 停止日志线程
    log_queue.put(None)
    log_thread.join(timeout=1)
    
    summary = []
    summary.append("=" * 80)
    summary.append(f"📊 检查完成! 耗时: {elapsed_time:.2f}秒")
    summary.append(f"   ✅ 发现 .git/HEAD: {stats['found']}")
    summary.append(f"   ❌ 未发现: {stats['failed']}")
    summary.append(f"   ⏰ 超时 (20秒): {stats['timeout']}")
    summary.append(f"   ⏭️  跳过（无IP）: {stats['skipped']}")
    summary.append(f"   📁 结果保存在: {output_dir}/")
    summary.append(f"   📁 日志保存在: {log_dir}/")
    
    for line in summary:
        print(line)
        write_log(log_dir, f'summary_{datetime.now().strftime("%Y%m%d")}.log', line)


if __name__ == "__main__":
    json_file = 'zoomeye_all_5_pages_simple.json'
    
    # 方式1: 直接使用 IP - 10线程
    check_git_head_ip_multithreaded(json_file, max_workers=10)
    
    # 方式2: 使用 IP 但 Host 头使用网域 - 10线程
    # check_git_head_ip_with_domain_header_multithreaded(json_file, max_workers=10)