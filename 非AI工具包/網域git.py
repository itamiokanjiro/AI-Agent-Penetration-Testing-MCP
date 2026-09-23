import requests
import json
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# 线程锁，用于安全打印
print_lock = threading.Lock()

def safe_print(message):
    """线程安全的打印"""
    with print_lock:
        print(message)

def check_single_target(target, index, total, output_dir='git_check_results_domain'):
    """
    检查单个目标
    """
    ip = target.get('ip')
    port = target.get('port')
    domain = target.get('domain', '')
    
    # 如果没有网域或网域为 N/A，则跳过
    if not domain or domain == 'N/A':
        safe_print(f"\n⏭️  [{index}/{total}] 跳过: 无网域信息 ({ip}:{port})")
        return {'status': 'skipped', 'reason': 'no_domain'}
    
    # 构建 URL（使用网域）
    url = f"https://{domain}:{port}/.git/HEAD"
    
    # 准备请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Host': f"{domain}:{port}"
    }
    
    safe_print(f"\n🔍 [{index}/{total}] 检查 {domain}:{port}")
    safe_print(f"   网域: {domain}")
    safe_print(f"   IP: {ip}")
    safe_print(f"   端口: {port}")
    safe_print(f"   URL: {url}")
    
    result = {
        'domain': domain,
        'ip': ip,
        'port': port,
        'url': url,
        'status': 'failed'
    }
    
    try:
        # 发送 GET 请求，超时设为20秒
        response = requests.get(
            url,
            headers=headers,
            verify=False,  # 忽略 SSL 证书验证
            timeout=20,  # 20秒超时
            allow_redirects=False  # 不跟随重定向
        )
        
        # 判断是否找到 .git/HEAD
        is_git = False
        if response.status_code == 200:
            content = response.text.strip()
            # 检查是否包含 ref: 或 commit hash
            if content.startswith('ref:') or (len(content) == 40 and all(c in '0123456789abcdef' for c in content)):
                is_git = True
                result['status'] = 'found'
                safe_print(f"   ✅ 发现 .git/HEAD! (状态码: {response.status_code})")
            else:
                result['status'] = f'status_{response.status_code}'
                safe_print(f"   ℹ️  响应 200 但内容不是 Git HEAD")
                safe_print(f"   内容: {content[:100]}")
        else:
            result['status'] = f'status_{response.status_code}'
            safe_print(f"   ❌ HTTP {response.status_code}")
        
        # 保存响应
        safe_domain = domain.replace('/', '_').replace('\\', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f'{safe_domain}_{port}_{result["status"]}.txt')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"目标网域: {domain}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"端口: {port}\n")
            f.write(f"URL: {url}\n")
            f.write(f"状态码: {response.status_code}\n")
            f.write("=" * 80 + "\n")
            f.write(response.text)
            
    except requests.exceptions.Timeout:
        result['status'] = 'timeout'
        safe_print(f"   ❌ 超时 (20秒)")
    except requests.exceptions.ConnectionError:
        result['status'] = 'connection_error'
        safe_print(f"   ❌ 连接失败")
    except requests.exceptions.SSLError:
        result['status'] = 'ssl_error'
        safe_print(f"   ❌ SSL 错误")
    except Exception as e:
        result['status'] = f'error_{str(e)[:30]}'
        safe_print(f"   ❌ 错误: {str(e)[:50]}")
    
    return result


def check_git_head_domain_multithreaded(json_file, output_dir='git_check_results_domain', max_workers=10):
    """
    批量检查目标服务器的 .git/HEAD 文件（使用网域）- 多线程版本
    
    Args:
        json_file: zoomeye_all_5_pages_simple.json 文件路径
        output_dir: 保存响应结果的目录
        max_workers: 线程数，默认10
    """
    # 读取目标列表
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    targets = data.get('data', [])
    total = len(targets)
    print(f"📋 共找到 {total} 个目标")
    print(f"🧵 使用 {max_workers} 个线程并发检查")
    print(f"⏱️  每个目标超时: 20秒")
    print("=" * 80)
    
    # 创建输出目录
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 统计变量
    stats = {
        'found': 0,
        'failed': 0,
        'skipped': 0,
        'timeout': 0,
        'error': 0
    }
    
    start_time = time.time()
    
    # 使用线程池执行
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_target = {
            executor.submit(check_single_target, target, i, total, output_dir): target 
            for i, target in enumerate(targets, 1)
        }
        
        # 收集结果
        for future in as_completed(future_to_target):
            try:
                result = future.result()
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
            except Exception as e:
                safe_print(f"⚠️  任务执行异常: {e}")
                stats['failed'] += 1
    
    elapsed_time = time.time() - start_time
    
    # 输出统计
    print("\n" + "=" * 80)
    print(f"📊 检查完成! 耗时: {elapsed_time:.2f}秒")
    print(f"   ✅ 发现 .git/HEAD: {stats['found']}")
    print(f"   ❌ 未发现: {stats['failed'] - stats['timeout']}")
    print(f"   ⏰ 超时 (20秒): {stats['timeout']}")
    print(f"   ⏭️  跳过（无网域）: {stats['skipped']}")
    print(f"   📁 结果保存在: {output_dir}/")


def check_git_head_domain_with_ip_fallback_multithreaded(json_file, output_dir='git_check_results_domain_ip_fallback', max_workers=10):
    """
    优先使用网域，如果没有网域则使用 IP - 多线程版本
    """
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    targets = data.get('data', [])
    total = len(targets)
    print(f"📋 共找到 {total} 个目标")
    print(f"🧵 使用 {max_workers} 个线程并发检查")
    print(f"⏱️  每个目标超时: 20秒")
    print("=" * 80)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    stats = {
        'found': 0,
        'failed': 0,
        'timeout': 0,
        'domain_count': 0,
        'ip_count': 0,
        'skipped': 0
    }
    
    start_time = time.time()
    
    def check_target_with_ip_fallback(target, index):
        ip = target.get('ip')
        port = target.get('port')
        domain = target.get('domain', '')
        
        # 决定使用网域还是 IP
        if domain and domain != 'N/A':
            use_domain = True
            host = domain
            stats['domain_count'] += 1
        elif ip and ip != 'N/A':
            use_domain = False
            host = ip
            stats['ip_count'] += 1
        else:
            safe_print(f"\n⚠️  [{index}/{total}] 跳过: 无网域且无 IP 信息")
            stats['skipped'] += 1
            return {'status': 'skipped', 'reason': 'no_host'}
        
        # 构建 URL
        url = f"https://{host}:{port}/.git/HEAD"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Host': f"{host}:{port}"
        }
        
        safe_print(f"\n🔍 [{index}/{total}] 检查 {host}:{port}")
        safe_print(f"   {'网域' if use_domain else 'IP'}: {host}")
        safe_print(f"   {'IP' if use_domain else '网域'}: {ip if use_domain else domain}")
        safe_print(f"   端口: {port}")
        safe_print(f"   URL: {url}")
        
        result = {
            'host': host,
            'ip': ip,
            'port': port,
            'domain': domain,
            'url': url,
            'use_domain': use_domain,
            'status': 'failed'
        }
        
        try:
            response = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=20,
                allow_redirects=False
            )
            
            is_git = False
            if response.status_code == 200:
                content = response.text.strip()
                if content.startswith('ref:') or (len(content) == 40 and all(c in '0123456789abcdef' for c in content)):
                    is_git = True
                    result['status'] = 'found'
                    safe_print(f"   ✅ 发现 .git/HEAD! (状态码: {response.status_code})")
                else:
                    result['status'] = f'status_{response.status_code}'
                    safe_print(f"   ℹ️  响应 200 但内容不是 Git HEAD")
            else:
                result['status'] = f'status_{response.status_code}'
                safe_print(f"   ❌ HTTP {response.status_code}")
            
            # 保存响应
            safe_host = host.replace('/', '_').replace('\\', '_').replace(':', '_')
            output_file = os.path.join(output_dir, f'{safe_host}_{port}_{result["status"]}.txt')
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"使用: {'网域' if use_domain else 'IP'}\n")
                f.write(f"目标: {host}\n")
                f.write(f"IP: {ip}\n")
                f.write(f"端口: {port}\n")
                f.write(f"网域: {domain}\n")
                f.write(f"URL: {url}\n")
                f.write(f"状态码: {response.status_code}\n")
                f.write("=" * 80 + "\n")
                f.write(response.text)
                
        except requests.exceptions.Timeout:
            result['status'] = 'timeout'
            safe_print(f"   ❌ 超时 (20秒)")
        except Exception as e:
            result['status'] = f'error_{str(e)[:30]}'
            safe_print(f"   ❌ 错误: {str(e)[:50]}")
        
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_target_with_ip_fallback, target, i): target 
            for i, target in enumerate(targets, 1)
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    status = result.get('status', 'unknown')
                    if status == 'found':
                        stats['found'] += 1
                    elif status == 'timeout':
                        stats['timeout'] += 1
                        stats['failed'] += 1
                    elif status == 'skipped':
                        stats['skipped'] += 1
                    elif status.startswith('status_'):
                        stats['failed'] += 1
                    else:
                        stats['failed'] += 1
            except Exception as e:
                safe_print(f"⚠️  任务执行异常: {e}")
                stats['failed'] += 1
    
    elapsed_time = time.time() - start_time
    
    print("\n" + "=" * 80)
    print(f"📊 检查完成! 耗时: {elapsed_time:.2f}秒")
    print(f"   ✅ 发现 .git/HEAD: {stats['found']}")
    print(f"   ❌ 未发现: {stats['failed']}")
    print(f"   ⏰ 超时 (20秒): {stats['timeout']}")
    print(f"   ⏭️  跳过: {stats['skipped']}")
    print(f"   🌐 使用网域: {stats.get('domain_count', 0)}")
    print(f"   📍 使用 IP: {stats.get('ip_count', 0)}")
    print(f"   📁 结果保存在: {output_dir}/")


if __name__ == "__main__":
    json_file = 'zoomeye_all_5_pages_simple.json'
    
    # 方式1: 只使用网域，没有网域则跳过 - 10线程
    check_git_head_domain_multithreaded(json_file, max_workers=10)
    
    # 方式2: 优先使用网域，没有网域则使用 IP（备选）- 10线程
    # check_git_head_domain_with_ip_fallback_multithreaded(json_file, max_workers=10)