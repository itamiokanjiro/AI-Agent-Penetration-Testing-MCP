import requests
import json
import time
import re
from urllib.parse import quote, urlencode
import base64
import math

class ZoomEyeAPI:
    def __init__(self, env_file='.env'):
        """
        初始化 ZoomEye API 客户端，从 .env 文件读取配置
        
        Args:
            env_file: .env 文件路径，默认为当前目录下的 .env
        """
        self.session = requests.Session()
        
        # 从 .env 文件读取配置
        self._load_from_env(env_file)
    
    def _load_from_env(self, env_file):
        """从 .env 文件解析配置"""
        with open(env_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 提取 User-Agent
        ua_match = re.search(r'\$session\.UserAgent\s*=\s*"([^"]+)"', content)
        if ua_match:
            self.session.headers.update({'User-Agent': ua_match.group(1)})
        
        # 提取所有 Cookies
        cookie_pattern = r'\$session\.Cookies\.Add\(\(New-Object System\.Net\.Cookie\("([^"]+)",\s*"([^"]+)",\s*"/",\s*"([^"]+)"\)\)\)'
        cookies = re.findall(cookie_pattern, content)
        
        for cookie_name, cookie_value, cookie_domain in cookies:
            self.session.cookies.set(cookie_name, cookie_value, domain=cookie_domain, path='/')
        
        # 提取 Headers
        headers_match = re.search(r'-Headers @\{([^}]+)\}', content, re.DOTALL)
        if headers_match:
            headers_str = headers_match.group(1)
            # 解析每个 header
            header_pattern = r'"([^"]+)"\s*=\s*"([^"]+)"'
            headers = re.findall(header_pattern, headers_str)
            
            for header_name, header_value in headers:
                # 处理特殊字符转义
                header_value = header_value.replace('`"', '"').replace('`$', '$')
                self.session.headers[header_name] = header_value
        
        # 提取查询参数中的 q 值
        uri_match = re.search(r'-Uri "([^"]+)"', content)
        if uri_match:
            uri = uri_match.group(1)
            # 提取 q 参数
            q_match = re.search(r'q=([^&]+)', uri)
            if q_match:
                self._query = q_match.group(1)
    
    def get_total_count(self, query=None):
        """
        获取搜索结果的总数量（仅获取第一页以取得 total）
        
        Args:
            query: 搜索查询，如果不提供则使用 .env 中的查询
        
        Returns:
            int: 总结果数，失败返回 0
        """
        if query is None:
            query = getattr(self, '_query', None)
            if query is None:
                raise ValueError("未找到查询参数，请提供 query 参数")
        
        # 构建 URL
        base_url = "https://www.zoomeye.ai/api/search"
        
        params = {
            'q': query,
            'page': 1,
            'pageSize': 1,  # 只取1条数据就能获得 total
            't': 'v4+v6+web'
        }
        
        # 构建 Referer
        referer = f"https://www.zoomeye.ai/searchResult?q={query}&page=1&pageSize=1"
        self.session.headers['Referer'] = referer
        
        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'X-Original-Referer': '',
        })
        
        token = self.session.cookies.get('token')
        if token:
            self.session.headers['Cube-Authorization'] = token
        
        try:
            response = self.session.get(base_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data.get('total', 0)
            else:
                print(f"   ⚠️  获取总数失败: HTTP {response.status_code}")
                return 0
        except Exception as e:
            print(f"   ⚠️  获取总数异常: {e}")
            return 0
    
    def search(self, query=None, page=1, page_size=50, max_retries=50, retry_delay=5):
        """
        搜索 ZoomEye（带重试机制）
        
        Args:
            query: 搜索查询（Base64编码的查询字符串），如果不提供则使用 .env 中的查询
            page: 页码
            page_size: 每页数量
            max_retries: 最大重试次数（默认50次）
            retry_delay: 重试延迟（秒，默认5秒）
        
        Returns:
            dict: API响应，失败返回 None
        """
        # 如果未提供查询，使用从 .env 提取的查询
        if query is None:
            query = getattr(self, '_query', None)
            if query is None:
                raise ValueError("未找到查询参数，请提供 query 参数")
        
        # 构建 URL - 使用 API 端点
        base_url = "https://www.zoomeye.ai/api/search"
        
        # 构建查询参数
        params = {
            'q': query,
            'page': page,
            'pageSize': page_size,
            't': 'v4+v6+web'
        }
        
        # 构建 Referer（用于 API 请求）
        referer = f"https://www.zoomeye.ai/searchResult?q={query}&page={page}&pageSize={page_size}"
        self.session.headers['Referer'] = referer
        
        # 添加 API 特定的 headers
        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'X-Original-Referer': '',
        })
        
        # 从现有 cookie 中提取 token 作为 Cube-Authorization
        token = self.session.cookies.get('token')
        if token:
            self.session.headers['Cube-Authorization'] = token
        
        # 重试循环
        for attempt in range(1, max_retries + 1):
            try:
                # 发送请求
                response = self.session.get(base_url, params=params, timeout=30)
                
                # 检查响应状态
                if response.status_code == 200:
                    return response.json()
                else:
                    error_msg = f"HTTP {response.status_code}"
                    if attempt < max_retries:
                        print(f"   ⚠️  请求失败 ({error_msg})，{retry_delay}秒后重试 (尝试 {attempt}/{max_retries})...")
                        time.sleep(retry_delay)
                    else:
                        print(f"   ❌ 请求失败: {error_msg} (已达到最大重试次数 {max_retries})")
                        print(f"   📝 响应内容: {response.text[:200]}")
                        return None
                        
            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    print(f"   ⚠️  请求超时，{retry_delay}秒后重试 (尝试 {attempt}/{max_retries})...")
                    time.sleep(retry_delay)
                else:
                    print(f"   ❌ 请求超时 (已达到最大重试次数 {max_retries})")
                    return None
                    
            except requests.exceptions.ConnectionError:
                if attempt < max_retries:
                    print(f"   ⚠️  连接错误，{retry_delay}秒后重试 (尝试 {attempt}/{max_retries})...")
                    time.sleep(retry_delay)
                else:
                    print(f"   ❌ 连接错误 (已达到最大重试次数 {max_retries})")
                    return None
                    
            except Exception as e:
                if attempt < max_retries:
                    print(f"   ⚠️  请求异常: {e}，{retry_delay}秒后重试 (尝试 {attempt}/{max_retries})...")
                    time.sleep(retry_delay)
                else:
                    print(f"   ❌ 请求异常: {e} (已达到最大重试次数 {max_retries})")
                    return None
        
        return None
    
    def decode_query(self, encoded_query):
        """
        解码 Base64 编码的查询
        """
        try:
            # 处理 URL 编码
            from urllib.parse import unquote
            encoded_query = unquote(encoded_query)
            
            # 添加 padding
            padding = 4 - (len(encoded_query) % 4)
            if padding != 4:
                encoded_query += '=' * padding
            
            decoded = base64.b64decode(encoded_query).decode('utf-8')
            return decoded
        except Exception as e:
            print(f"解码失败: {e}")
            return encoded_query


def get_ip(match):
    """
    从 match 中提取 IP，兼容字符串和数组两种格式
    """
    ip_value = match.get('ip', 'N/A')
    
    # 如果 IP 是字符串
    if isinstance(ip_value, str):
        return ip_value
    
    # 如果 IP 是数组
    if isinstance(ip_value, list):
        # 过滤掉无效值，取第一个有效的
        for ip in ip_value:
            if ip and ip != 'N/A':
                return ip
        return ip_value[0] if ip_value else 'N/A'
    
    # 其他情况返回 N/A
    return 'N/A'


def calculate_pages(total_count, page_size=50, max_pages=5):
    """
    根据总结果数计算需要获取的页数
    
    規則：
    - 先計算理論需要的頁數（無條件進位）
    - 再根據總數規則決定要抓的頁數
    - 取兩者的最大值，確保不會遺漏資料
    
    例如：
    - 88 個 -> 理論 2 頁，規則 1 頁 -> 取 2 頁 ✅
    - 120 個 -> 理論 3 頁，規則 2 頁 -> 取 3 頁 ✅
    - 180 個 -> 理論 4 頁，規則 3 頁 -> 取 4 頁 ✅
    - 230 個 -> 理論 5 頁，規則 4 頁 -> 取 5 頁 ✅
    - 300 個 -> 理論 6 頁，規則 5 頁 -> 取 5 頁（上限）
    
    Args:
        total_count: 总结果数
        page_size: 每页数量（默认50）
        max_pages: 最大页数（默认5）
    
    Returns:
        int: 需要获取的页数
    """
    if total_count <= 0:
        return 1  # 至少有1页
    
    # 計算理論需要的頁數（無條件進位）
    needed_pages = math.ceil(total_count / page_size)
    
    # 根據總數規則決定要抓的頁數
    if total_count >= 250:
        rule_pages = 5
    elif total_count >= 200:
        rule_pages = 4
    elif total_count >= 150:
        rule_pages = 3
    elif total_count >= 100:
        rule_pages = 2
    else:
        rule_pages = 1
    
    # 取理論頁數和規則頁數的最大值，但不超過最大頁數限制
    final_pages = max(needed_pages, rule_pages)
    
    # 確保不超過最大頁數
    return min(final_pages, max_pages)


def search_dynamic_pages(max_retries=50):
    """
    动态搜索：根据总结果数自动决定抓取页数
    
    Args:
        max_retries: 每页的最大重试次数（默认50次）
    """
    api = ZoomEyeAPI('.env')
    
    # 获取查询（从 .env 自动提取）
    query = api._query
    print(f"从 .env 提取的查询: {query}")
    
    # 解码查询查看实际内容
    decoded = api.decode_query(query)
    print(f"解码后的查询: {decoded}")
    print("=" * 80)
    
    # 第一步：获取总结果数
    print("\n📊 正在获取搜索结果总数...")
    total_count = api.get_total_count(query)
    
    if total_count == 0:
        print("⚠️  未获取到结果总数，将使用默认值（5页）")
        total_pages = 5
    else:
        print(f"📊 总结果数: {total_count}")
        
        # 计算理论页数
        needed_pages = math.ceil(total_count / 50)
        print(f"📄 理論需要 {needed_pages} 頁（每頁50筆）")
        
        # 计算规则页数
        if total_count >= 250:
            rule_pages = 5
            rule_desc = ">= 250，規則抓 5 頁"
        elif total_count >= 200:
            rule_pages = 4
            rule_desc = "200-249，規則抓 4 頁"
        elif total_count >= 150:
            rule_pages = 3
            rule_desc = "150-199，規則抓 3 頁"
        elif total_count >= 100:
            rule_pages = 2
            rule_desc = "100-149，規則抓 2 頁"
        else:
            rule_pages = 1
            rule_desc = "< 100，規則抓 1 頁"
        
        print(f"📄 規則: {rule_desc}")
        
        # 计算最终页数（取最大值）
        total_pages = max(needed_pages, rule_pages)
        total_pages = min(total_pages, 5)  # 不超過5頁
        
        print(f"📄 最終決定抓取 {total_pages} 頁 (理論 {needed_pages} 頁 vs 規則 {rule_pages} 頁，取較大值)")
        
        # 顯示特殊情況說明
        if total_pages > rule_pages:
            print(f"   ⚠️  因為理論頁數 ({needed_pages}) 大於規則頁數 ({rule_pages})，為避免遺漏資料，採用理論頁數")
    
    print("=" * 80)
    
    all_results = []
    failed_pages = []
    page_size = 50
    
    # 搜索计算出的页数
    for page in range(1, total_pages + 1):
        print(f"\n📡 搜索第 {page} 页...")
        
        # 使用重试机制
        result = api.search(page=page, page_size=page_size, max_retries=max_retries, retry_delay=5)
        
        if result:
            # 获取总数（第一页时获取）
            if page == 1 and total_count == 0:
                total_count = result.get('total', 0)
                print(f"📊 总结果数: {total_count}")
            
            # API 返回的数据在 'matches' 字段
            matches = result.get('matches', [])
            
            # 提取 IP、端口和网域
            page_results = []
            for match in matches:
                ip = get_ip(match)
                portinfo = match.get('portinfo', {})
                port = portinfo.get('port', 'N/A')
                site = match.get('site', 'N/A')
                
                item = {
                    'ip': ip,
                    'port': port,
                    'domain': site
                }
                page_results.append(item)
                all_results.append(item)
            
            print(f"   ✅ 获取到 {len(matches)} 条结果")
            print(f"   📊 已累计: {len(all_results)} 条")
            
            # 保存单页结果
            page_data = {
                'total': total_count,
                'page': page,
                'total_pages': total_pages,
                'needed_pages': math.ceil(total_count / 50) if total_count > 0 else 0,
                'data': page_results
            }
            with open(f'zoomeye_page{page}_simple.json', 'w', encoding='utf-8') as f:
                json.dump(page_data, f, ensure_ascii=False, indent=2)
            print(f"   ✅ 已保存到 zoomeye_page{page}_simple.json")
        else:
            print(f"   ❌ 第 {page} 页获取失败")
            failed_pages.append(page)
        
        # 延迟避免请求过快
        if page < total_pages:
            time.sleep(1)
    
    # 如果有失败的页面，尝试重新获取
    if failed_pages:
        print("\n" + "=" * 80)
        print(f"🔁 检测到 {len(failed_pages)} 个页面失败，正在重新尝试获取...")
        print(f"   失败的页面: {failed_pages}")
        
        for page in failed_pages[:]:
            print(f"\n📡 重新获取第 {page} 页...")
            
            result = api.search(page=page, page_size=page_size, max_retries=50, retry_delay=5)
            
            if result:
                matches = result.get('matches', [])
                
                page_results = []
                for match in matches:
                    ip = get_ip(match)
                    portinfo = match.get('portinfo', {})
                    port = portinfo.get('port', 'N/A')
                    site = match.get('site', 'N/A')
                    
                    item = {
                        'ip': ip,
                        'port': port,
                        'domain': site
                    }
                    page_results.append(item)
                    all_results.append(item)
                
                print(f"   ✅ 重新获取成功，得到 {len(matches)} 条结果")
                
                page_data = {
                    'total': total_count,
                    'page': page,
                    'total_pages': total_pages,
                    'needed_pages': math.ceil(total_count / 50) if total_count > 0 else 0,
                    'data': page_results
                }
                with open(f'zoomeye_page{page}_simple.json', 'w', encoding='utf-8') as f:
                    json.dump(page_data, f, ensure_ascii=False, indent=2)
                print(f"   ✅ 已更新 zoomeye_page{page}_simple.json")
                
                failed_pages.remove(page)
            else:
                print(f"   ❌ 第 {page} 页重新获取仍然失败")
    
    # 保存所有结果
    output = {
        'total': total_count,
        'fetched': len(all_results),
        'total_pages': total_pages,
        'needed_pages': math.ceil(total_count / 50) if total_count > 0 else 0,
        'failed_pages': failed_pages,
        'data': all_results
    }
    
    with open('zoomeye_all_5_pages_simple.json', 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ 共获取 {len(all_results)} 条结果（总计 {total_count} 条）")
    print(f"📄 抓取了 {total_pages} 页")
    if failed_pages:
        print(f"⚠️  仍有 {len(failed_pages)} 个页面获取失败: {failed_pages}")
    else:
        print("✅ 所有页面获取成功！")
    print(f"✅ 已保存到 zoomeye_all_pages_simple.json")
    
    # 显示前10个结果
    if all_results:
        print(f"\n📋 前10个结果:")
        for i, item in enumerate(all_results[:10], 1):
            print(f"  {i}. {item['ip']}:{item['port']}  ({item['domain']})")
    
    return all_results, failed_pages, total_pages


if __name__ == "__main__":
    # 动态搜索：根据总结果数自动决定抓取页数
    results, failed, pages = search_dynamic_pages(max_retries=50)