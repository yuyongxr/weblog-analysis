import re
from collections import defaultdict
from datetime import datetime
import os

# 各字段的独立正则表达式
# ip_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+)')
ip_pattern = re.compile(r'(?P<ip>(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5]))')
timestamp_pattern = re.compile(r'\[(?P<timestamp>.*?)\]')
method_url_pattern = re.compile(r'"(?P<method>\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b)\s+(?P<url>.*?)\s+HTTP/[\d\.]+"')
status_code_pattern = re.compile(r'(?P<status_code>\s(\d{3})\s)')
user_agent_pattern = re.compile(r'"(?P<user_agent>Mozilla[^"]+)"')


# 统计变量
stats = {
    'status_code_count': defaultdict(int),  # 统计状态码
    'method_count': defaultdict(int),  # 统计请求方法
    'user_agent_count': defaultdict(int),  # 统计用户代理
    'ip_count': defaultdict(int),  # 统计客户端IP
    'hourly_requests': defaultdict(int),  # 按小时统计请求数
}

def parse_log(log_line):
    """解析日志行，返回解析后的数据字典"""
    parsed_data = {}

    # 逐个字段匹配
    ip_match = ip_pattern.findall(log_line)
    if ip_match:
        parsed_data['ip'] = ip_match

    timestamp_match = timestamp_pattern.search(log_line)
    if timestamp_match:
        parsed_data['timestamp'] = timestamp_match.group('timestamp')

    method_url_match = method_url_pattern.search(log_line)
    if method_url_match:
        parsed_data['method'] = method_url_match.group('method')
        parsed_data['url'] = method_url_match.group('url')

    status_code_match = status_code_pattern.search(log_line)
    if status_code_match:
        parsed_data['status_code'] = status_code_match.group('status_code')

    user_agent_match = user_agent_pattern.search(log_line)
    if user_agent_match:
        parsed_data['user_agent'] = user_agent_match.group('user_agent')

    return parsed_data if parsed_data else None


def update_stats(parsed_data):
    """更新统计数据"""
    if parsed_data:
        # 按状态码统计
        if 'status_code' in parsed_data:
            stats['status_code_count'][parsed_data['status_code']] += 1

        # 按请求方法统计
        if 'method' in parsed_data:
            stats['method_count'][parsed_data['method']] += 1

        # 按用户代理统计
        if 'user_agent' in parsed_data:
            stats['user_agent_count'][parsed_data['user_agent']] += 1

        # 按客户端IP统计
        if 'ip' in parsed_data:
            for i in parsed_data['ip']:
                stats['ip_count'][i] += 1

        # 按小时统计请求数
        if 'timestamp' in parsed_data:
            timestamp = datetime.strptime(parsed_data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
            hour = timestamp.strftime("%Y-%m-%d %H:00")
            stats['hourly_requests'][hour] += 1

def read_log_file(log_file_path):
    """从指定的日志文件中读取内容并返回"""
    if not os.path.isfile(log_file_path):
        print(f"文件 {log_file_path} 不存在!")
        return []

    with open(log_file_path, 'r') as file:
        return file.readlines()


def process_log_file(log_file_path):
    """处理日志文件并更新统计数据"""
    log_lines = read_log_file(log_file_path)
    for log_line in log_lines:
        # print(f"正在处理日志行：{log_line}")
        parsed_data = parse_log(log_line)
        update_stats(parsed_data)


def print_statistics():
    """打印统计信息"""
    print("状态码统计：")
    for status_code, count in stats['status_code_count'].items():
        print(f"状态码 {status_code}: {count}")

    print("\n请求方法统计：")
    for method, count in stats['method_count'].items():
        print(f"方法 {method}: {count}")

    print("\nuseragent统计：")
    for user_agent, count in stats['user_agent_count'].items():
        print(f"useragent统计： {user_agent}: {count}")


    print("\nIP统计：")
    for ip, count in stats['ip_count'].items():
        print(f"IP {ip}: {count}")

    print("\n按小时统计请求数：")
    for hour, count in stats['hourly_requests'].items():
        print(f"{hour}: {count}")


if __name__ == "__main__":
    # 默认读取当前目录下的access.log文件
    log_file = 'access.log'
    # log_file = 'test.log'

    # 如果希望读取其他文件，可以更改log_file的路径
    if os.path.isfile(log_file):
        print(f"正在读取日志文件：{log_file}")
        process_log_file(log_file)
    else:
        print(f"未找到日志文件 {log_file}, 请检查文件路径或指定文件名")

    # 打印统计信息
    print_statistics()
