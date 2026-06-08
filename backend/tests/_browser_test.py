import requests, json, time

base = 'http://127.0.0.1:5000'

# 模拟浏览器：第一次请求就 POST detect
print("=== Test 1: Fresh start - POST detect as first request ===")
r = requests.post(base + '/api/detect', json={'text': 'hello'}, timeout=30)
print(f'  Status: {r.status_code}')
if r.status_code != 200:
    print(f'  Body: {r.text[:200]}')

# 模拟并发请求（前端页面加载时）
print("\n=== Test 2: Concurrent requests (like browser tab opens) ===")
import concurrent.futures
def fetch(path, method='GET', data=None):
    try:
        r = requests.post(base + path, json=data, timeout=30) if method == 'POST' else requests.get(base + path, timeout=30)
        return path, r.status_code, 'OK' if 200 <= r.status_code < 300 else 'FAIL'
    except Exception as e:
        return path, 0, f'ERROR: {e}'

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
    futures = [
        pool.submit(fetch, '/api/detect', 'POST', {'text': 'init'}),
        pool.submit(fetch, '/api/stats'),
        pool.submit(fetch, '/api/events'),
        pool.submit(fetch, '/api/policies'),
        pool.submit(fetch, '/api/dashboard/overview'),
    ]
    for f in concurrent.futures.as_completed(futures):
        path, code, status = f.result()
        print(f'  [{status}] {code} {path}')

# 模拟 dashboard 加载
print("\n=== Test 3: Dashboard endpoints ===")
r1 = requests.get(base + '/api/dashboard/overview', timeout=30)
r2 = requests.get(base + '/api/dashboard/live?limit=25', timeout=30)
print(f'  /dashboard/overview -> {r1.status_code}')
print(f'  /dashboard/live -> {r2.status_code}')
if r1.status_code != 200:
    print(f'  Body: {r1.text[:200]}')
if r2.status_code != 200:
    print(f'  Body: {r2.text[:200]}')

# 再次测试 /api/health
print("\n=== Test 4: /api/health ===")
r = requests.get(base + '/api/health', timeout=30)
print(f'  Status: {r.status_code}, Body: {r.text[:200]}')

print("\n=== Done ===')
