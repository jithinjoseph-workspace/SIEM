import sys, os, re
sys.path.insert(0, os.path.dirname(__file__))
from test_100_log_types import LOG_TYPES

failed_indices = [21, 22, 25, 26, 28, 32, 41, 42, 44, 47, 52, 57, 64, 67, 91, 99]

ts_pattern = r'^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
kv_pattern = re.compile(r'([\w\.\-]+)=')

passed_count = 0
for idx in failed_indices:
    item = LOG_TYPES[idx-1]
    name = item['name']
    samples = item['samples']
    
    # 1. Find keys in each sample
    sample_key_lists = [kv_pattern.findall(s) for s in samples]
    s0_keys = sample_key_lists[0]
    common_keys = [k for k in s0_keys if all(k in k_list for k_list in sample_key_lists[1:]) and k != 'dc']
    
    # 2. Build Rust-compatible regex (NO lookaround)
    parts = ['^']
    if re.search(ts_pattern, samples[0]):
        parts.append(r'(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+')
    
    for i, key in enumerate(common_keys):
        gname = key.replace('.', '_').replace('-', '_')
        if i == len(common_keys) - 1:
            # Last common key: captures to end or next space
            parts.append(f'.*?{re.escape(key)}=(?P<{gname}>.+?)(?:\\s.*)?$')
        else:
            parts.append(f'.*?{re.escape(key)}=(?P<{gname}>[^\\s,]+|"[^"]*")')
            
    regex_str = ''.join(parts)
    try:
        compiled = re.compile(regex_str)
        all_matched = all(compiled.search(s) is not None for s in samples)
        if all_matched:
            passed_count += 1
            print(f'[{idx:03d}] PASS {name}: {len(common_keys)} keys')
        else:
            print(f'[{idx:03d}] FAIL {name}: regex={regex_str}')
            for s in samples:
                print('   Match?', bool(compiled.search(s)), '->', s[:60])
    except Exception as e:
        print(f'[{idx:03d}] ERROR {name}: {e}')

print(f'\nTotal passed: {passed_count}/{len(failed_indices)}')
