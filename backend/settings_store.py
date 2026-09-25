"""系统设置存取：system.json 与默认配置合并。"""
import copy

from backend import config
from backend.storage import read_json, atomic_write_json


def _deep_merge(base, override):
    """递归合并：override 覆盖 base 中的键。"""
    result = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def get_settings():
    stored = read_json(config.SETTINGS_FILE, {})
    return _deep_merge(config.DEFAULT_SETTINGS, stored)


def save_settings(patch):
    """合并写入系统设置，返回合并后的完整设置。"""
    current = get_settings()
    merged = _deep_merge(current, patch)
    atomic_write_json(config.SETTINGS_FILE, merged)
    return merged
