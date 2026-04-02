"""时间工具模块。"""

from datetime import datetime, timezone


def parse_request_timestamp(value):
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (int, float)) or str(value).strip().replace(".", "", 1).isdigit():
            ts = float(value)
            if ts > 1e12:
                ts = ts / 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None



def row_timestamp_to_utc(row_ts):
    if not row_ts:
        return None
    try:
        text = str(row_ts).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except Exception:
            dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None
