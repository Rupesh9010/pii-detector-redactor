#!/usr/bin/env python3
import re, json, csv, ast, sys
from typing import Dict, Any

PHONE_RE = re.compile(r"\b\d{10}\b")
AADHAR_RE = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
PASSPORT_RE = re.compile(r"\b[A-Za-z][0-9]{7}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
UPI_RE = re.compile(r"\b[\w\.\-]{2,}@[A-Za-z0-9\.\-]{2,}\b")
IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

def mask_phone(s: str) -> str:
    digits = re.sub(r"\D", "", s)
    if len(digits) == 10:
        return digits[:2] + "XXXXXX" + digits[-2:]
    return "[REDACTED_PII]"

def mask_aadhar(s: str) -> str:
    digits = re.sub(r"\D", "", s)
    if len(digits) == 12:
        return "XXXX XXXX " + digits[-4:]
    return "[REDACTED_PII]"

def mask_email(s: str) -> str:
    m = EMAIL_RE.search(s or "")
    if not m:
        return s
    local, domain = m.group(0).split("@", 1)
    keep = max(2, min(len(local), 2))
    masked_local = local[:keep] + "X" * max(0, len(local) - keep)
    return masked_local + "@" + domain

def mask_passport(s: str) -> str:
    m = PASSPORT_RE.search(s or "")
    if not m:
        return s
    return s[0] + "XXXXXXX"

def mask_upi(s: str) -> str:
    m = UPI_RE.search(s or "")
    if not m:
        return s
    handle = m.group(0)
    user, domain = handle.split("@", 1)
    keep = max(2, min(len(user), 2))
    masked_user = user[:keep] + "X" * max(0, len(user) - keep)
    return masked_user + "@" + domain

def mask_name(full_name: str) -> str:
    if not isinstance(full_name, str):
        return full_name
    parts = [p for p in full_name.split() if p]
    if len(parts) >= 2:
        def mask_part(p):
            return (p[0] + "X" * (len(p)-1)) if len(p) > 1 else p
        return " ".join(mask_part(p) for p in parts[:2])
    return full_name

def mask_address(_: str) -> str:
    return "[REDACTED_PII]"

def mask_ip(ip: str) -> str:
    if not isinstance(ip, str):
        return ip
    if IP_RE.fullmatch(ip):
        parts = ip.split(".")
        if len(parts) == 4:
            parts[-1] = "x"
            return ".".join(parts)
    return "[REDACTED_PII]"

def mask_device(_: str) -> str:
    return "[REDACTED_PII]"

def has_full_name(obj: Dict[str, Any]) -> bool:
    n = obj.get("name", "")
    if isinstance(n, str) and len(n.split()) >= 2:
        return True
    return bool(obj.get("first_name")) and bool(obj.get("last_name"))

def has_email(obj: Dict[str, Any]) -> bool:
    val = obj.get("email", "")
    return bool(EMAIL_RE.search(str(val))) if val else False

def has_address_component(obj: Dict[str, Any]) -> bool:
    if obj.get("address"):
        return True
    has_city_pin = bool(obj.get("city")) and bool(obj.get("pin_code"))
    return has_city_pin

def has_device_context(obj: Dict[str, Any]) -> bool:
    return bool(obj.get("ip_address")) or bool(obj.get("device_id"))

def detect_standalone(obj: Dict[str, Any]):
    flags = {"phone": False, "aadhar": False, "passport": False, "upi": False}
    for key in ("phone", "contact"):
        v = str(obj.get(key, "") or "")
        if re.search(r"\\b\\d{10}\\b", v):
            digits = re.sub(r"\\D", "", v)
            if len(digits) == 10:
                flags["phone"] = True
                break
    v = str(obj.get("aadhar", "") or "")
    if re.search(r"\\b\\d{4}\\s?\\d{4}\\s?\\d{4}\\b", v) and len(re.sub(r"\\D","",v)) == 12:
        flags["aadhar"] = True
    v = str(obj.get("passport", "") or "")
    if re.search(r"\\b[A-Za-z][0-9]{7}\\b", v):
        flags["passport"] = True
    v = str(obj.get("upi_id", "") or "")
    if re.search(r"\\b[\\w\\.\\-]{2,}@[A-Za-z0-9\\.\\-]{2,}\\b", v):
        flags["upi"] = True
    return flags

def redact_obj(obj: Dict[str, Any], is_pii: bool) -> Dict[str, Any]:
    data = dict(obj)
    if not is_pii:
        return data
    for k in ("phone", "contact"):
        if k in data and data[k]:
            data[k] = mask_phone(str(data[k]))
    if "aadhar" in data and data.get("aadhar"):
        data["aadhar"] = mask_aadhar(str(data["aadhar"]))
    if "passport" in data and data.get("passport"):
        data["passport"] = mask_passport(str(data["passport"]))
    if "upi_id" in data and data.get("upi_id"):
        data["upi_id"] = mask_upi(str(data["upi_id"]))
    if "name" in data and data.get("name"):
        data["name"] = mask_name(str(data["name"]))
    if "first_name" in data and data.get("first_name"):
        fn = str(data["first_name"])
        data["first_name"] = fn[0] + "X" * (len(fn)-1) if len(fn) > 1 else fn
    if "last_name" in data and data.get("last_name"):
        ln = str(data["last_name"])
        data["last_name"] = ln[0] + "X" * (len(ln)-1) if len(ln) > 1 else ln
    if "email" in data and data.get("email"):
        data["email"] = mask_email(str(data["email"]))
    if "address" in data and data.get("address"):
        data["address"] = mask_address(str(data["address"]))
    if "ip_address" in data and data.get("ip_address"):
        data["ip_address"] = mask_ip(str(data["ip_address"]))
    if "device_id" in data and data.get("device_id"):
        data["device_id"] = mask_device(str(data["device_id"]))
    if "pin_code" in data and data.get("pin_code"):
        p = str(data["pin_code"])
        digits = re.sub(r"\\D","",p)
        if digits.isdigit() and len(digits) >= 6:
            data["pin_code"] = "XXXX" + digits[-2:]
    return data

def parse_json_cell(cell: str) -> Dict[str, Any]:
    if cell is None:
        return {}
    s = cell
    try:
        return json.loads(s)
    except Exception:
        pass
    try:
        return ast.literal_eval(s)
    except Exception:
        pass
    try:
        s2 = s.replace("'", '"')
        return json.loads(s2)
    except Exception:
        return {}

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv> [<output_csv>]")
        sys.exit(1)
    input_csv = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else "redacted_output_candidate_full_name.csv"
    with open(input_csv, newline="", encoding="utf-8") as f_in, \
         open(output_csv, "w", newline="", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            record_id = row.get("record_id")
            data_json = row.get("Data_json") or row.get("data_json") or ""
            obj = parse_json_cell(data_json)
            standalone = detect_standalone(obj)
            combinatorial_components = sum([
                has_full_name(obj),
                has_email(obj),
                has_address_component(obj),
                has_device_context(obj),
            ])
            combinatorial = combinatorial_components >= 2
            is_pii = any(standalone.values()) or combinatorial
            redacted_obj = redact_obj(obj, is_pii)
            writer.writerow({
                "record_id": record_id,
                "redacted_data_json": json.dumps(redacted_obj, ensure_ascii=False),
                "is_pii": str(bool(is_pii))
            })

if __name__ == "__main__":
    main()
