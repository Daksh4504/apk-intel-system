from androguard.misc import AnalyzeAPK

# Dangerous permissions list
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.RECEIVE_BOOT_COMPLETED"
}

def analyze_permissions(apk_path):
    a, d, dx = AnalyzeAPK(apk_path)
    permissions = a.get_permissions()

    dangerous = []
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            dangerous.append(perm)

    return {
        "all_permissions": permissions,
        "dangerous_permissions": dangerous
    }
