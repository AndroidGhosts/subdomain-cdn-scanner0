[app]
title = Subdomain CDN Scanner
package.name = subdomaincdnscanner
package.domain = com.ghost.subdomaincdnscanner
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,txt
version = 0.1
requirements = python3,requests,dnspython,colorama,urllib3,openssl
orientation = portrait

[buildozer]
log_level = 2
warn_on_root = 1

# إعدادات Android المحددة
[app:android]
api = 33
minapi = 21
ndk = 25b
android.allow_backup = True
android.accept_sdk_license = True

# إعدادات Python
[python]
android.python = 3.9
