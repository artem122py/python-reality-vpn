[1mdiff --git a/config.example.json b/config.example.json[m
[1mindex a2615f0..af975fb 100644[m
[1m--- a/config.example.json[m
[1m+++ b/config.example.json[m
[36m@@ -19,5 +19,21 @@[m
   "vision_client_padding_max": 1111,[m
   "vision_server_padding_min": 111,[m
   "vision_server_padding_max": 1111,[m
[31m-  "vision_debug": false[m
[32m+[m[32m  "vision_debug": false,[m
[32m+[m[32m  "traffic_limits_enabled": false,[m
[32m+[m[32m  "traffic_limit_default": 0,[m
[32m+[m[32m  "users": [[m
[32m+[m[32m    {[m
[32m+[m[32m      "name": "default",[m
[32m+[m[32m      "uuid": "00000000-0000-0000-0000-000000000001",[m
[32m+[m[32m      "short_id": "0011223344556677",[m
[32m+[m[32m      "limit_bytes": 0[m
[32m+[m[32m    },[m
[32m+[m[32m    {[m
[32m+[m[32m      "name": "friend",[m
[32m+[m[32m      "uuid": "00000000-0000-0000-0000-000000000002",[m
[32m+[m[32m      "short_id": "8899aabbccddeeff",[m
[32m+[m[32m      "limit_bytes": 10737418240[m
[32m+[m[32m    }[m
[32m+[m[32m  ][m
 }[m
\ No newline at end of file[m
[1mdiff --git a/main.py b/main.py[m
[1mindex 1b9766c..a615791 100644[m
[1m--- a/main.py[m
[1m+++ b/main.py[m
[36m@@ -85,7 +85,7 @@[m [mdef main():[m
     argv = sys.argv[m
 [m
     # Расширенные команды (без addr)[m
[31m-    if len(argv) >= 2 and argv[1] in ("status", "stop", "users", "link", "stats", "version"):[m
[32m+[m[32m    if len(argv) >= 2 and argv[1] in ("status", "stop", "users", "link", "stats", "version", "traffic"):[m
         cmd = argv[1][m
         rest = argv[2:][m
         from vpncli import cmd_status, cmd_stop, cmd_users, cmd_link[m
[36m@@ -101,6 +101,9 @@[m [mdef main():[m
         elif cmd == "version":[m
             from vpncli import cmd_version[m
             cmd_version()[m
[32m+[m[32m        elif cmd == "traffic":[m
[32m+[m[32m            from vpncli import cmd_traffic[m
[32m+[m[32m            cmd_traffic()[m
         elif cmd == "link":[m
             # link [name] [host] [port][m
             cmd_link(rest[0] if len(rest) > 0 else None,[m
[1mdiff --git a/vpncli.py b/vpncli.py[m
[1mindex 94fa122..559a8d5 100644[m
[1m--- a/vpncli.py[m
[1m+++ b/vpncli.py[m
[36m@@ -10,6 +10,57 @@[m [mfrom genconf import gen_uuid, gen_short_id, gen_x25519[m
 [m
 [m
 [m
[32m+[m[32mdef cmd_traffic():[m
[32m+[m[32m    """Показать использование трафика."""[m
[32m+[m[32m    from vpnstats import stats[m
[32m+[m[32m    from vpntraffic import limiter[m
[32m+[m
[32m+[m[32m    stats.load()[m
[32m+[m[32m    try:[m
[32m+[m[32m        cfg = load_config_file()[m
[32m+[m[32m        stats.load_user_map(cfg)[m
[32m+[m[32m        limiter.load(cfg)[m
[32m+[m[32m    except Exception as e:[m
[32m+[m[32m        print(f"config error: {e}")[m
[32m+[m[32m        return[m
[32m+[m
[32m+[m[32m    if not limiter.enabled:[m
[32m+[m[32m        print("traffic limits: DISABLED (traffic_limits_enabled = false)")[m
[32m+[m[32m        print()[m
[32m+[m[32m        print("=== per-user usage (без лимитов) ===")[m
[32m+[m[32m        print(stats.per_user_summary())[m
[32m+[m[32m        return[m
[32m+[m
[32m+[m[32m    print("traffic limits: ENABLED")[m
[32m+[m[32m    print()[m
[32m+[m
[32m+[m[32m    # Собираем всех известных пользователей[m
[32m+[m[32m    all_users = {}[m
[32m+[m[32m    for uid, us in stats.users.items():[m
[32m+[m[32m        all_users[uid] = us[m
[32m+[m
[32m+[m[32m    # Добавляем тех, кто в конфиге, но ещё не подключался[m
[32m+[m[32m    for uid, name in limiter._uuid_to_name.items():[m
[32m+[m[32m        if uid not in all_users:[m
[32m+[m[32m            from vpnstats import UserStat[m
[32m+[m[32m            us = UserStat(name, uid)[m
[32m+[m[32m            all_users[uid] = us[m
[32m+[m
[32m+[m[32m    print("=== per-user usage ===")[m
[32m+[m[32m    for uid, us in all_users.items():[m
[32m+[m[32m        limit = limiter._uuid_to_limit.get(uid, limiter.default_limit)[m
[32m+[m[32m        used = us.up + us.down[m
[32m+[m[32m        if limit > 0:[m
[32m+[m[32m            percent = used / limit * 100[m
[32m+[m[32m            bar_len = min(20, int(percent / 5))[m
[32m+[m[32m            bar = "█" * bar_len + "░" * (20 - bar_len)[m
[32m+[m[32m            status = " ❌BLOCKED" if percent >= 100 else ""[m
[32m+[m[32m            print(f"  {us.name:<16} [{bar}] {percent:5.1f}% "[m
[32m+[m[32m                  f"({limiter._fmt(used)} / {limiter._fmt(limit)}){status}")[m
[32m+[m[32m        else:[m
[32m+[m[32m            print(f"  {us.name:<16} (no limit) {limiter._fmt(used)}")[m
[32m+[m
[32m+[m
 def cmd_version():[m
     """Показать версию сервера."""[m
     try:[m
[36m@@ -193,6 +244,8 @@[m [mdef cmd_users(args):[m
     action = args[0][m
     if action == "list":[m
         cmd_users_list()[m
[32m+[m[32m    elif action == "usage":[m
[32m+[m[32m        cmd_traffic()[m
     elif action == "add":[m
         if len(args) < 2:[m
             print("usage: users add <name> [uuid] [short_id]")[m
