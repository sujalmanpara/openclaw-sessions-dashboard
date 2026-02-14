#!/usr/bin/env python3
import http.server, json, os, socketserver, glob, time, threading, asyncio, websockets, urllib.request, urllib.error, gzip, hashlib, secrets, base64
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, urlencode
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

PORT = 3847
WS_PORT = 3848
DIR = os.path.dirname(os.path.abspath(__file__))
SESSIONS_FILE = '/home/sam/.openclaw/agents/main/sessions/sessions.json'
TOPIC_NAMES_FILE = os.path.join(DIR, 'topic-names.json')

# ── In-memory cache ──
_sessions_cache = {'data': None, 'etag': None, 'mtime': 0}
_sessions_cache_lock = threading.Lock()

# ── OAuth Constants ──
OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
OAUTH_AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
OAUTH_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
OAUTH_SCOPES = "org:create_api_key user:profile user:inference"
OAUTH_CREDS_FILE = os.path.join(DIR, 'oauth-creds.json')

# Pending PKCE sessions: {sessionId: {verifier, createdAt}}
_pkce_sessions = {}
_pkce_lock = threading.Lock()

def _pkce_cleanup():
    """Remove PKCE sessions older than 10 minutes."""
    now = time.time()
    with _pkce_lock:
        expired = [k for k, v in _pkce_sessions.items() if now - v['createdAt'] > 600]
        for k in expired:
            del _pkce_sessions[k]

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def _oauth_load_creds():
    try:
        with open(OAUTH_CREDS_FILE) as f:
            return json.load(f)
    except:
        return {"accounts": {}}

def _oauth_save_creds(creds):
    with open(OAUTH_CREDS_FILE, 'w') as f:
        json.dump(creds, f, indent=2)
    os.chmod(OAUTH_CREDS_FILE, 0o600)

def _oauth_token_request(payload):
    """Make a POST to the OAuth token endpoint with browser-like headers."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(OAUTH_TOKEN_URL, data=data, headers={
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Origin': 'https://claude.ai',
        'Referer': 'https://claude.ai/',
    })
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = ''
        try:
            body = e.read().decode()
        except:
            pass
        raise ValueError(f'Token exchange failed (HTTP {e.code}): {body}')

def _oauth_refresh_if_needed(account):
    """Refresh token if expiring within 5 minutes. Returns updated account or None on failure."""
    if account.get('expiresAt', 0) > time.time() + 300:
        return account
    try:
        result = _oauth_token_request({
            "grant_type": "refresh_token",
            "client_id": OAUTH_CLIENT_ID,
            "refresh_token": account['refreshToken'],
        })
        account['accessToken'] = result['access_token']
        account['refreshToken'] = result['refresh_token']
        account['expiresAt'] = time.time() + result.get('expires_in', 3600)
        return account
    except Exception as e:
        account['refreshError'] = str(e)
        return None

def _oauth_get_usage(access_token):
    """Fetch usage stats for an OAuth account."""
    req = urllib.request.Request(
        'https://api.anthropic.com/api/oauth/usage',
        headers={
            'Authorization': f'Bearer {access_token}',
            'anthropic-beta': 'oauth-2025-04-20',
        }
    )
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())

def get_system_info():
    info = {}
    try:
        # CPU
        cpu_count = os.cpu_count() or 1
        load1, load5, load15 = os.getloadavg()
        cpu_usage = min(100, round(load1 / cpu_count * 100, 1))
        cpu_model = ''
        try:
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if 'model name' in line:
                        cpu_model = line.split(':')[1].strip()
                        break
        except: pass
        info['cpu'] = {
            'usage_pct': cpu_usage,
            'load_avg': f'{load1:.2f} / {load5:.2f} / {load15:.2f}',
            'cores': cpu_count,
            'model': cpu_model
        }
        
        # Memory
        try:
            with open('/proc/meminfo') as f:
                meminfo = {}
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = int(parts[1].strip().split()[0])  # kB
                        meminfo[key] = val
            total = meminfo.get('MemTotal', 0)
            avail = meminfo.get('MemAvailable', 0)
            used = total - avail
            swap_total = meminfo.get('SwapTotal', 0)
            swap_free = meminfo.get('SwapFree', 0)
            swap_used = swap_total - swap_free
            def fmt_kb(kb):
                if kb > 1048576: return f'{kb/1048576:.1f}G'
                if kb > 1024: return f'{kb/1024:.0f}M'
                return f'{kb}K'
            info['memory'] = {
                'total': fmt_kb(total), 'used': fmt_kb(used), 'available': fmt_kb(avail),
                'used_pct': round(used/total*100, 1) if total else 0,
                'swap_total': fmt_kb(swap_total), 'swap_used': fmt_kb(swap_used),
                'swap_pct': round(swap_used/swap_total*100, 1) if swap_total else 0
            }
        except: info['memory'] = {}
        
        # Disk
        try:
            df = subprocess.check_output(['df', '-h', '--output=source,fstype,size,used,avail,pcent,target'], text=True)
            disks = []
            for line in df.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 7 and parts[0].startswith('/'):
                    pct = int(parts[5].replace('%',''))
                    disks.append({'fs': parts[0], 'type': parts[1], 'size': parts[2], 'used': parts[3], 'avail': parts[4], 'used_pct': pct, 'mount': parts[6]})
            info['disks'] = disks
        except: info['disks'] = []
        
        # Network
        try:
            with open('/proc/net/dev') as f:
                lines = f.readlines()[2:]
            rx_total = tx_total = 0
            for line in lines:
                parts = line.split()
                if parts[0].rstrip(':') in ('lo',): continue
                rx_total += int(parts[1])
                tx_total += int(parts[9])
            def fmt_bytes(b):
                if b > 1073741824: return f'{b/1073741824:.1f}G'
                if b > 1048576: return f'{b/1048576:.1f}M'
                if b > 1024: return f'{b/1024:.0f}K'
                return f'{b}B'
            conns = subprocess.check_output(['ss', '-tun'], text=True).count('\n') - 1
            info['network'] = {'rx': fmt_bytes(rx_total), 'tx': fmt_bytes(tx_total), 'connections': str(conns)}
        except: info['network'] = {}
        
        # System
        try:
            hostname = os.uname().nodename
            kernel = os.uname().release
            uptime_s = float(open('/proc/uptime').read().split()[0])
            days = int(uptime_s // 86400)
            hours = int((uptime_s % 86400) // 3600)
            mins = int((uptime_s % 3600) // 60)
            uptime = f'{days}d {hours}h {mins}m' if days else f'{hours}h {mins}m'
            proc_count = len([d for d in os.listdir('/proc') if d.isdigit()])
            info['system'] = {'hostname': hostname, 'kernel': kernel, 'uptime': uptime, 'processes': str(proc_count)}
        except: info['system'] = {}
        
        # Services
        svcs = []
        # Check OpenClaw gateway process
        try:
            result = subprocess.run(['pgrep', '-f', 'openclaw-gateway'], capture_output=True, text=True, timeout=3)
            active = result.returncode == 0
            svcs.append({'name': 'openclaw-gateway', 'status': 'active' if active else 'inactive', 'active': active})
        except:
            svcs.append({'name': 'openclaw-gateway', 'status': 'unknown', 'active': False})
        # Systemd services
        for svc in ['cozy-dashboard']:
            try:
                result = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True, timeout=3)
                status = result.stdout.strip()
                svcs.append({'name': svc, 'status': status, 'active': status == 'active'})
            except:
                svcs.append({'name': svc, 'status': 'unknown', 'active': False})
        # Check tailscale
        try:
            result = subprocess.run(['tailscale', 'status', '--json'], capture_output=True, text=True, timeout=3)
            active = result.returncode == 0
            svcs.append({'name': 'tailscale', 'status': 'active' if active else 'inactive', 'active': active})
        except:
            svcs.append({'name': 'tailscale', 'status': 'unknown', 'active': False})
        info['services'] = svcs
        
        # Top processes
        try:
            ps = subprocess.check_output(['ps', 'aux', '--sort=-pcpu'], text=True, timeout=5)
            procs = []
            for line in ps.strip().split('\n')[1:11]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({'user': parts[0], 'pid': parts[1], 'cpu': parts[2], 'mem': parts[3], 'rss': parts[5], 'cmd': parts[10][:80]})
            info['processes'] = procs
        except: info['processes'] = []
        
    except Exception as e:
        info['error'] = str(e)
    return info

def load_topic_names():
    try:
        with open(TOPIC_NAMES_FILE) as f:
            return json.load(f)
    except:
        return {}
TRANSCRIPTS_DIR = '/home/sam/.openclaw/agents/main/sessions/'
PINNED_FILE = os.path.join(DIR, 'pinned.json')

# WebSocket clients for real-time updates
ws_clients = set()

class ReuseServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    allow_reuse_port = True
    daemon_threads = True

def load_pinned():
    try:
        with open(PINNED_FILE) as f:
            return set(json.load(f))
    except:
        return set()

def save_pinned(pinned):
    try:
        with open(PINNED_FILE, 'w') as f:
            json.dump(list(pinned), f)
    except:
        pass

def get_recent_activity(session_id, max_lines=5):
    """Read last few lines of a transcript to get current activity."""
    patterns = [
        os.path.join(TRANSCRIPTS_DIR, f'{session_id}.jsonl'),
        os.path.join(TRANSCRIPTS_DIR, f'{session_id}-*.jsonl'),
    ]
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    if not files:
        return None
    
    f = max(files, key=os.path.getmtime)
    
    try:
        with open(f, 'rb') as fh:
            fh.seek(0, 2)
            size = fh.tell()
            read_size = min(size, 10240)
            fh.seek(-read_size, 2)
            data = fh.read().decode('utf-8', errors='ignore')
        
        lines = [l for l in data.strip().split('\n') if l.strip()]
        activities = []
        
        for line in lines[-max_lines:]:
            try:
                entry = json.loads(line)
                msg = entry.get('message', {})
                role = msg.get('role', '')
                model = msg.get('model', '')
                stop = msg.get('stopReason', '')
                ts = msg.get('timestamp', entry.get('timestamp', ''))
                cost = msg.get('usage', {}).get('cost', {}).get('total', 0)
                
                content = msg.get('content', [])
                if isinstance(content, str):
                    content = [{'type': 'text', 'text': content}]
                
                activity = {'role': role, 'model': model, 'stop': stop, 'ts': ts, 'cost': cost}
                
                if role == 'toolResult':
                    tn = msg.get('toolName', '?')
                    rt = ''
                    for c in (content if isinstance(content, list) else []):
                        if c.get('type') == 'text':
                            rt = c.get('text', '')[:60]
                            break
                    activity['action'] = f"✅ {tn} done"
                    if rt: activity['detail'] = rt
                    activities.append(activity)
                    continue
                
                for c in (content if isinstance(content, list) else []):
                    t = c.get('type', '')
                    if t == 'toolCall':
                        activity['action'] = f"🔧 {c.get('name', '?')}"
                        args = c.get('arguments', {})
                        if isinstance(args, dict):
                            if 'command' in args:
                                cmd = args['command'][:60]
                                activity['detail'] = cmd
                            elif 'query' in args:
                                activity['detail'] = args['query'][:60]
                            elif 'url' in args:
                                activity['detail'] = args['url'][:60]
                            elif 'action' in args:
                                activity['detail'] = args['action']
                    elif t == 'toolResult':
                        activity['action'] = f"✅ {c.get('name', '?')} done"
                    elif t == 'text' and c.get('text', '').strip():
                        txt = c['text'].strip()
                        if txt != 'NO_REPLY' and len(txt) > 2:
                            activity['action'] = '💬 Responding'
                            activity['detail'] = txt[:80]
                    elif t == 'thinking':
                        activity['action'] = '🧠 Thinking'
                
                if 'action' in activity:
                    activities.append(activity)
            except:
                continue
        
        return activities[-3:] if activities else None
    except:
        return None

def get_auth_info():
    """Get API key profiles from config."""
    try:
        with open('/home/sam/.openclaw/openclaw.json') as f:
            cfg = json.load(f)
        profiles = cfg.get('auth', {}).get('profiles', {})
        order = cfg.get('auth', {}).get('order', {})
        return {'profiles': profiles, 'order': order}
    except:
        return {'profiles': {}, 'order': {}}

def get_cron_jobs():
    """Read cron jobs from jobs.json"""
    try:
        with open('/home/sam/.openclaw/cron/jobs.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        return {'version': 1, 'jobs': [], 'error': str(e)}

def get_cron_runs(job_id):
    """Read cron run history for a specific job"""
    try:
        file_path = f'/home/sam/.openclaw/cron/runs/{job_id}.jsonl'
        if not os.path.exists(file_path):
            return {'runs': []}
        
        with open(file_path, 'r') as f:
            lines = f.read().strip().split('\n')
        
        # Get last 20 lines
        recent_lines = lines[-20:]
        runs = []
        for line in recent_lines:
            line = line.strip()
            if not line:
                continue
            try:
                runs.append(json.loads(line))
            except:
                continue
        
        return {'runs': runs}
    except Exception as e:
        return {'runs': [], 'error': str(e)}

def toggle_cron_job(job_id, enabled):
    """Toggle cron job enabled/disabled"""
    try:
        with open('/home/sam/.openclaw/cron/jobs.json', 'r') as f:
            data = json.load(f)
        
        job = None
        for j in data.get('jobs', []):
            if j.get('id') == job_id:
                job = j
                break
        
        if not job:
            return {'error': 'Job not found'}
        
        job['enabled'] = enabled
        job['updatedAtMs'] = int(time.time() * 1000)
        
        with open('/home/sam/.openclaw/cron/jobs.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        return {'success': True, 'enabled': enabled}
    except Exception as e:
        return {'error': str(e)}

def run_cron_job(job_id):
    """Trigger a cron job run"""
    try:
        result = subprocess.run(
            ['openclaw', 'cron', 'run', job_id],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return {'success': True, 'output': result.stdout.strip()}
        else:
            return {
                'error': f'Command failed with exit code {result.returncode}',
                'output': result.stdout,
                'stderr': result.stderr
            }
    except subprocess.TimeoutExpired:
        return {'error': 'Command timed out'}
    except Exception as e:
        return {'error': str(e)}

def calculate_session_stats(sessions):
    """Calculate aggregate statistics for dashboard."""
    now = time.time() * 1000
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000
    week_ago = (datetime.now() - timedelta(days=7)).timestamp() * 1000
    month_ago = (datetime.now() - timedelta(days=30)).timestamp() * 1000
    
    stats = {
        'total_cost_today': 0,
        'total_cost_week': 0, 
        'total_cost_month': 0,
        'total_tokens_in': 0,
        'total_tokens_out': 0,
        'total_cache_hits': 0,
        'by_model': {},
        'active_sessions': 0,
        'failed_sessions': 0,
        'completed_sessions': 0
    }
    
    for session in sessions:
        updated = session.get('updatedAt', 0)
        activity = session.get('activity', [])
        
        # Count status
        if now - updated < 300000:  # 5 min = active
            stats['active_sessions'] += 1
        
        # Aggregate costs and tokens from activity
        for act in activity:
            cost = act.get('cost', 0)
            if cost > 0:
                ts = act.get('ts', 0)
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp() * 1000
                    except:
                        continue
                
                if ts >= today:
                    stats['total_cost_today'] += cost
                if ts >= week_ago:
                    stats['total_cost_week'] += cost
                if ts >= month_ago:
                    stats['total_cost_month'] += cost
                
                model = act.get('model', 'unknown')
                if model not in stats['by_model']:
                    stats['by_model'][model] = {'cost': 0, 'tokens_in': 0, 'tokens_out': 0}
                stats['by_model'][model]['cost'] += cost
    
    return stats

def get_sessions_with_activity():
    try:
        with open(SESSIONS_FILE) as f:
            raw = json.load(f)
        
        sessions = []
        now = time.time() * 1000
        pinned = load_pinned()
        
        # Build parent-child map
        children_map = {}
        parent_map = {}
        
        for key, val in raw.items():
            if ':run:' in key:
                parent_key = key.rsplit(':run:', 1)[0]
                if parent_key in raw:
                    parent_map[key] = parent_key
                    children_map.setdefault(parent_key, []).append(key)
            spawned_by = val.get('spawnedBy', '')
            if spawned_by and spawned_by in raw:
                parent_map[key] = spawned_by
                children_map.setdefault(spawned_by, []).append(key)
        
        for key, s in raw.items():
            session = {'key': key, **s}
            sid = s.get('sessionId', '')
            updated = s.get('updatedAt', 0)
            
            # Mark if pinned
            session['pinned'] = key in pinned
            
            # Add parent/children references
            if key in parent_map:
                session['parentKey'] = parent_map[key]
                parent = raw.get(parent_map[key], {})
                session['parentLabel'] = parent.get('label', '') or parent.get('displayName', '') or parent_map[key]
            if key in children_map:
                child_list = children_map[key]
                child_info = []
                for ck in sorted(child_list, key=lambda c: raw.get(c, {}).get('updatedAt', 0), reverse=True):
                    cv = raw[ck]
                    child_info.append({
                        'key': ck,
                        'sessionId': cv.get('sessionId', ''),
                        'updatedAt': cv.get('updatedAt', 0),
                        'label': cv.get('label', ''),
                    })
                session['children'] = child_info
                session['childCount'] = len(child_info)
            
            # Classify session type
            if key == 'agent:main:main':
                session['sessionType'] = 'main'
            elif ':subagent:' in key:
                session['sessionType'] = 'subagent'
            elif ':cron:' in key and ':run:' in key:
                session['sessionType'] = 'cron-run'
            elif ':cron:' in key:
                session['sessionType'] = 'cron'
            elif ':telegram:' in key:
                session['sessionType'] = 'telegram'
            else:
                session['sessionType'] = 'other'
            
            # Determine status
            age_ms = now - updated
            if age_ms < 300000:  # 5 min
                session['status'] = 'running'
            elif age_ms < 3600000:  # 1 hour
                session['status'] = 'idle'
            else:
                session['status'] = 'completed'
            
            # Get activity only for ACTIVE sessions (5 min window, not 2 hours)
            if now - updated < 300000 and sid:
                activity = get_recent_activity(sid)
                if activity:
                    session['activity'] = activity
            
            # Strip heavy fields not needed by frontend
            session.pop('skillsSnapshot', None)
            session.pop('systemPromptReport', None)
            session.pop('origin', None)
            session.pop('deliveryContext', None)
            
            sessions.append(session)
        
        auth = get_auth_info()
        stats = calculate_session_stats(sessions)
        topic_names = load_topic_names()
        
        return json.dumps({
            'count': len(sessions), 
            'sessions': sessions, 
            'auth': auth,
            'stats': stats,
            'timestamp': now,
            'topicNames': topic_names
        })
    except Exception as e:
        return json.dumps({'error': str(e), 'count': 0, 'sessions': []})

def _test_anthropic_key(cred, profile_name=''):
    """Test an Anthropic API key. OAuth tokens check usage stats; API keys call messages API."""
    token = cred.get('token') or cred.get('key') or ''
    if not token:
        return {'ok': False, 'error': 'No token/key found'}
    
    is_oauth = token.startswith('sk-ant-oat')
    
    if is_oauth:
        # OAuth tokens (from Claude Code setup-token) can ONLY be used through OpenClaw's
        # gateway — they're restricted to Claude Code client. We check usage stats instead.
        try:
            with open('/home/sam/.openclaw/agents/main/agent/auth-profiles.json') as f:
                store = json.load(f)
            usage = store.get('usageStats', {})
            stats = usage.get(profile_name, {})
            last_ok = stats.get('lastUsed', 0)
            last_err = stats.get('lastFailureAt', 0)
            total_err = stats.get('errorCount', 0)
            last_error_msg = stats.get('lastError', '')
            total_ok = 1 if last_ok > 0 else 0  # no okCount tracked
            
            if last_ok > 0 and last_ok >= last_err:
                # Format last success time
                from datetime import datetime
                last_ok_str = datetime.fromtimestamp(last_ok / 1000).strftime('%H:%M:%S') if last_ok > 1e12 else datetime.fromtimestamp(last_ok).strftime('%H:%M:%S')
                return {
                    'ok': True, 'oauth': True,
                    'note': f'Last used successfully at {last_ok_str} ({total_ok} ok, {total_err} errors)'
                }
            elif last_err > last_ok and last_error_msg:
                return {
                    'ok': False, 'oauth': True,
                    'error': f'Last error: {last_error_msg} ({total_err} errors)'
                }
            elif total_ok == 0 and total_err == 0:
                # No usage data — token exists but hasn't been used yet
                return {'ok': True, 'oauth': True, 'note': 'OAuth token present (no usage data yet)'}
            else:
                return {'ok': True, 'oauth': True, 'note': f'OAuth token ({total_ok} ok, {total_err} errors)'}
        except Exception as e:
            return {'ok': True, 'oauth': True, 'note': 'OAuth token present (cannot read usage stats)'}
    
    # Regular API keys — test with a minimal messages call
    try:
        payload = json.dumps({
            'model': 'claude-3-5-haiku-20241022',
            'max_tokens': 1,
            'messages': [{'role': 'user', 'content': 'hi'}]
        }).encode()
        headers = {
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json',
            'x-api-key': token,
        }
        req = urllib.request.Request(
            'https://api.anthropic.com/v1/messages',
            data=payload,
            headers=headers
        )
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        return {'ok': True, 'model': data.get('model', '')}
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
            msg = body.get('error', {}).get('message', str(e))
        except:
            msg = str(e)
        return {'ok': False, 'error': msg}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=DIR, **kw)
    
    def do_POST(self):
        content_type = self.headers.get('Content-Type', '')

        if self.path == '/api/keys/toggle':
            cl = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(cl).decode()) if cl else {}
            profile_name = body.get('profileName', '')
            enabled = body.get('enabled', True)
            try:
                with open('/home/sam/.openclaw/openclaw.json') as f:
                    cfg = json.load(f)
                auth = cfg.setdefault('auth', {})
                profiles = auth.get('profiles', {})
                if profile_name not in profiles:
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'Profile not found'}).encode())
                    return
                provider = profiles[profile_name].get('provider', '')
                order = auth.setdefault('order', {})
                provider_order = order.setdefault(provider, [])
                if enabled:
                    if profile_name not in provider_order:
                        provider_order.append(profile_name)
                else:
                    if profile_name in provider_order:
                        provider_order.remove(profile_name)
                with open('/home/sam/.openclaw/openclaw.json', 'w') as f:
                    json.dump(cfg, f, indent=2)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'ok'}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path == '/api/keys/reorder':
            cl = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(cl).decode()) if cl else {}
            provider = body.get('provider', '')
            new_order = body.get('order', [])
            try:
                with open('/home/sam/.openclaw/openclaw.json') as f:
                    cfg = json.load(f)
                cfg.setdefault('auth', {}).setdefault('order', {})[provider] = new_order
                with open('/home/sam/.openclaw/openclaw.json', 'w') as f:
                    json.dump(cfg, f, indent=2)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'ok'}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path in ('/api/keys/test', '/api/keys/test-all'):
            cl = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(cl).decode()) if cl else {}
            try:
                auth_store_path = '/home/sam/.openclaw/agents/main/agent/auth-profiles.json'
                with open(auth_store_path) as f:
                    store = json.load(f)
                store_profiles = store.get('profiles', {})

                if self.path == '/api/keys/test':
                    profile_name = body.get('profileName', '')
                    cred = store_profiles.get(profile_name)
                    if not cred:
                        self.send_response(404)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'error': 'Profile not found in auth store'}).encode())
                        return
                    result = _test_anthropic_key(cred, profile_name)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({profile_name: result}).encode())
                else:
                    results = {}
                    with open('/home/sam/.openclaw/openclaw.json') as f:
                        cfg = json.load(f)
                    all_profiles = cfg.get('auth', {}).get('profiles', {})
                    for pname in all_profiles:
                        cred = store_profiles.get(pname)
                        if cred:
                            results[pname] = _test_anthropic_key(cred, pname)
                        else:
                            results[pname] = {'ok': False, 'error': 'No credentials in auth store'}
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(results).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path == '/api/keys/oauth/start':
            try:
                _pkce_cleanup()
                verifier = _b64url(secrets.token_bytes(32))
                challenge = _b64url(hashlib.sha256(verifier.encode('ascii')).digest())
                session_id = secrets.token_hex(16)
                with _pkce_lock:
                    _pkce_sessions[session_id] = {'verifier': verifier, 'createdAt': time.time()}
                params = urlencode({
                    'code': 'true',
                    'client_id': OAUTH_CLIENT_ID,
                    'response_type': 'code',
                    'redirect_uri': OAUTH_REDIRECT_URI,
                    'scope': OAUTH_SCOPES,
                    'code_challenge': challenge,
                    'code_challenge_method': 'S256',
                    'state': verifier,
                })
                auth_url = f"{OAUTH_AUTHORIZE_URL}?{params}"
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'sessionId': session_id, 'authUrl': auth_url}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path == '/api/keys/oauth/complete':
            cl = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(cl).decode()) if cl else {}
            session_id = body.get('sessionId', '')
            raw_code = body.get('code', '')
            try:
                with _pkce_lock:
                    pkce = _pkce_sessions.pop(session_id, None)
                if not pkce:
                    raise ValueError('Invalid or expired session. Please start over.')
                if '#' in raw_code:
                    code, state = raw_code.split('#', 1)
                else:
                    code = raw_code
                    state = pkce['verifier']
                result = _oauth_token_request({
                    'grant_type': 'authorization_code',
                    'client_id': OAUTH_CLIENT_ID,
                    'code': code,
                    'state': state,
                    'redirect_uri': OAUTH_REDIRECT_URI,
                    'code_verifier': pkce['verifier'],
                })
                access_token = result['access_token']
                refresh_token = result['refresh_token']
                expires_in = result.get('expires_in', 3600)
                email = f"claude-account-{secrets.token_hex(4)}"
                creds = _oauth_load_creds()
                creds['accounts'][email] = {
                    'accessToken': access_token,
                    'refreshToken': refresh_token,
                    'expiresAt': time.time() + expires_in,
                    'email': email,
                }
                _oauth_save_creds(creds)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': True, 'email': email}).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path == '/api/keys/oauth/update':
            cl = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(cl).decode()) if cl else {}
            account_id = body.get('accountId', '')
            label = body.get('label', '')
            linked_key = body.get('linkedKey', '')
            try:
                creds = _oauth_load_creds()
                if account_id not in creds['accounts']:
                    raise ValueError('Account not found')
                creds['accounts'][account_id]['label'] = label
                creds['accounts'][account_id]['linkedKey'] = linked_key
                _oauth_save_creds(creds)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': True}).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path == '/api/keys/oauth/remove':
            cl = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(cl).decode()) if cl else {}
            email = body.get('email', '')
            try:
                creds = _oauth_load_creds()
                creds['accounts'].pop(email, None)
                _oauth_save_creds(creds)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': True}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path == '/api/pin':
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length).decode()
            try:
                data = json.loads(body)
                session_key = data.get('sessionKey', '')
                pin_action = data.get('action', '')  # 'pin' or 'unpin'
                
                pinned = load_pinned()
                if pin_action == 'pin':
                    pinned.add(session_key)
                else:
                    pinned.discard(session_key)
                save_pinned(pinned)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
                return
            except:
                self.send_response(400)
                self.end_headers()
                return
        if self.path == '/api/restart-gateway':
            try:
                subprocess.Popen(['systemctl', 'restart', 'openclaw'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status":"restarting"}')
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
                return
        
        if self.path == '/api/send-message':
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length).decode()
            try:
                data = json.loads(body)
                session_id = data.get('sessionId', '')
                message = data.get('message', '')
                if not session_id or not message:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error":"sessionId and message required"}')
                    return
                # Look up session key from session ID
                session_key = None
                try:
                    with open(SESSIONS_FILE) as f:
                        sessions_data = json.load(f)
                    for key, sess in sessions_data.items():
                        if sess.get('sessionId') == session_id:
                            session_key = key
                            break
                except:
                    pass
                if not session_key:
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error":"Session key not found"}')
                    return
                # Fire-and-forget via gateway API (faster than CLI)
                subprocess.Popen(
                    ['node', '--import', 'tsx', '/home/sam/.openclaw/workspace/dashboard/send-message.mjs', session_key, message],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    cwd='/root/openclaw'
                )
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status":"sent"}')
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
                return

        # Cron job toggle endpoint
        if self.path == '/api/cron/toggle':
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length).decode()
            try:
                data = json.loads(body)
                job_id = data.get('jobId', '')
                enabled = data.get('enabled', True)
                result = toggle_cron_job(job_id, enabled)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
                return

        # Cron job run endpoint
        if self.path == '/api/cron/run':
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length).decode()
            try:
                data = json.loads(body)
                job_id = data.get('jobId', '')
                result = run_cron_job(job_id)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
                return

        super().do_POST()
    
    def do_GET(self):
        if self.path.startswith('/session/'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.end_headers()
            with open(os.path.join(DIR, 'session.html'), 'rb') as f:
                self.wfile.write(f.read())
            return

        if self.path == '/keys' or self.path == '/keys/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            with open(os.path.join(DIR, 'keys.html'), 'rb') as f:
                self.wfile.write(f.read())
            return

        if self.path.startswith('/api/keys/oauth/usage'):
            try:
                creds = _oauth_load_creds()
                accounts = creds.get('accounts', {})
                result = {}
                for email, account in accounts.items():
                    refreshed = _oauth_refresh_if_needed(account)
                    if not refreshed:
                        result[email] = {'error': 'refresh_failed', 'message': account.get('refreshError', 'Token refresh failed. Please re-login.')}
                        continue
                    # Save refreshed tokens
                    accounts[email] = refreshed
                    try:
                        usage = _oauth_get_usage(refreshed['accessToken'])
                        result[email] = {'ok': True, 'usage': usage, 'email': email, 'subscriptionType': refreshed.get('subscriptionType', ''), 'label': refreshed.get('label', ''), 'linkedKey': refreshed.get('linkedKey', '')}
                    except urllib.error.HTTPError as e:
                        try:
                            body = json.loads(e.read())
                            msg = body.get('error', {}).get('message', str(e))
                        except:
                            msg = str(e)
                        if e.code == 401:
                            result[email] = {'error': 'auth_failed', 'message': 'Re-login needed'}
                        else:
                            result[email] = {'error': 'api_error', 'message': msg}
                    except Exception as e:
                        result[email] = {'error': 'api_error', 'message': str(e)}
                _oauth_save_creds(creds)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path.startswith('/api/keys/usage'):
            try:
                # Load usage stats from auth-profiles.json
                with open('/home/sam/.openclaw/agents/main/agent/auth-profiles.json') as f:
                    store = json.load(f)
                usage_stats = store.get('usageStats', {})

                # Load config for profile list
                with open('/home/sam/.openclaw/openclaw.json') as f:
                    cfg = json.load(f)
                profiles = cfg.get('auth', {}).get('profiles', {})
                order = cfg.get('auth', {}).get('order', {})

                now = time.time() * 1000
                result = {'keys': {}, 'summary': {}}
                active_count = 0
                total_errors = 0

                for name in profiles:
                    stats = usage_stats.get(name, {})
                    last_used = stats.get('lastUsed', 0)
                    error_count = stats.get('errorCount', 0)
                    last_failure = stats.get('lastFailureAt', 0)
                    last_error = stats.get('lastError', '')

                    # Determine status
                    if last_used == 0 and last_failure == 0:
                        status = 'unused'
                    elif error_count > 0 and last_failure > last_used:
                        status = 'error'
                    elif last_used > 0 and (now - last_used) < 600000:  # 10 min
                        status = 'active'
                    elif last_used > 0:
                        status = 'idle'
                    else:
                        status = 'unused'

                    if status == 'active':
                        active_count += 1
                    total_errors += error_count

                    # Check if enabled
                    provider = profiles[name].get('provider', '')
                    provider_order = order.get(provider, [])
                    enabled = name in provider_order

                    result['keys'][name] = {
                        'lastUsed': last_used,
                        'errorCount': error_count,
                        'lastFailureAt': last_failure,
                        'lastError': last_error,
                        'status': status,
                        'enabled': enabled,
                    }

                # Find last rotation (most recent lastUsed across all keys)
                all_last_used = [s.get('lastUsed', 0) for s in usage_stats.values()]
                last_rotation = max(all_last_used) if all_last_used else 0

                result['summary'] = {
                    'activeKeys': active_count,
                    'totalKeys': len(profiles),
                    'totalErrors': total_errors,
                    'lastRotation': last_rotation,
                    'timestamp': now,
                }

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path.startswith('/api/keys'):
            try:
                with open('/home/sam/.openclaw/openclaw.json') as f:
                    cfg = json.load(f)
                auth = cfg.get('auth', {})
                profiles = auth.get('profiles', {})
                order = auth.get('order', {})
                keys_data = []
                for name, prof in profiles.items():
                    provider = prof.get('provider', '')
                    provider_order = order.get(provider, [])
                    enabled = name in provider_order
                    position = provider_order.index(name) if enabled else -1
                    keys_data.append({
                        'name': name,
                        'provider': provider,
                        'mode': prof.get('mode', ''),
                        'enabled': enabled,
                        'position': position
                    })
                keys_data.sort(key=lambda x: (x['provider'], x['position'] if x['enabled'] else 999, x['name']))
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'keys': keys_data, 'order': order}).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        if self.path.startswith('/data/system.json'):
            data = json.dumps(get_system_info())
            self._send_json_gzipped(data)
            return

        # Cron jobs data endpoint
        if self.path == '/data/cron-jobs.json':
            data = json.dumps(get_cron_jobs())
            self._send_json_gzipped(data)
            return

        # Cron runs data endpoint
        if self.path.startswith('/data/cron-runs/'):
            job_id = self.path.replace('/data/cron-runs/', '')
            data = json.dumps(get_cron_runs(job_id))
            self._send_json_gzipped(data)
            return
        
        if self.path.startswith('/data/transcript/'):
            parsed_url = urlparse(self.path)
            sid = parsed_url.path.split('/data/transcript/')[1]
            tparams = parse_qs(parsed_url.query)
            t_limit = int(tparams.get('limit', [100])[0])
            t_offset = int(tparams.get('offset', [-1])[0])  # -1 means "last N"
            import glob
            patterns = [
                os.path.join(TRANSCRIPTS_DIR, f'{sid}.jsonl'),
                os.path.join(TRANSCRIPTS_DIR, f'{sid}-*.jsonl'),
            ]
            files = []
            for p in patterns:
                files.extend(glob.glob(p))
            
            if not files:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"error":"not found"}')
                return
            
            f = max(files, key=os.path.getmtime)
            entries = []
            try:
                with open(f, 'r') as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            msg = entry.get('message', {})
                            role = msg.get('role', '')
                            model = msg.get('model', '')
                            stop = msg.get('stopReason', '')
                            ts = msg.get('timestamp', entry.get('timestamp', ''))
                            cost = msg.get('usage', {}).get('cost', {}).get('total', 0)
                            tokens_in = msg.get('usage', {}).get('input', 0)
                            tokens_out = msg.get('usage', {}).get('output', 0)
                            cache_read = msg.get('usage', {}).get('cacheRead', 0)
                            
                            content = msg.get('content', [])
                            if isinstance(content, str):
                                content = [{'type': 'text', 'text': content}]
                            
                            parsed = []
                            
                            if role == 'toolResult':
                                tool_call_id = msg.get('toolCallId', '')
                                tool_name = msg.get('toolName', '?')
                                result_text = ''
                                for c in (content if isinstance(content, list) else []):
                                    if c.get('type') == 'text':
                                        result_text = c.get('text', '')[:4000]
                                        break
                                    elif c.get('type') == 'image':
                                        src = c.get('source', {})
                                        url = src.get('url', '') or c.get('url', '') or c.get('image', '')
                                        if url:
                                            result_text = f'[IMAGE: {url}]'
                                            break
                                parsed.append({'type': 'result', 'name': tool_name, 'text': result_text, 'id': tool_call_id})
                            
                            for c in (content if isinstance(content, list) else []):
                                t = c.get('type', '')
                                if role == 'toolResult':
                                    break
                                if t == 'toolCall':
                                    args = c.get('arguments', {})
                                    if isinstance(args, dict):
                                        for k, v in args.items():
                                            if isinstance(v, str) and len(v) > 2000:
                                                args[k] = v[:2000] + '…'
                                    parsed.append({'type': 'tool', 'name': c.get('name','?'), 'args': args, 'id': c.get('id','')})
                                elif t == 'image':
                                    src = c.get('source', {})
                                    url = src.get('url', '') or c.get('url', '') or c.get('image', '')
                                    parsed.append({'type': 'image', 'url': url})
                                elif t == 'text':
                                    txt = c.get('text', '')
                                    if txt.strip():
                                        parsed.append({'type': 'text', 'text': txt[:5000]})
                                elif t == 'thinking':
                                    thinking = c.get('thinking', '')
                                    if thinking:
                                        parsed.append({'type': 'thinking', 'text': thinking[:3000]})
                            
                            if parsed:
                                entries.append({
                                    'role': role, 'model': model, 'stop': stop,
                                    'ts': ts, 'cost': cost,
                                    'tokens': {'in': tokens_in, 'out': tokens_out, 'cache': cache_read},
                                    'content': parsed
                                })
                        except:
                            continue
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
                return
            
            total = len(entries)
            # Pagination: default returns last 100 entries
            if t_offset == -1:
                # Last N entries
                paginated = entries[-t_limit:] if len(entries) > t_limit else entries
                actual_offset = max(0, total - t_limit)
            else:
                paginated = entries[t_offset:t_offset + t_limit]
                actual_offset = t_offset
            
            data = json.dumps({
                'file': os.path.basename(f),
                'count': len(paginated),
                'total': total,
                'offset': actual_offset,
                'hasMore': actual_offset > 0 if t_offset == -1 else (t_offset + t_limit) < total,
                'entries': paginated
            })
            self._send_json_gzipped(data)
            return
        
        if self.path.startswith('/data/sessions.json'):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            since = int(float(params.get('since', [0])[0]))
            
            # Check cache
            with _sessions_cache_lock:
                try:
                    current_mtime = os.path.getmtime(SESSIONS_FILE)
                except:
                    current_mtime = 0
                
                if _sessions_cache['data'] is None or current_mtime != _sessions_cache['mtime']:
                    raw_data = get_sessions_with_activity()
                    _sessions_cache['data'] = raw_data
                    _sessions_cache['mtime'] = current_mtime
                    _sessions_cache['etag'] = hashlib.md5(raw_data.encode()).hexdigest()[:16]
                    _sessions_cache['parsed'] = json.loads(raw_data)
                
                etag = _sessions_cache['etag']
                cached_parsed = _sessions_cache['parsed']
            
            # ETag support
            client_etag = self.headers.get('If-None-Match', '').strip('"')
            if client_etag == etag and not since:
                self.send_response(304)
                self.end_headers()
                return
            
            # If since param, filter to only changed sessions
            if since:
                filtered = [s for s in cached_parsed.get('sessions', []) if s.get('updatedAt', 0) > since]
                response_data = json.dumps({
                    'count': len(filtered),
                    'sessions': filtered,
                    'stats': cached_parsed.get('stats', {}),
                    'timestamp': cached_parsed.get('timestamp', 0),
                    'topicNames': cached_parsed.get('topicNames', {}),
                    'incremental': True
                })
            else:
                response_data = _sessions_cache['data']
            
            self._send_json_gzipped(response_data, etag)
            return
        super().do_GET()
    
    def _send_json_gzipped(self, data, etag=None):
        """Send JSON response with gzip if client supports it and data > 1KB."""
        raw = data.encode('utf-8') if isinstance(data, str) else data
        accept_enc = self.headers.get('Accept-Encoding', '')
        use_gzip = 'gzip' in accept_enc and len(raw) > 1024
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        if etag:
            self.send_header('ETag', f'"{etag}"')
        if use_gzip:
            compressed = gzip.compress(raw, compresslevel=6)
            self.send_header('Content-Encoding', 'gzip')
            self.send_header('Content-Length', str(len(compressed)))
            self.end_headers()
            self.wfile.write(compressed)
        else:
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    def log_message(self, *a): pass

# WebSocket server for real-time updates
async def websocket_handler(websocket, path):
    ws_clients.add(websocket)
    try:
        await websocket.wait_closed()
    finally:
        ws_clients.remove(websocket)

async def broadcast_update(message):
    if ws_clients:
        await asyncio.gather(
            *[ws.send(message) for ws in ws_clients.copy()],
            return_exceptions=True
        )

# File watcher for sessions updates
class SessionsWatcher(FileSystemEventHandler):
    def __init__(self):
        self.last_update = time.time()
    
    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith('sessions.json') or event.src_path.endswith('.jsonl'):
            # Invalidate cache
            with _sessions_cache_lock:
                _sessions_cache['data'] = None
            # Debounce - only update every 2 seconds
            now = time.time()
            if now - self.last_update > 2:
                self.last_update = now
                asyncio.run_coroutine_threadsafe(
                    broadcast_update(json.dumps({'type': 'sessions_updated', 'timestamp': now * 1000})),
                    ws_loop
                )

def start_file_watcher():
    observer = Observer()
    handler = SessionsWatcher()
    observer.schedule(handler, '/home/sam/.openclaw/agents/main/sessions', recursive=True)
    observer.start()
    return observer

def start_websocket_server():
    global ws_loop
    ws_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(ws_loop)
    start_server = websockets.serve(websocket_handler, "localhost", WS_PORT)
    ws_loop.run_until_complete(start_server)
    ws_loop.run_forever()

if __name__ == "__main__":
    # Start file watcher
    observer = start_file_watcher()
    
    # Start WebSocket server in background thread
    ws_thread = threading.Thread(target=start_websocket_server, daemon=True)
    ws_thread.start()
    
    try:
        with ReuseServer(('0.0.0.0', PORT), Handler) as s:
            print(f'Dashboard: http://localhost:{PORT}')
            print(f'WebSocket: ws://localhost:{WS_PORT}')
            s.serve_forever()
    except KeyboardInterrupt:
        observer.stop()
        observer.join()