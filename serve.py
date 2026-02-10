#!/usr/bin/env python3
import http.server, json, os, socketserver, glob, time

PORT = 3847
DIR = os.path.dirname(os.path.abspath(__file__))
SESSIONS_FILE = '/root/.openclaw/agents/main/sessions/sessions.json'
TRANSCRIPTS_DIR = '/root/.openclaw/agents/main/sessions/'

class ReuseServer(socketserver.TCPServer):
    allow_reuse_address = True
    allow_reuse_port = True

def get_recent_activity(session_id, max_lines=5):
    """Read last few lines of a transcript to get current activity."""
    # Try both patterns
    patterns = [
        os.path.join(TRANSCRIPTS_DIR, f'{session_id}.jsonl'),
        os.path.join(TRANSCRIPTS_DIR, f'{session_id}-*.jsonl'),
    ]
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    if not files:
        return None
    
    # Pick most recently modified
    f = max(files, key=os.path.getmtime)
    
    try:
        # Read last N lines efficiently
        with open(f, 'rb') as fh:
            fh.seek(0, 2)
            size = fh.tell()
            # Read last 10KB
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
                
                # Handle toolResult role
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
                        # Extract brief args
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
        with open('/root/.openclaw/openclaw.json') as f:
            cfg = json.load(f)
        profiles = cfg.get('auth', {}).get('profiles', {})
        order = cfg.get('auth', {}).get('order', {})
        return {'profiles': profiles, 'order': order}
    except:
        return {'profiles': {}, 'order': {}}

def get_sessions_with_activity():
    try:
        with open(SESSIONS_FILE) as f:
            raw = json.load(f)
        
        sessions = []
        now = time.time() * 1000
        
        # Build parent-child map from key structure and spawnedBy field
        # Cron runs: "agent:main:cron:<id>:run:<runId>" → parent "agent:main:cron:<id>"
        # Sub-agents: spawnedBy field → parent session key
        children_map = {}  # parent_key → [child_keys]
        parent_map = {}    # child_key → parent_key
        
        for key, val in raw.items():
            # Cron run relationship
            if ':run:' in key:
                parent_key = key.rsplit(':run:', 1)[0]
                if parent_key in raw:
                    parent_map[key] = parent_key
                    children_map.setdefault(parent_key, []).append(key)
            # Sub-agent relationship
            spawned_by = val.get('spawnedBy', '')
            if spawned_by and spawned_by in raw:
                parent_map[key] = spawned_by
                children_map.setdefault(spawned_by, []).append(key)
        
        for key, s in raw.items():
            session = {'key': key, **s}
            sid = s.get('sessionId', '')
            updated = s.get('updatedAt', 0)
            
            # Add parent/children references
            if key in parent_map:
                session['parentKey'] = parent_map[key]
                parent = raw.get(parent_map[key], {})
                session['parentLabel'] = parent.get('label', '') or parent.get('displayName', '') or parent_map[key]
            if key in children_map:
                child_list = children_map[key]
                # Sort by updatedAt desc, include basic info
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
            
            # Only get activity for sessions active in last 2 hours
            if now - updated < 7200000 and sid:
                activity = get_recent_activity(sid)
                if activity:
                    session['activity'] = activity
            
            sessions.append(session)
        
        auth = get_auth_info()
        return json.dumps({'count': len(sessions), 'sessions': sessions, 'auth': auth})
    except Exception as e:
        return json.dumps({'error': str(e), 'count': 0, 'sessions': []})

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=DIR, **kw)
    
    def do_GET(self):
        if self.path.startswith('/data/transcript/'):
            sid = self.path.split('/data/transcript/')[1].split('?')[0]
            # Find transcript file
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
                            
                            # Handle toolResult role (result at message level)
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
                                    break  # Already handled above
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
            
            data = json.dumps({'file': os.path.basename(f), 'count': len(entries), 'entries': entries})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(data.encode())
            return
        
        if self.path.startswith('/data/sessions.json'):
            data = get_sessions_with_activity()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(data.encode())
            return
        super().do_GET()
    
    def log_message(self, *a): pass

with ReuseServer(('0.0.0.0', PORT), Handler) as s:
    print(f'Dashboard: http://localhost:{PORT}')
    s.serve_forever()
