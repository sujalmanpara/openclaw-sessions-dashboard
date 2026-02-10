#!/usr/bin/env python3
import http.server, json, os, socketserver, glob, time, threading, asyncio, websockets
from datetime import datetime, timedelta
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

PORT = 3847
WS_PORT = 3848
DIR = os.path.dirname(os.path.abspath(__file__))
SESSIONS_FILE = '/root/.openclaw/agents/main/sessions/sessions.json'
TOPIC_NAMES_FILE = os.path.join(DIR, 'topic-names.json')

def load_topic_names():
    try:
        with open(TOPIC_NAMES_FILE) as f:
            return json.load(f)
    except:
        return {}
TRANSCRIPTS_DIR = '/root/.openclaw/agents/main/sessions/'
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
        with open('/root/.openclaw/openclaw.json') as f:
            cfg = json.load(f)
        profiles = cfg.get('auth', {}).get('profiles', {})
        order = cfg.get('auth', {}).get('order', {})
        return {'profiles': profiles, 'order': order}
    except:
        return {'profiles': {}, 'order': {}}

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
            
            # Get activity for recent sessions
            if now - updated < 7200000 and sid:
                activity = get_recent_activity(sid)
                if activity:
                    session['activity'] = activity
            
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

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=DIR, **kw)
    
    def do_POST(self):
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
        super().do_POST()
    
    def do_GET(self):
        if self.path.startswith('/data/transcript/'):
            sid = self.path.split('/data/transcript/')[1].split('?')[0]
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
    observer.schedule(handler, '/root/.openclaw/agents/main/sessions', recursive=True)
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