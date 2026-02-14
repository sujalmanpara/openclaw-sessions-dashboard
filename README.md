# OpenClaw Sessions Dashboard

A real-time web dashboard for monitoring all your OpenClaw sessions — active agents, cron jobs, group chats, and direct conversations.

![Dashboard Screenshot](screenshot.png)

## Features

- **Live session monitoring** — auto-refreshes every 5 seconds
- **Activity feed** — see tool calls (🔧), responses (💬), thinking (🧠) in real-time
- **Session detail panel** — click any session to see the full transcript with color-coded entries
- **Cron job management** — view, enable/disable, and trigger cron jobs
- **Smart filters** — All / Active / Recent / Groups / Crons / Direct / Busy
- **Stats bar** — total sessions, active count, cron jobs, groups at a glance
- **Cost tracking** — per-entry cost displayed in transcripts
- **Dark theme** — easy on the eyes

## Quick Start

### 1. Clone

```bash
git clone https://github.com/sujalmanpara/openclaw-sessions-dashboard.git
cd openclaw-sessions-dashboard
```

### 2. Configure paths

Edit `server.js` and update the paths to match your OpenClaw installation:

```javascript
// Sessions file
'/home/<user>/.openclaw/agents/main/sessions/sessions.json'

// Cron jobs
'/home/<user>/.openclaw/cron/jobs.json'
'/home/<user>/.openclaw/cron/runs/'
```

### 3. Run

```bash
node server.js
```

Open `http://localhost:3847` in your browser.

## Files

| File | Description |
|---|---|
| `server.js` | Node.js HTTP server — serves dashboard + API endpoints |
| `index.html` | Main dashboard — sessions list, activity feed, transcripts |
| `cron.html` | Cron job management — view, toggle, trigger, run history |
| `session.html` | Detailed session view |
| `system.html` | System overview |
| `keys.html` | API keys management |
| `send-message.mjs` | Utility to send messages to sessions |

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `GET /` | GET | Dashboard UI |
| `GET /data/sessions.json` | GET | All sessions with metadata |
| `GET /data/cron-jobs.json` | GET | All cron jobs |
| `GET /data/cron-runs/<jobId>` | GET | Run history for a cron job |
| `POST /api/cron/toggle` | POST | Enable/disable a cron job |
| `POST /api/cron/run` | POST | Trigger a cron job manually |

## Requirements

- Node.js 18+
- A running OpenClaw instance (reads session/cron files directly)

## Customization

- **Port:** Change `PORT = 3847` in `server.js`
- **Refresh rate:** Change `setInterval` in `index.html`

## License

MIT
