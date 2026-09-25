// Single HTTP client for the dashboard. Every request goes through API_BASE so
// the same build works in dev (Vite proxies /api -> http://127.0.0.1:8001) and
// in production (VITE_API_URL points at the deployed backend).
const PROD_API = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
export const API_BASE = PROD_API || '/api';

// Optional: sent as X-API-Key when the backend runs with API_KEY set. Anything
// in a browser bundle is public, so this only deters drive-by scripts; see the
// README's security notes.
const API_KEY = import.meta.env.VITE_API_KEY || '';

const withKey = (headers = {}) => (API_KEY ? { ...headers, 'X-API-Key': API_KEY } : headers);

async function request(path, { method = 'GET', body, headers } = {}) {
  const init = { method, headers: withKey(headers) };
  if (body instanceof FormData) {
    init.body = body;
  } else if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = 'application/json';
  }
  const response = await fetch(`${API_BASE}${path}`, init);
  const isJson = (response.headers.get('content-type') || '').includes('application/json');
  const data = isJson ? await response.json() : await response.text();
  if (!response.ok) {
    // FastAPI puts messages in `detail` (a string, or a list for 422s).
    const detail = isJson ? data.detail : data;
    const message = Array.isArray(detail)
      ? detail.map((d) => d.msg.replace(/^Value error, /, '')).join('; ')
      : detail || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return data;
}

export const fetchAlerts = ({ riskLevel = null, limit = 50, offset = 0 } = {}) => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (riskLevel) params.set('risk_level', riskLevel);
  return request(`/alerts?${params}`);
};

export const fetchTraffic = (limit = 100) => request(`/traffic?limit=${limit}`);
export const fetchStats = () => request('/stats');
export const fetchModelInfo = () => request('/model');
export const fetchBlocked = () => request('/blocked');

export const analyzeQuery = (query, sourceIp) =>
  request('/analyze', { method: 'POST', body: { query, source_ip: sourceIp } });

export const uploadDataset = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return request('/upload', { method: 'POST', body: formData });
};

export const trainModel = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return request('/train', { method: 'POST', body: formData });
};

export const archiveCase = () => request('/archive', { method: 'POST' });
export const blockIP = (logId) => request(`/alerts/${logId}/block`, { method: 'POST' });
export const markBenign = (logId) => request(`/alerts/${logId}/feedback`, { method: 'POST' });
export const unblockEntity = (target) =>
  request(`/unblock/${encodeURIComponent(target)}`, { method: 'POST' });
export const fetchIncidentReport = (logId) => request(`/alerts/${logId}/report`);

// Download URLs (opened directly by the browser, so no custom headers).
export const getExportCsvUrl = (riskLevel = null) =>
  `${API_BASE}/export/alerts.csv${riskLevel ? `?risk_level=${encodeURIComponent(riskLevel)}` : ''}`;
export const getAuditPdfUrl = () => `${API_BASE}/export/pdf`;
export const getAlertPdfUrl = (logId) => `${API_BASE}/alerts/${logId}/pdf`;

/**
 * Subscribe to the Server-Sent Events feed. EventSource reconnects on its own;
 * onError fires on every drop so the UI can show a "reconnecting" state.
 */
export const connectSSE = (onMessage, onOpen, onError) => {
  const eventSource = new EventSource(`${API_BASE}/stream`);
  eventSource.onopen = () => onOpen?.();
  eventSource.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch (e) {
      console.error('SSE parse error:', e);
    }
  };
  eventSource.onerror = (err) => onError?.(err);
  return eventSource;
};
