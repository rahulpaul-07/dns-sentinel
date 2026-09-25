// Backend timestamps are ISO-8601 UTC with a trailing "Z"; render them in the
// analyst's local time zone. Returns "--:--:--" for missing/invalid input
// instead of throwing inside a render.
export const formatTime = (iso) => {
  const d = iso ? new Date(iso) : null;
  return d && !Number.isNaN(d.getTime())
    ? d.toLocaleTimeString('en-GB', { hour12: false })
    : '--:--:--';
};

export const formatDateTime = (iso) => {
  const d = iso ? new Date(iso) : null;
  return d && !Number.isNaN(d.getTime())
    ? d.toLocaleString('en-GB', { hour12: false })
    : 'N/A';
};

export const formatScore = (value, digits = 1) =>
  typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : '-';
