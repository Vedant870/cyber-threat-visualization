-- 1) Event counts by type
SELECT event_type, COUNT(*) AS total_events
FROM threat_events
GROUP BY event_type
ORDER BY total_events DESC;

-- 2) Event counts by source
SELECT source, COUNT(*) AS total_events
FROM threat_events
GROUP BY source
ORDER BY total_events DESC;

-- 3) Top 3 highest severity events
SELECT event_id, event_type, severity, source, event_time
FROM threat_events
ORDER BY severity DESC, event_time DESC
LIMIT 3;

-- 4) Average severity per event type
SELECT event_type, ROUND(AVG(severity), 2) AS avg_severity
FROM threat_events
GROUP BY event_type
ORDER BY avg_severity DESC;
