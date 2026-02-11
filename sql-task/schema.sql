CREATE TABLE threat_events (
    event_id VARCHAR(20) PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity INT NOT NULL,
    source VARCHAR(50) NOT NULL,
    event_time TIMESTAMP NOT NULL,
    detections INT NOT NULL
);

INSERT INTO threat_events (event_id, event_type, severity, source, event_time, detections) VALUES
('EVT-001','malware',7,'endpoint','2026-01-10 10:14:00',3),
('EVT-002','phishing',5,'email','2026-01-10 11:05:00',2),
('EVT-003','ddos',8,'network','2026-01-10 11:20:00',4),
('EVT-004','bruteforce',6,'auth','2026-01-10 12:02:00',3),
('EVT-005','malware',4,'endpoint','2026-01-10 12:22:00',1),
('EVT-006','phishing',5,'email','2026-01-10 13:14:00',2),
('EVT-007','malware',9,'endpoint','2026-01-10 13:55:00',5),
('EVT-008','ddos',7,'network','2026-01-10 14:18:00',4),
('EVT-009','ransomware',9,'endpoint','2026-01-10 14:45:00',6),
('EVT-010','bruteforce',6,'auth','2026-01-10 15:05:00',3),
('EVT-011','phishing',3,'email','2026-01-10 15:35:00',1),
('EVT-012','malware',8,'endpoint','2026-01-10 16:22:00',4);
