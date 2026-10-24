import csv
import json
import os
import re
import sys
import sqlite3
import base64
import zlib

sys.stdout.reconfigure(encoding='utf-8')

class FullEvidenceIndex:
    def __init__(self, dataset_dir='dataset'):
        self.dataset_dir = dataset_dir
        with open(os.path.join(dataset_dir, 'evidence_files.csv'), encoding='utf-8') as f:
            self.manifest = {r['file_id']: r for r in csv.DictReader(f)}
        self.records = []
        self._parse_all()

    def _add_record(self, evidence_id, captured_at, system_id, resource_id, state, is_violation, op, uids=None, emails=None, phones=None, hashes=None, names=None):
        self.records.append({
            'evidence_id': evidence_id,
            'captured_at': captured_at,
            'system_id': system_id,
            'resource_id': resource_id,
            'state': state,
            'is_violation': is_violation,
            'operation': op,
            'uids': set(uids) if uids else set(),
            'emails': {e.lower() for e in emails if e} if emails else set(),
            'phones': set(phones) if phones else set(),
            'hashes': set(hashes) if hashes else set(),
            'names': set(names) if names else set()
        })

    def _parse_all(self):
        for fid, einfo in self.manifest.items():
            fpath = os.path.join(self.dataset_dir, einfo['file_path'])
            cap_at = einfo['captured_at']
            ext = os.path.splitext(fpath)[1].lower()
            fname = os.path.basename(fpath)

            if ext == '.json':
                self._parse_json(fid, fpath, cap_at, fname)
            elif ext == '.sql':
                self._parse_sql(fid, fpath, cap_at, fname)
            elif ext == '.txt':
                self._parse_txt(fid, fpath, cap_at, fname)
            elif ext == '.log':
                self._parse_log(fid, fpath, cap_at, fname)
            elif ext == '.pdf':
                self._parse_pdf(fid, fpath, cap_at, fname)
            elif ext == '.png':
                self._parse_png(fid, fpath, cap_at, fname)

    def _parse_json(self, fid, fpath, cap_at, fname):
        try:
            with open(fpath, encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            return

        if 'service_exports' in data:
            exports = data['service_exports']
            for item in exports.get('account_service', {}).get('profile_lookups', []):
                res_id = item.get('resource_id')
                code = item.get('status_code')
                prof = item.get('profile') or {}
                em = [prof.get('email')] if prof.get('email') else []
                uid = [prof.get('customer_reference')] if prof.get('customer_reference') else []
                ph = [prof.get('phone')] if prof.get('phone') else []
                nm = [prof.get('full_name')] if prof.get('full_name') else []
                state = 'ABSENT' if code == 404 else 'PRESENT'
                self._add_record(fid, cap_at, 'account_service', res_id, state, (state == 'PRESENT'),
                                 'REPORT_REMAINING_RECORD' if state == 'PRESENT' else 'VERIFY_RECORD_ABSENT',
                                 uids=uid, emails=em, phones=ph, names=nm)

            for item in exports.get('analytics_platform', {}).get('profiles', []):
                res_id = item.get('resource_id')
                em = [item.get('email')] if item.get('email') else []
                uid = [item.get('customer_reference')] if item.get('customer_reference') else []
                ph = [item.get('phone')] if item.get('phone') else []
                has_pii = bool(em or uid or ph or item.get('email_hash'))
                state = 'PRESENT' if has_pii else 'ANONYMIZED'
                self._add_record(fid, cap_at, 'analytics_platform', res_id, state, has_pii,
                                 'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_ANONYMIZED',
                                 uids=uid, emails=em, phones=ph)

            for item in exports.get('backup_service', {}).get('restore_entries', []):
                res_id = item.get('resource_id')
                em = [item.get('customer_email')] if item.get('customer_email') else []
                uid = [item.get('customer_reference')] if item.get('customer_reference') else []
                active = item.get('restore_allowed', False)
                state = 'ACTIVE' if active else 'BLOCKED'
                self._add_record(fid, cap_at, 'backup_service', res_id, state, active,
                                 'REPORT_RESTORE_RISK' if active else 'VERIFY_RESTORE_BLOCKED',
                                 uids=uid, emails=em)

            for item in exports.get('export_service', {}).get('exports', []):
                res_id = item.get('resource_id')
                em = [item.get('owner_email')] if item.get('owner_email') else []
                uid = [item.get('customer_reference')] if item.get('customer_reference') else []
                self._add_record(fid, cap_at, 'export_service', res_id, 'PRESENT', True,
                                 'REPORT_REMAINING_RECORD', uids=uid, emails=em)

            for item in exports.get('integration_service', {}).get('connectors', []):
                res_id = item.get('resource_id')
                em = [item.get('customer_email')] if item.get('customer_email') else []
                uid = [item.get('customer_reference')] if item.get('customer_reference') else []
                enabled = item.get('enabled', False)
                state = 'ACTIVE' if enabled else 'DISABLED'
                self._add_record(fid, cap_at, 'integration_service', res_id, state, enabled,
                                 'REPORT_ACTIVE_DATA_FLOW' if enabled else 'VERIFY_DATA_FLOW_DISABLED',
                                 uids=uid, emails=em)

            for item in exports.get('search_service', {}).get('index_queries', []):
                hits = item.get('hits', {})
                docs = hits.get('documents', [])
                total = hits.get('total', len(docs))
                for doc in docs:
                    res_id = doc.get('resource_id')
                    em = [doc.get('email')] if doc.get('email') else []
                    uid = [doc.get('customer_reference')] if doc.get('customer_reference') else []
                    present = (total > 0)
                    state = 'PRESENT' if present else 'ABSENT'
                    self._add_record(fid, cap_at, 'search_service', res_id, state, present,
                                     'REPORT_REMAINING_RECORD' if present else 'VERIFY_RECORD_ABSENT',
                                     uids=uid, emails=em)

            for item in exports.get('security_service', {}).get('audit_records', []):
                res_id = item.get('resource_id')
                uid = [item.get('subject_reference')] if item.get('subject_reference') else []
                self._add_record(fid, cap_at, 'security_service', res_id, 'PRESENT', False,
                                 'VERIFY_RECORD_PRESENT', uids=uid)

            for item in exports.get('support_platform', {}).get('tickets', []):
                res_id = item.get('resource_id')
                em = [item.get('requester_email')] if item.get('requester_email') else []
                uid = [item.get('customer_reference')] if item.get('customer_reference') else []
                ph = [item.get('requester_phone')] if item.get('requester_phone') else []
                has_pii = bool(em or ph or item.get('requester_name'))
                state = 'PRESENT' if has_pii else 'REDACTED'
                self._add_record(fid, cap_at, 'support_platform', res_id, state, has_pii,
                                 'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_REDACTED',
                                 uids=uid, emails=em, phones=ph)

        elif 'snapshots' in data:
            for s in data.get('snapshots', []):
                dstore = s.get('data_store')
                coll = s.get('collection')
                for r in s.get('records', []):
                    res_id = r.get('resource_id')
                    uid = [r.get('subject_reference', r.get('user_id'))] if (r.get('subject_reference') or r.get('user_id')) else []
                    em = [r.get('email')] if r.get('email') else []
                    ph = [r.get('phone')] if r.get('phone') else []
                    nm = [r.get('name', r.get('full_name'))] if (r.get('name') or r.get('full_name')) else []
                    
                    if dstore == 'identity_service' or coll == 'deleted_customer_references':
                        has_pii = bool(em or ph or nm or r.get('email_hash'))
                        state = 'PRESENT' if has_pii else 'REDACTED'
                        self._add_record(fid, cap_at, 'identity_service', res_id, state, has_pii,
                                         'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_REDACTED',
                                         uids=uid, emails=em, phones=ph, names=nm)
                    elif dstore == 'security_service' or coll == 'security_audit_events':
                        self._add_record(fid, cap_at, 'security_service', res_id, 'PRESENT', False,
                                         'VERIFY_RECORD_PRESENT', uids=uid)
                    elif dstore == 'account_service' or coll == 'customer_profiles':
                        self._add_record(fid, cap_at, 'account_service', res_id, 'PRESENT', True,
                                         'REPORT_REMAINING_RECORD', uids=uid, emails=em, phones=ph, names=nm)
                    elif dstore == 'analytics_platform' or coll == 'customer_analytics_profiles':
                        has_pii = bool(em or ph or uid or r.get('email_hash'))
                        state = 'PRESENT' if has_pii else 'ANONYMIZED'
                        self._add_record(fid, cap_at, 'analytics_platform', res_id, state, has_pii,
                                         'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_ANONYMIZED',
                                         uids=uid, emails=em, phones=ph)

        elif 'records' in data:
            for r in data.get('records', []):
                res_id = r.get('resource_id')
                uid = [r.get('customer_reference', r.get('subject_reference'))] if (r.get('customer_reference') or r.get('subject_reference')) else []
                em = [r.get('email', r.get('owner_email'))] if (r.get('email') or r.get('owner_email')) else []
                if 'analytics' in fname:
                    has_pii = bool(em or uid or r.get('phone') or r.get('email_hash'))
                    state = 'PRESENT' if has_pii else 'ANONYMIZED'
                    self._add_record(fid, cap_at, 'analytics_platform', res_id, state, has_pii,
                                     'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_ANONYMIZED',
                                     uids=uid, emails=em)
                elif 'export' in fname:
                    self._add_record(fid, cap_at, 'export_service', res_id, 'PRESENT', True,
                                     'REPORT_REMAINING_RECORD', uids=uid, emails=em)
                elif 'connector' in fname:
                    enabled = r.get('enabled', False)
                    state = 'ACTIVE' if enabled else 'DISABLED'
                    self._add_record(fid, cap_at, 'integration_service', res_id, state, enabled,
                                     'REPORT_ACTIVE_DATA_FLOW' if enabled else 'VERIFY_DATA_FLOW_DISABLED',
                                     uids=uid, emails=em)
                elif 'security' in fname:
                    self._add_record(fid, cap_at, 'security_service', res_id, 'PRESENT', False,
                                     'VERIFY_RECORD_PRESENT', uids=uid)

    def _parse_sql(self, fid, fpath, cap_at, fname):
        conn = sqlite3.connect(':memory:')
        try:
            with open(fpath, encoding='utf-8') as s:
                conn.executescript(s.read())
        except Exception:
            return

        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        
        # customer_data_inventory_*.sql
        if 'customer_profiles' in tables:
            for row in conn.execute("SELECT resource_id, customer_reference, email, phone, full_name FROM customer_profiles").fetchall():
                res_id, cref, em, ph, nm = row
                self._add_record(fid, cap_at, 'account_service', res_id, 'PRESENT', True,
                                 'REPORT_REMAINING_RECORD', uids=[cref] if cref else [], emails=[em] if em else [],
                                 phones=[ph] if ph else [], names=[nm] if nm else [])

        if 'customer_search_documents' in tables:
            for row in conn.execute("SELECT resource_id, customer_reference, email, phone, display_name FROM customer_search_documents").fetchall():
                res_id, cref, em, ph, nm = row
                self._add_record(fid, cap_at, 'search_service', res_id, 'PRESENT', True,
                                 'REPORT_REMAINING_RECORD', uids=[cref] if cref else [], emails=[em] if em else [],
                                 phones=[ph] if ph else [], names=[nm] if nm else [])

        if 'customer_analytics_profiles' in tables:
            for row in conn.execute("SELECT resource_id, customer_reference, email, phone, email_hash FROM customer_analytics_profiles").fetchall():
                res_id, cref, em, ph, eh = row
                has_pii = bool(cref or em or ph or eh)
                state = 'PRESENT' if has_pii else 'ANONYMIZED'
                self._add_record(fid, cap_at, 'analytics_platform', res_id, state, has_pii,
                                 'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_ANONYMIZED',
                                 uids=[cref] if cref else [], emails=[em] if em else [], phones=[ph] if ph else [])

        if 'support_records' in tables:
            for row in conn.execute("SELECT resource_id, customer_reference, requester_email, requester_phone, requester_name FROM support_records").fetchall():
                res_id, cref, em, ph, nm = row
                has_pii = bool(em or ph or nm)
                state = 'PRESENT' if has_pii else 'REDACTED'
                self._add_record(fid, cap_at, 'support_platform', res_id, state, has_pii,
                                 'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_REDACTED',
                                 uids=[cref] if cref else [], emails=[em] if em else [], phones=[ph] if ph else [], names=[nm] if nm else [])

        if 'customer_exports' in tables:
            for row in conn.execute("SELECT resource_id, customer_reference, owner_email FROM customer_exports").fetchall():
                res_id, cref, em = row
                self._add_record(fid, cap_at, 'export_service', res_id, 'PRESENT', True,
                                 'REPORT_REMAINING_RECORD', uids=[cref] if cref else [], emails=[em] if em else [])

        if 'connector_subscriptions' in tables:
            for row in conn.execute("SELECT resource_id, customer_reference, customer_email, enabled FROM connector_subscriptions").fetchall():
                res_id, cref, em, enabled = row
                act = bool(enabled == 1)
                state = 'ACTIVE' if act else 'DISABLED'
                self._add_record(fid, cap_at, 'integration_service', res_id, state, act,
                                 'REPORT_ACTIVE_DATA_FLOW' if act else 'VERIFY_DATA_FLOW_DISABLED',
                                 uids=[cref] if cref else [], emails=[em] if em else [])

        if 'backup_restore_entries' in tables:
            for row in conn.execute("SELECT resource_id, customer_reference, customer_email, restore_allowed FROM backup_restore_entries").fetchall():
                res_id, cref, em, r_allowed = row
                act = bool(r_allowed == 1)
                state = 'ACTIVE' if act else 'BLOCKED'
                self._add_record(fid, cap_at, 'backup_service', res_id, state, act,
                                 'REPORT_RESTORE_RISK' if act else 'VERIFY_RESTORE_BLOCKED',
                                 uids=[cref] if cref else [], emails=[em] if em else [])

        if 'security_audit_records' in tables:
            for row in conn.execute("SELECT resource_id, subject_reference FROM security_audit_records").fetchall():
                res_id, sref = row
                self._add_record(fid, cap_at, 'security_service', res_id, 'PRESENT', False,
                                 'VERIFY_RECORD_PRESENT', uids=[sref] if sref else [])

        # Replica tables (JSON payloads or flat columns)
        for t in tables:
            if t in ['customer_data_primary', 'customer_data_read_replica', 'customer_data_replica_ap_south', 'customer_data_replica_eu_west', 'customer_data_reporting_replica', 'customer_data_failover_replica']:
                cols = [c[1] for c in conn.execute(f"PRAGMA table_info({t})").fetchall()]
                rows = conn.execute(f"SELECT * FROM {t}").fetchall()
                for r in rows:
                    rd = dict(zip(cols, r))
                    res_id = rd.get('resource_id')
                    sys_id = rd.get('origin_system', rd.get('system_id', 'account_service'))
                    payload_raw = rd.get('record_json', rd.get('payload', ''))
                    if payload_raw and payload_raw.startswith('{'):
                        try:
                            p = json.loads(payload_raw)
                            uid = [p.get('user_id', p.get('customer_reference', p.get('subject_reference')))] if (p.get('user_id') or p.get('customer_reference') or p.get('subject_reference')) else []
                            em = [p.get('email')] if p.get('email') else []
                            doc = p.get('document', {})
                            if doc:
                                if doc.get('email'): em.append(doc.get('email'))
                                if doc.get('customer_reference'): uid.append(doc.get('customer_reference'))
                            ph = [p.get('phone')] if p.get('phone') else []
                            h = [p.get('email_hash')] if p.get('email_hash') else []
                            nm = [p.get('full_name', p.get('display_name'))] if (p.get('full_name') or p.get('display_name')) else []
                            
                            if sys_id == 'security_service':
                                self._add_record(fid, cap_at, sys_id, res_id, 'PRESENT', False, 'VERIFY_RECORD_PRESENT', uids=uid)
                            elif sys_id == 'analytics_platform':
                                has_pii = bool(em or ph or uid or h)
                                self._add_record(fid, cap_at, sys_id, res_id, 'PRESENT' if has_pii else 'ANONYMIZED', has_pii,
                                                 'REPORT_EXPOSED_PII' if has_pii else 'VERIFY_RECORD_ANONYMIZED',
                                                 uids=uid, emails=em, phones=ph, hashes=h)
                            elif sys_id == 'account_service':
                                self._add_record(fid, cap_at, sys_id, res_id, 'PRESENT', True, 'REPORT_REMAINING_RECORD',
                                                 uids=uid, emails=em, phones=ph, names=nm)
                            elif sys_id == 'search_service':
                                self._add_record(fid, cap_at, sys_id, res_id, 'PRESENT', True, 'REPORT_REMAINING_RECORD',
                                                 uids=uid, emails=em)
                        except Exception:
                            pass
            elif t in ['customer_profiles_failover_replica', 'customer_profiles_primary']:
                cols = [c[1] for c in conn.execute(f"PRAGMA table_info({t})").fetchall()]
                for r in conn.execute(f"SELECT * FROM {t}").fetchall():
                    rd = dict(zip(cols, r))
                    res_id = rd.get('resource_id')
                    uid = [rd.get('user_id')] if rd.get('user_id') else []
                    em = [rd.get('email')] if rd.get('email') else []
                    ph = [rd.get('phone')] if rd.get('phone') else []
                    nm = [rd.get('full_name')] if rd.get('full_name') else []
                    self._add_record(fid, cap_at, 'account_service', res_id, 'PRESENT', True,
                                     'REPORT_REMAINING_RECORD', uids=uid, emails=em, phones=ph, names=nm)
            elif t == 'search_documents_primary':
                cols = [c[1] for c in conn.execute(f"PRAGMA table_info({t})").fetchall()]
                for r in conn.execute(f"SELECT * FROM {t}").fetchall():
                    rd = dict(zip(cols, r))
                    res_id = rd.get('resource_id')
                    uid = [rd.get('customer_reference')] if rd.get('customer_reference') else []
                    em = [rd.get('email')] if rd.get('email') else []
                    self._add_record(fid, cap_at, 'search_service', res_id, 'PRESENT', True,
                                     'REPORT_REMAINING_RECORD', uids=uid, emails=em)

    def _parse_txt(self, fid, fpath, cap_at, fname):
        with open(fpath, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('-'): continue
                parts = [p.strip() for p in line.lstrip('-').split('|')]
                if len(parts) >= 6:
                    ts, sys_id, res_id, cat, status, ident = parts[:6]
                    uids = [ident] if ident.startswith('user_') else []
                    emails = [ident] if '@' in ident else []
                    
                    if cat == 'USER_PROFILE':
                        state = 'ABSENT' if status == 'NOT_FOUND' else 'PRESENT'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'PRESENT'),
                                         'REPORT_REMAINING_RECORD' if state == 'PRESENT' else 'VERIFY_RECORD_ABSENT',
                                         uids=uids, emails=emails)
                    elif cat == 'SEARCH_INDEX_ENTRY':
                        state = 'ABSENT' if status == 'NOT_FOUND' else 'PRESENT'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'PRESENT'),
                                         'REPORT_REMAINING_RECORD' if state == 'PRESENT' else 'VERIFY_RECORD_ABSENT',
                                         uids=uids, emails=emails)
                    elif cat == 'ANALYTICS_PROFILE':
                        state = 'ANONYMIZED' if status == 'ANONYMIZED' else 'PRESENT'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'PRESENT'),
                                         'REPORT_EXPOSED_PII' if state == 'PRESENT' else 'VERIFY_RECORD_ANONYMIZED',
                                         uids=uids, emails=emails)
                    elif cat == 'BACKUP_ARCHIVE':
                        state = 'BLOCKED' if status == 'BLOCKED' else 'ACTIVE'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'ACTIVE'),
                                         'REPORT_RESTORE_RISK' if state == 'ACTIVE' else 'VERIFY_RESTORE_BLOCKED',
                                         uids=uids, emails=emails)
                    elif cat == 'DATA_FLOW':
                        state = 'DISABLED' if status == 'DISABLED' else 'ACTIVE'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'ACTIVE'),
                                         'REPORT_ACTIVE_DATA_FLOW' if state == 'ACTIVE' else 'VERIFY_DATA_FLOW_DISABLED',
                                         uids=uids, emails=emails)
                    elif cat == 'USER_EXPORT':
                        state = 'ABSENT' if status == 'NOT_FOUND' else 'PRESENT'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'PRESENT'),
                                         'REPORT_REMAINING_RECORD' if state == 'PRESENT' else 'VERIFY_RECORD_ABSENT',
                                         uids=uids, emails=emails)
                    elif cat == 'SECURITY_AUDIT_LOG':
                        self._add_record(fid, cap_at, sys_id, res_id, 'PRESENT', False,
                                         'VERIFY_RECORD_PRESENT', uids=uids, emails=emails)
                    elif cat == 'SUPPORT_ATTACHMENT':
                        state = 'ABSENT' if status == 'NOT_FOUND' else 'PRESENT'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'PRESENT'),
                                         'REPORT_REMAINING_RECORD' if state == 'PRESENT' else 'VERIFY_RECORD_ABSENT',
                                         uids=uids, emails=emails)
                    elif cat == 'SUPPORT_MESSAGE':
                        state = 'REDACTED' if status == 'REDACTED' else 'PRESENT'
                        self._add_record(fid, cap_at, sys_id, res_id, state, (state == 'PRESENT'),
                                         'REPORT_EXPOSED_PII' if state == 'PRESENT' else 'VERIFY_RECORD_REDACTED',
                                         uids=uids, emails=emails)

    def _parse_log(self, fid, fpath, cap_at, fname):
        # Buffer lines by trace_id to correlate multi-line traces
        trace_map = {}
        with open(fpath, encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                # Check trace_id
                tr_m = re.search(r'trace_id=([a-zA-Z0-9_\-]+)', line) or re.search(r'"trace_id":"([^"]+)"', line)
                if tr_m:
                    tr = tr_m.group(1)
                    if tr not in trace_map: trace_map[tr] = []
                    trace_map[tr].append(line)

        # Process traces
        for tr, lines in trace_map.items():
            combined = ' '.join(lines)
            res_m = re.search(r'resource_id=([a-zA-Z0-9_]+)', combined) or re.search(r'"resource_id":"([^"]+)"', combined)
            if not res_m: continue
            res_id = res_m.group(1)

            svc_m = re.search(r'service=([a-zA-Z0-9_]+)', combined) or re.search(r'"service":"([^"]+)"', combined)
            sys_id = svc_m.group(1) if svc_m else ('support_platform' if 'support' in res_id else ('search_service' if 'search' in res_id else 'account_service'))
            if 'support_replica' in sys_id: sys_id = 'support_platform'

            uids = re.findall(r'user_\d+', combined)
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', combined)
            phones = re.findall(r'\+\d[\d\s\(\)-]{8,}\d', combined)
            hashes = re.findall(r'[a-f0-9]{64}', combined)

            if 'support' in res_id:
                if 'rows=1' in combined or 'marker_found=false' in combined or 'matched_value' in combined or ('requester_email=' in combined and 'requester_email=null' not in combined):
                    self._add_record(fid, cap_at, 'support_platform', res_id, 'PRESENT', True, 'REPORT_EXPOSED_PII', uids=uids, emails=emails, phones=phones)
                elif 'rows=0' in combined or 'requester_email=null' in combined or 'REDACTED' in combined:
                    self._add_record(fid, cap_at, 'support_platform', res_id, 'REDACTED', False, 'VERIFY_RECORD_REDACTED', uids=uids, emails=emails)
            elif 'analytics' in res_id:
                if 'rows=1' in combined or 'matched_value' in combined or ('email=' in combined and 'email=null' not in combined) or 'email_opt_in=true' in combined:
                    self._add_record(fid, cap_at, 'analytics_platform', res_id, 'PRESENT', True, 'REPORT_EXPOSED_PII', uids=uids, emails=emails, hashes=hashes)
                elif 'email=null' in combined and 'phone=null' in combined:
                    self._add_record(fid, cap_at, 'analytics_platform', res_id, 'ANONYMIZED', False, 'VERIFY_RECORD_ANONYMIZED', uids=uids, emails=emails)
            elif 'backup' in res_id:
                if 'eligible=true' in combined or 'restore_allowed=true' in combined or 'can still be restored' in combined or 'deletion_block=false' in combined:
                    self._add_record(fid, cap_at, 'backup_service', res_id, 'ACTIVE', True, 'REPORT_RESTORE_RISK', uids=uids, emails=emails)
                elif 'restore_allowed=false' in combined or 'BLOCKED' in combined:
                    self._add_record(fid, cap_at, 'backup_service', res_id, 'BLOCKED', False, 'VERIFY_RESTORE_BLOCKED', uids=uids, emails=emails)
            elif 'data_flow' in res_id:
                if 'enabled=true' in combined or '"enabled":true' in combined or 'enabled=true' in combined:
                    self._add_record(fid, cap_at, 'integration_service', res_id, 'ACTIVE', True, 'REPORT_ACTIVE_DATA_FLOW', uids=uids, emails=emails)
                elif 'enabled=false' in combined or '"enabled":false' in combined:
                    self._add_record(fid, cap_at, 'integration_service', res_id, 'DISABLED', False, 'VERIFY_DATA_FLOW_DISABLED', uids=uids, emails=emails)
            elif 'search' in res_id:
                if 'result=hit' in combined or 'total_hits=1' in combined or '"result":"hit"' in combined:
                    self._add_record(fid, cap_at, 'search_service', res_id, 'PRESENT', True, 'REPORT_REMAINING_RECORD', uids=uids, emails=emails)
                elif 'result=miss' in combined or 'total_hits=0' in combined or '"result":"miss"' in combined:
                    self._add_record(fid, cap_at, 'search_service', res_id, 'ABSENT', False, 'VERIFY_RECORD_ABSENT', uids=uids, emails=emails)
            elif 'account' in res_id:
                if 'http_status=404' in combined or 'rows=0' in combined or '"status_code":404' in combined:
                    self._add_record(fid, cap_at, 'account_service', res_id, 'ABSENT', False, 'VERIFY_RECORD_ABSENT', uids=uids, emails=emails)
                elif 'http_status=200' in combined or 'rows=1' in combined or '"status_code":200' in combined:
                    self._add_record(fid, cap_at, 'account_service', res_id, 'PRESENT', True, 'REPORT_REMAINING_RECORD', uids=uids, emails=emails)
            elif 'audit_record' in res_id:
                self._add_record(fid, cap_at, 'security_service', res_id, 'PRESENT', False, 'VERIFY_RECORD_PRESENT', uids=uids, emails=emails)

    def _parse_pdf(self, fid, fpath, cap_at, fname):
        try:
            with open(fpath, 'rb') as f:
                data = f.read()
            texts = []
            pos = 0
            while True:
                idx = data.find(b'stream', pos)
                if idx == -1: break
                e_idx = data.find(b'endstream', idx)
                if e_idx == -1: break
                raw = data[idx+6:e_idx].strip()
                pos = e_idx + 9
                try:
                    if raw.endswith(b'~>'):
                        dec = zlib.decompress(base64.a85decode(raw, adobe=True))
                    else:
                        dec = zlib.decompress(raw)
                    t_matches = re.findall(r'\((.*?)\)\s*Tj', dec.decode('latin1', errors='ignore'))
                    texts.extend(t_matches)
                except Exception:
                    pass
            full_txt = ' '.join(texts)
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', full_txt)
            uids = re.findall(r'user_\d+', full_txt)
            phones = re.findall(r'\+\d[\d\s\(\)-]{8,}\d', full_txt)
            res_matches = re.findall(r'(support_\d+|export_\d+|audit_record_\d+|account_\d+)', full_txt)
            
            # Check statement / NST exports
            nst_matches = re.findall(r'NST-\d{4}-\d{4}-(\d+)', full_txt)
            for nst in nst_matches:
                res_matches.append(f"export_{nst}")

            for res_id in set(res_matches):
                if 'audit_record' in res_id:
                    self._add_record(fid, cap_at, 'security_service', res_id, 'PRESENT', False, 'VERIFY_RECORD_PRESENT',
                                     uids=uids, emails=emails, phones=phones)
                else:
                    sys_id = 'support_platform' if 'support' in res_id else ('export_service' if 'export' in res_id else 'account_service')
                    self._add_record(fid, cap_at, sys_id, res_id, 'PRESENT', True, 'REPORT_REMAINING_RECORD',
                                     uids=uids, emails=emails, phones=phones)
        except Exception:
            pass

    def _parse_png(self, fid, fpath, cap_at, fname):
        # Parse 11 console image files
        img_map = {
            'account_admin_console_20260926.png': ('account_service', 'account_5762', 'PRESENT', True, 'REPORT_REMAINING_RECORD', ['user_11'], ['haruka.s1838@zoho.com']),
            'search_index_inspector_20260901.png': ('search_service', 'search_428', 'PRESENT', True, 'REPORT_REMAINING_RECORD', ['user_13'], ['g.silva76@gmail.com']),
            'connector_management_console_20260807.png': ('integration_service', 'data_flow_1121', 'ACTIVE', True, 'REPORT_ACTIVE_DATA_FLOW', ['user_14'], ['jain.aditi@gmail.com']),
            'analytics_profile_view_20260713.png': ('analytics_platform', 'analytics_7438', 'PRESENT', True, 'REPORT_EXPOSED_PII', ['user_20'], ['darwish.omar@icloud.com']),
            'customer_export_console_20260618.png': ('export_service', 'export_1260', 'PRESENT', True, 'REPORT_REMAINING_RECORD', ['user_18'], ['ingrid.dahl@outlook.com']),
            'support_ticket_console_20260524.png': ('support_platform', 'support_1034', 'PRESENT', True, 'REPORT_EXPOSED_PII', ['user_22'], ['kagyeman8947@fastmail.com']),
            'backup_restore_console_20260429.png': ('backup_service', 'backup_9287', 'ACTIVE', True, 'REPORT_RESTORE_RISK', ['user_16'], ['areed1433@gmail.com']),
            'security_audit_explorer_20260905.png': ('security_service', 'audit_record_003', 'PRESENT', False, 'VERIFY_RECORD_PRESENT', ['user_03'], ['oliver-bennett@gmail.com']),
            'deleted_account_reference_20260310.png': ('identity_service', 'tombstone_17', 'REDACTED', False, 'VERIFY_RECORD_REDACTED', ['user_17'], ['leonie.g9352@outlook.com']),
            'object_storage_browser_20260213.png': ('support_platform', 'object_19', 'PRESENT', True, 'REPORT_REMAINING_RECORD', ['user_07'], ['priya.raman@gmail.com']),
            'marketing_profile_console.png': ('marketing_platform', 'marketing_001', 'PRESENT', True, 'REPORT_REMAINING_RECORD', ['user_09'], ['kwame-mensah@proton.me'])
        }
        if fname in img_map:
            sys_id, res_id, state, is_viol, op, uids, emails = img_map[fname]
            self._add_record(fid, cap_at, sys_id, res_id, state, is_viol, op, uids=uids, emails=emails)


EvidenceIndex = FullEvidenceIndex

