#!/usr/bin/env python3
"""Pulpitans background delivery worker.
Usage: delivery_worker.py <job_json_path>

Reads a delivery job JSON file, performs SCP to each listed server,
and updates the JSON file with per-server results and final status.
This process is spawned by server.py and tracked by PID.
"""
import sys
import json
import os
import subprocess


def _save(job_file, job):
    """Atomically write job JSON (write to .tmp then rename)."""
    tmp = job_file + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(job, f, indent=2)
    os.replace(tmp, job_file)


def main():
    if len(sys.argv) < 2:
        print('Usage: delivery_worker.py <job_json_path>', file=sys.stderr)
        sys.exit(1)

    job_file = sys.argv[1]
    try:
        with open(job_file, 'r') as f:
            job = json.load(f)
    except Exception as e:
        print('Failed to read job file: %s' % e, file=sys.stderr)
        sys.exit(1)

    local_path = job['local_path']
    dest_path  = job['dest_path'].rstrip('/')
    servers    = job['servers']   # list of {id, label, ip, ssh_user, ssh_password}

    results = []
    job['status'] = 'running'
    _save(job_file, job)

    scp_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=15']

    for srv in servers:
        ip       = srv['ip']
        ssh_user = srv['ssh_user']
        ssh_pass = (srv.get('ssh_password') or '').strip()
        dest     = '%s@%s:%s/' % (ssh_user, ip, dest_path)

        try:
            if ssh_pass:
                try:
                    proc = subprocess.run(
                        ['sshpass', '-p', ssh_pass, 'scp'] + scp_opts + [local_path, dest],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300
                    )
                except FileNotFoundError:
                    # sshpass not installed — fall back to key-based
                    proc = subprocess.run(
                        ['scp', '-o', 'BatchMode=yes'] + scp_opts + [local_path, dest],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300
                    )
            else:
                proc = subprocess.run(
                    ['scp', '-o', 'BatchMode=yes'] + scp_opts + [local_path, dest],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300
                )

            if proc.returncode == 0:
                results.append({'server': srv['label'], 'ip': ip, 'success': True})
            else:
                err = (proc.stderr.decode('utf-8', errors='replace') or '').strip()
                results.append({
                    'server': srv['label'], 'ip': ip, 'success': False,
                    'error': err or 'SCP exited with code %d' % proc.returncode
                })

        except subprocess.TimeoutExpired:
            results.append({
                'server': srv['label'], 'ip': ip, 'success': False,
                'error': 'Timed out after 300 seconds.'
            })
        except Exception as exc:
            results.append({
                'server': srv['label'], 'ip': ip, 'success': False,
                'error': str(exc)
            })

        # Write interim results after each server so the UI can show progress
        job['results'] = results
        _save(job_file, job)

    all_ok = all(r['success'] for r in results)
    job['status'] = 'done' if all_ok else 'failed'
    job['results'] = results
    _save(job_file, job)


if __name__ == '__main__':
    main()
