import os
import subprocess
import re

def get_repo_name(repo_url):
    """Extracts the repo name from the URL. Eg: pulpitans-v2 from the URL"""
    name = repo_url.rstrip('/').split('/')[-1]
    if name.endswith('.git'):
        name = name[:-4]
    return name

def get_repo_path(config):
    """Builds the full path where the repo will be cloned"""
    repo_dir  = config.get('system', 'repo_dir')
    repo_url  = config.get('system', 'repo_url')
    repo_name = get_repo_name(repo_url)
    return os.path.join(repo_dir, repo_name)

def ensure_dirs(path):
    """Creates the directory if it doesn't exist"""
    if not os.path.exists(path):
        os.makedirs(path)

def clone_repo(repo_url, repo_path, username, password):
    """Clones the repo with credentials embedded in the URL"""
    # Embed credentials in URL: https://user:pass@github.com/...
    url_with_creds = repo_url.replace('https://', f'https://{username}:{password}@')

    ensure_dirs(os.path.dirname(repo_path))

    result = subprocess.run(
        ['git', 'clone', url_with_creds, repo_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return {
        "success": result.returncode == 0,
        "output": result.stdout.decode('utf-8'),
        "error":  result.stderr.decode('utf-8').replace(password, '***')  # hide password in logs
    }

def update_repo(repo_path):
    """Runs git pull in the repo directory"""
    if not os.path.exists(repo_path):
        return {"success": False, "error": "Repo not found. Please download it first."}

    result = subprocess.run(
        ['git', '-C', repo_path, 'pull'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return {
        "success": result.returncode == 0,
        "output": result.stdout.decode('utf-8'),
        "error":  result.stderr.decode('utf-8')
    }

def get_branches(repo_path):
    """Returns a list of all branches in the repo"""
    if not os.path.exists(repo_path):
        return {"success": False, "branches": [], "error": "Repo not found. Please download it first."}

    result = subprocess.run(
        ['git', '-C', repo_path, 'branch', '-a'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        return {"success": False, "branches": [], "error": result.stderr.decode('utf-8')}

    branches = []
    for line in result.stdout.decode('utf-8').splitlines():
        branch = line.strip().replace('* ', '')
        if '->' not in branch:  # skip HEAD -> origin/main lines
            branch = branch.replace('remotes/origin/', '')
            if branch not in branches:
                branches.append(branch)

    return {"success": True, "branches": branches, "error": ""}

def get_commits(repo_path, branch):
    """Returns the last 50 commits of a branch"""
    if not os.path.exists(repo_path):
        return {"success": False, "commits": [], "error": "Repo not found. Please download it first."}

    # Try branch as-is, then with origin/ prefix for remote-only branches
    for ref in [branch, f'origin/{branch}']:
        result = subprocess.run(
            ['git', '-C', repo_path, 'log', ref, '--pretty=format:%H|%s|%ad', '--date=short', '-50'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.returncode == 0:
            break

    if result.returncode != 0:
        return {"success": False, "commits": [], "error": result.stderr.decode('utf-8')}

    commits = []
    for line in result.stdout.decode('utf-8').splitlines():
        parts = line.split('|')
        if len(parts) == 3:
            commits.append({
                "hash":    parts[0],
                "message": parts[1],
                "date":    parts[2]
            })

    return {"success": True, "commits": commits, "error": ""}

def get_tags(repo_path):
    """Returns a list of all tags in the repo, newest first"""
    if not os.path.exists(repo_path):
        return {"success": False, "tags": [], "error": "Repo not found. Please download it first."}

    result = subprocess.run(
        ['git', '-C', repo_path, 'tag', '--sort=-version:refname'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        return {"success": False, "tags": [], "error": result.stderr.decode('utf-8')}

    tags = [t.strip() for t in result.stdout.decode('utf-8').splitlines() if t.strip()]
    return {"success": True, "tags": tags, "error": ""}

def apply_tag(repo_path, tag_name, commit_hash):
    """Applies a tag to a specific commit and pushes it to remote"""
    if not os.path.exists(repo_path):
        return {"success": False, "error": "Repo not found. Please download it first."}

    # Create the tag locally
    result = subprocess.run(
        ['git', '-C', repo_path, 'tag', tag_name, commit_hash],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        return {
            "success": False,
            "error": result.stderr.decode('utf-8')
        }

    # Push the tag to remote
    push_result = subprocess.run(
        ['git', '-C', repo_path, 'push', 'origin', tag_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return {
        "success": push_result.returncode == 0,
        "output": push_result.stdout.decode('utf-8'),
        "error":  push_result.stderr.decode('utf-8')
    }