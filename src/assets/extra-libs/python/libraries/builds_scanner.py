import os
import glob
import time
import math
import config_loader

def get_build_files():
    """Returns all build tar.gz files based on config.conf paths"""
    config = config_loader.load_config()
    projects_path = config['scanner']['projects_path'].rstrip('/')
    build_subdir  = config['scanner']['build_subdir']
    build_pattern = config['scanner']['build_pattern']

    pattern = os.path.join(projects_path, '*', build_subdir, build_pattern)
    files = glob.glob(pattern)
    return files

def get_project_name(filepath):
    """Extracts the project name from the build file path"""
    parts = filepath.split(os.sep)
    # /iDASREPO/PROJECTS/<project>/build/file.tar.gz
    return parts[-3]

def format_size(size_bytes):
    """Converts bytes to human readable format (matches du -h: ceiling rounding)"""
    if size_bytes >= 1_073_741_824:
        val = size_bytes / 1_073_741_824
        if val >= 10:
            return f"{math.ceil(val)} GB"
        else:
            return f"{math.ceil(val * 10) / 10:.1f} GB"
    elif size_bytes >= 1_048_576:
        val = size_bytes / 1_048_576
        if val >= 10:
            return f"{math.ceil(val)} MB"
        else:
            return f"{math.ceil(val * 10) / 10:.1f} MB"
    else:
        return f"{math.ceil(size_bytes / 1024)} KB"

def get_file_date(filepath):
    """Returns the file modification date"""
    mtime = os.path.getmtime(filepath)
    return time.strftime('%Y-%m-%d', time.localtime(mtime))

def scan_builds():
    """
    Main function - scans all builds and returns structured data.
    Returns:
        {
            total_builds: int,
            total_size: str,
            total_size_bytes: int,
            active_projects: int,
            latest_build: str,
            projects: {
                project_name: {
                    builds: [ { name, size, size_bytes, date } ],
                    total_builds: int,
                    total_size: str,
                    total_size_bytes: int,
                    latest_build: str
                }
            }
        }
    """
    build_files = get_build_files()

    projects = {}
    total_size_bytes = 0
    latest_mtime = 0
    latest_build_name = "--"

    for filepath in build_files:
        project = get_project_name(filepath)
        filename = os.path.basename(filepath)
        size_bytes = os.stat(filepath).st_blocks * 512
        date = get_file_date(filepath)
        mtime = os.path.getmtime(filepath)

        total_size_bytes += size_bytes

        # Track latest build globally
        if mtime > latest_mtime:
            latest_mtime = mtime
            latest_build_name = filename

        # Init project if not exists
        if project not in projects:
            projects[project] = {
                "builds": [],
                "total_builds": 0,
                "total_size_bytes": 0,
                "latest_build": "--",
                "latest_mtime": 0
            }

        projects[project]["builds"].append({
            "name": filename,
            "size": format_size(size_bytes),
            "size_bytes": size_bytes,
            "date": date
        })
        projects[project]["total_builds"] += 1
        projects[project]["total_size_bytes"] += size_bytes

        # Track latest build per project
        if mtime > projects[project]["latest_mtime"]:
            projects[project]["latest_mtime"] = mtime
            projects[project]["latest_build"] = filename

    # Sort builds by date descending within each project
    for project in projects:
        projects[project]["builds"].sort(key=lambda x: x["date"], reverse=True)
        projects[project]["total_size"] = format_size(projects[project]["total_size_bytes"])
        # keep latest_mtime for engineer summary comparison

    return {
        "total_builds": len(build_files),
        "total_size": format_size(total_size_bytes),
        "total_size_bytes": total_size_bytes,
        "active_projects": len(projects),
        "latest_build": latest_build_name,
        "projects": projects
    }


# Engineer -> projects mapping
# Each project has 'display' (shown in UI) and 'folder' (real dir name in /iDASREPO/PROJECTS/)
ENGINEER_PROJECTS = {
    "Jibsan Toirac": {
        "username": "jjrosat",
        "projects": [
            {"display": "AVINOR",    "folder": "avinor"},
            {"display": "iCAS-LVNL", "folder": "icas-lvnl"},
            {"display": "iSNS-LVNL", "folder": "isns-lvnl"},
        ]
    },
    "Ismael": {
        "username": "ismael",
        "projects": [
            {"display": "PANSA",   "folder": "pansa"},
            {"display": "FF-ICE",  "folder": "ffice"},
            {"display": "ROMATSA", "folder": "romatsa"},
        ]
    },
    "Sergio": {
        "username": "sergio",
        "projects": [
            {"display": "Nav-Canada", "folder": "navcanada"},
            {"display": "NATS",       "folder": "nats"},
        ]
    },
    "Daniel": {
        "username": "daniel",
        "projects": [
            {"display": "SKYNEX",  "folder": "skynex"},
            {"display": "IRTOS",   "folder": "irtos"},
            {"display": "UTM",     "folder": "utm"},
            {"display": "YAKARTA", "folder": "yakarta"},
            {"display": "SACTA",   "folder": "sacta"},
        ]
    }
}

def get_engineers_summary(projects_data):
    """
    Returns per-engineer stats based on their associated projects.
    """
    result = {}

    for engineer, info in ENGINEER_PROJECTS.items():
        total_builds = 0
        total_size_bytes = 0
        latest_build = "--"
        latest_mtime = 0

        for proj in info["projects"]:
            matched = projects_data.get(proj["folder"])
            if matched:
                total_builds += matched["total_builds"]
                total_size_bytes += matched["total_size_bytes"]
                mtime = matched.get("latest_mtime", 0)
                if mtime > latest_mtime:
                    latest_mtime = mtime
                    latest_build = matched["latest_build"]

        result[engineer] = {
            "username": info["username"],
            "projects": [p["display"] for p in info["projects"]],
            "projects_detail": [{"display": p["display"], "folder": p["folder"]} for p in info["projects"]],
            "total_builds": total_builds,
            "total_size": format_size(total_size_bytes),
            "total_size_bytes": total_size_bytes,
            "latest_build": latest_build
        }

    return result