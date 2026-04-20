import os
import glob
import time
import config_loader

def load_config():
    return config_loader.load_config()

def get_build_files():
    """Returns all build tar.gz files based on config.conf paths"""
    config = load_config()
    projects_path = config['scanner']['projects_path']
    build_subdir  = config['scanner']['build_subdir']
    build_pattern = config['scanner']['build_pattern']

    pattern = os.path.join(projects_path, '*', build_subdir, build_pattern)
    return glob.glob(pattern)

def get_project_name(filepath):
    """Extracts the project name from the build file path"""
    parts = filepath.split(os.sep)
    # /iDASREPO/PROJECTS/<project>/build/file.tar.gz
    return parts[-3]

def format_size(size_bytes):
    """Converts bytes to human readable format"""
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    elif size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.0f} MB"
    else:
        return f"{size_bytes / 1024:.0f} KB"

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
        size_bytes = os.path.getsize(filepath)
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
        del projects[project]["latest_mtime"]  # clean up internal field

    return {
        "total_builds": len(build_files),
        "total_size": format_size(total_size_bytes),
        "total_size_bytes": total_size_bytes,
        "active_projects": len(projects),
        "latest_build": latest_build_name,
        "projects": projects
    }


# Engineer -> projects mapping
ENGINEER_PROJECTS = {
    "Jibsan Toirac": {
        "username": "jjrosat",
        "projects": ["AVINOR", "iCAS-LVNL", "iSNS-LVNL"]
    },
    "Ismael": {
        "username": "ismael",
        "projects": ["PANSA", "FF-ICE", "ROMATSA"]
    },
    "Sergio": {
        "username": "sergio",
        "projects": ["NAV-CANADA", "NATS"]
    },
    "Daniel": {
        "username": "daniel",
        "projects": ["SKYNEX", "IRTOS", "UTM", "YAKARTA", "SACTA"]
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
        latest_date = ""

        for project_name in info["projects"]:
            # Case-insensitive match
            matched = next(
                (v for k, v in projects_data.items() if k.upper() == project_name.upper()),
                None
            )
            if matched:
                total_builds += matched["total_builds"]
                total_size_bytes += matched["total_size_bytes"]
                if matched["latest_build"] != "--" and matched["latest_build"] > latest_date:
                    latest_date = matched["latest_build"]
                    latest_build = matched["latest_build"]

        result[engineer] = {
            "username": info["username"],
            "projects": info["projects"],
            "total_builds": total_builds,
            "total_size": format_size(total_size_bytes),
            "total_size_bytes": total_size_bytes,
            "latest_build": latest_build
        }

    return result