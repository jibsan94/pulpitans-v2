import os

def search_folder(folder_name, base_route="/home"):
    results = []
    for root, dirs, files in os.walk(base_route):
        if folder_name in dirs:
            full_route = os.path.join(root, folder_name)
            results.append(full_route)
    return results

# Solo se ejecuta si lo llamas directamente con python3 path-finder.py
if __name__ == '__main__':
    routes = search_folder("idas_tool_mkbuild")
    if routes:
        print(f"There are {len(routes)} result(s):")
        for r in routes:
            print(f"  -> {r}")
    else:
        print("No folder(s) were found.")