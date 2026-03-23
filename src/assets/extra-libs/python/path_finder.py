import os

def buscar_carpeta(nombre_carpeta, ruta_base="/home"):
    resultados = []
    for root, dirs, files in os.walk(ruta_base):
        if nombre_carpeta in dirs:
            ruta_completa = os.path.join(root, nombre_carpeta)
            resultados.append(ruta_completa)
    return resultados

# Solo se ejecuta si lo llamas directamente con python3 path-finder.py
if __name__ == '__main__':
    rutas = buscar_carpeta("idas_tool_mkbuild")
    if rutas:
        print(f"Se encontraron {len(rutas)} resultado(s):")
        for r in rutas:
            print(f"  -> {r}")
    else:
        print("No se encontró ninguna carpeta.")