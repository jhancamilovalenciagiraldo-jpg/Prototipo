"""Menú principal y modo por línea de comandos."""

import argparse
import ipaddress
import logging
import os
import subprocess
import sys
from logging.handlers import RotatingFileHandler

from detector_red import (__version__, almacenamiento, config, escaner, fabricantes,
                          inventario as inv, mantenimiento, servicio)

LINEA = "=" * 88
registro = logging.getLogger("detector_red")

AVISO = """
 AVISO DE USO Y PRIVACIDAD
 Este programa registra la IP, la MAC y el nombre de los equipos de la red.
 - Úselo solo en redes que usted administra o con autorización de quien las
   administra.
 - En una empresa o institución, una MAC o un nombre como "iPhone-de-Ana"
   puede asociarse a una persona: es un dato personal según la Ley 1581 de
   2012 (Colombia). Informe a los usuarios y obtenga la autorización que
   corresponda. En uso exclusivamente personal o doméstico esa ley no aplica.
 - Los datos se guardan solo en este equipo; el programa no envía nada a
   internet (salvo si usted pide actualizar la lista de fabricantes).
"""


cargar_todo = servicio.cargar_todo
guardar_todo = servicio.guardar_todo


def pedir(texto, defecto=None):
    try:
        valor = input(texto).strip()
    except EOFError:
        return defecto
    return valor if valor else defecto


def confirmar(texto):
    return (pedir(f"{texto} (s/n): ", "n") or "n").lower().startswith("s")


def pedir_entero(texto, defecto):
    valor = pedir(f"{texto} [{defecto}]: ")
    try:
        return int(valor) if valor is not None else defecto
    except ValueError:
        print(" Número no válido, se deja el valor actual.")
        return defecto


def escanear_y_actualizar(cfg, perfil_forzado=None, red_forzada=None):
    """Escanea mostrando el progreso en consola. Devuelve el resultado o None."""
    print()
    r = servicio.escanear(cfg, perfil_forzado, red_forzada, mostrar=lambda t: print(f" {t}"))
    if not r["ok"]:
        print(f" ❌ {r['error']}")
        return None
    resumen, limpieza = r["resumen"], r["limpieza"]
    print(f"\n{LINEA}")
    print(f" ✅ {r['activos']} dispositivos activos en {r['duracion']} s")
    print(f"    Nuevos: {resumen['nuevos']} | Volvieron: {resumen['reconectados']} | "
          f"Se fueron: {resumen['desconectados']} | Cambiaron de IP: {resumen['cambios_ip']}"
          f" | Cambiaron de MAC: {resumen['cambios_mac']}")
    if limpieza and any(limpieza.values()):
        print(f"    Limpieza: {limpieza['eventos_vencidos'] + limpieza['eventos_recortados']} "
              f"eventos viejos borrados, {limpieza['bajas']} dispositivos dados de baja")
    for alerta in resumen["alertas"]:
        print(f"    🚨 {alerta}")
    if r["sugerencia"]:
        print(f"    💡 La 2.ª ronda encontró {r['rondas'][1]} equipos que la 1.ª no vio: su red pierde "
              f"respuestas. Pruebe el perfil '{r['sugerencia']}' en Configuración.")
    if r.get("aviso_firewall"):
        print("    🧱 Ningún equipo respondió a mDNS ni SSDP: puede ser el Firewall de Windows.")
        print("       Ejecute como administrador:  DetectorRed.exe --configurar-firewall")
    if not r["fabricantes_disponible"]:
        print("    ℹ️ Para ver fabricantes, descargue la lista oficial: Configuración → opción F")
    print(LINEA)
    return r


def mostrar_inventario(inventario):
    if not inventario:
        print("\n El inventario está vacío. Use la opción 1 para escanear.")
        return
    print(f"\n{LINEA}")
    print(f" {'':2}{'NOMBRE':<22}{'IP':<16}{'MAC':<19}{'TIPO / FABRICANTE':<19}{'ÚLTIMA VEZ':<11}")
    print(LINEA)
    for d in inv.ordenar(inventario):
        marca = "🟢" if d["estado"] == inv.ACTIVO else "⚪"
        extras = ("🔒" if d["protegido"] else "") + ("*" if d["mac_aleatoria"] else "") \
            + ("+" if d.get("ips_extra") else "")
        tipo = d.get("tipo") or d.get("fabricante") or ""
        print(f" {marca} {d['nombre'][:20]:<21}{d['ip']:<16}{(d['mac'] or '¿desconocida?'):<19}"
              f"{tipo[:18]:<19}{d['ultima_vez'][:10]:<11}{extras}")
    activos, inactivos = inv.contar_estados(inventario)
    print(LINEA)
    print(f" Total {len(inventario)}  |  🟢 activos {activos}  |  ⚪ inactivos {inactivos}")
    print(" 🔒 protegido   * MAC aleatoria (celular con 'dirección privada')   + responde por varias IPs")


def mostrar_dispositivo(d):
    print(f"\n {d['nombre']}")
    filas = [("IP", d["ip"]), ("MAC", d["mac"]), ("Nombre de red", d.get("hostname")),
             ("Tipo (probable)", d.get("tipo")), ("Fabricante", d.get("fabricante")),
             ("Estado", d["estado"]), ("Visto por 1.ª vez", d["primera_vez"]),
             ("Visto por última vez", d["ultima_vez"]), ("Red", d.get("red")),
             ("Servicios anunciados", ", ".join(d.get("servicios") or [])),
             ("IPs adicionales", ", ".join(d.get("ips_extra") or [])),
             ("MACs anteriores", ", ".join(d.get("macs_anteriores") or [])),
             ("MAC aleatoria", "sí" if d["mac_aleatoria"] else "no"),
             ("Protegido", "sí" if d["protegido"] else "no")]
    for etiqueta, valor in filas:
        print(f"   {etiqueta:<22}: {valor or '-'}")


def agregar_manual():
    print("\n NUEVO DISPOSITIVO (manual)")
    nombre = pedir(" Nombre: ")
    if not nombre:
        return
    ip = pedir(" IP: ", "")
    while not inv.validar_ip(ip):
        ip = pedir(" IP no válida (ej. 192.168.1.20). IP: ", "")
        if ip == "":
            return
    mac = pedir(" MAC (Enter si no la sabe): ", "")
    while mac and not inv.validar_mac(mac):
        mac = pedir(" MAC no válida (ej. 00:1A:2B:3C:4D:5E). MAC: ", "")
    with almacenamiento.bloqueo():
        inventario, historial = cargar_todo()
        ok, mensaje = inv.agregar_manual(inventario, historial, nombre, ip, mac)
        if ok:
            guardar_todo(inventario, historial)
    print(f" {'✅' if ok else '⚠️'} {mensaje}")


def buscar():
    inventario, _ = cargar_todo()
    d = inv.buscar(inventario, pedir("\n MAC, IP o nombre a buscar: ", ""))
    if d:
        mostrar_dispositivo(d)
    else:
        print(" ❌ Dispositivo no encontrado.")


def renombrar():
    texto = pedir("\n MAC, IP o nombre del dispositivo: ", "")
    d = inv.buscar(cargar_todo()[0], texto)
    if not d:
        print(" ❌ Dispositivo no encontrado.")
        return
    nuevo = escaner.limpiar_texto(pedir(f" Nuevo nombre para '{d['nombre']}': "), 60)
    if not nuevo:
        return
    with almacenamiento.bloqueo():
        inventario, historial = cargar_todo()
        d = inv.buscar(inventario, texto)
        if d:
            inv.registrar_evento(historial, "renombrado", d, f"{d['nombre']} -> {nuevo}")
            d["nombre"], d["nombre_auto"] = nuevo, False
            guardar_todo(inventario, historial)
            print(" ✅ Renombrado.")


def ver_historial(cantidad=25):
    historial = almacenamiento.cargar_historial()
    print(f"\n HISTORIAL (últimos {min(cantidad, len(historial))} de {len(historial)} eventos)")
    print(LINEA)
    for e in historial[-cantidad:]:
        detalle = f"  ({e['detalle']})" if e.get("detalle") else ""
        print(f" {e.get('fecha', '?')}  {e.get('evento', '?'):<17} {str(e.get('nombre') or '')[:20]:<21}"
              f" {e.get('ip', '')}{detalle}")
    print(LINEA)


def menu_mantenimiento(cfg):
    while True:
        inventario, historial = cargar_todo()
        e = mantenimiento.estado(inventario, historial, cfg,
                                 almacenamiento.tamano_archivo(config.ARCHIVO_HISTORIAL))
        print("\n🧹 MANTENIMIENTO DEL HISTORIAL")
        print(f" Eventos: {e['eventos']} ({e['tamano_kb']} KB) del {e['mas_antiguo']} al {e['mas_reciente']}")
        print(f" Eventos con más de {cfg['retencion_historial_dias']} días: {e['eventos_vencidos']}")
        print(f" Dispositivos: {e['dispositivos']} | protegidos: {e['protegidos']} | "
              f"candidatos a baja: {e['candidatos_baja']}")
        print(f" Limpieza automática: {'ACTIVADA' if cfg['limpieza_automatica'] else 'desactivada'}")
        print(" 1. Borrar eventos antiguos")
        print(" 2. Dar de baja dispositivos que ya no aparecen")
        print(" 3. Borrar el historial de un dispositivo")
        print(" 4. Eliminar un dispositivo")
        print(" 5. Proteger / desproteger un dispositivo")
        print(" 6. Borrar datos (historial, o historial y dispositivos)")
        print(" 7. Configurar limpieza automática")
        print(" 0. Volver")
        op = pedir(" Opción: ", "0")

        if op == "1":
            dias = pedir_entero(" Borrar eventos con más de cuántos días", cfg["retencion_historial_dias"])
            _, n = mantenimiento.purgar_eventos_antiguos(historial, dias)
            if not n:
                print(" No hay eventos tan antiguos.")
            elif confirmar(f" Se borrarán {n} eventos. ¿Continuar?"):
                with almacenamiento.bloqueo():
                    almacenamiento.respaldar(config.ARCHIVO_HISTORIAL)
                    nuevo, n = mantenimiento.purgar_eventos_antiguos(almacenamiento.cargar_historial(), dias)
                    almacenamiento.guardar_historial(nuevo)
                registro.info("AUDITORIA consola: borrar eventos de más de %d días (%d)", dias, n)
                print(f" ✅ {n} eventos borrados.")

        elif op == "2":
            dias = pedir_entero(" Sin verse hace más de cuántos días", cfg["dias_para_baja"])
            candidatos = mantenimiento.candidatos_baja(inventario, dias, cfg["dias_para_baja_mac_aleatoria"])
            if not candidatos:
                print(" No hay dispositivos para dar de baja.")
                continue
            print(f"\n Candidatos ({len(candidatos)}):")
            for d in candidatos:
                print(f"   - {d['nombre']:<24} {d['ip']:<16} {d['mac'] or '-':<19} visto {d['ultima_vez'][:10]}")
            if confirmar(" ¿Dar de baja todos estos?"):
                with almacenamiento.bloqueo():
                    almacenamiento.respaldar(config.ARCHIVO_INVENTARIO)
                    almacenamiento.respaldar(config.ARCHIVO_HISTORIAL)
                    inventario, historial = cargar_todo()   # releer: otra instancia pudo cambiarlo
                    candidatos = mantenimiento.candidatos_baja(inventario, dias,
                                                               cfg["dias_para_baja_mac_aleatoria"])
                    bajas = almacenamiento.cargar_bajas()
                    inventario, historial = mantenimiento.dar_de_baja(
                        inventario, historial, candidatos,
                        bajas if cfg["archivar_bajas"] else None, max_bajas=cfg["max_bajas_archivadas"])
                    guardar_todo(inventario, historial)
                    if cfg["archivar_bajas"]:
                        almacenamiento.guardar_bajas(bajas)
                registro.info("AUDITORIA consola: dar de baja %d dispositivos", len(candidatos))
                donde = f" (copia en {config.ruta_archivo(config.ARCHIVO_BAJAS)})" if cfg["archivar_bajas"] else ""
                print(f" ✅ {len(candidatos)} dados de baja{donde}.")

        elif op == "3":
            d = inv.buscar(inventario, pedir(" MAC, IP o nombre: ", ""))
            if not d or not d["mac"]:
                print(" ❌ No encontrado (o no tiene MAC conocida).")
                continue
            _, n = mantenimiento.borrar_historial_dispositivo(historial, d["mac"])
            if n and confirmar(f" Se borrarán {n} eventos de '{d['nombre']}'. ¿Continuar?"):
                with almacenamiento.bloqueo():
                    almacenamiento.respaldar(config.ARCHIVO_HISTORIAL)
                    nuevo, _ = mantenimiento.borrar_historial_dispositivo(
                        almacenamiento.cargar_historial(), d["mac"])
                    almacenamiento.guardar_historial(nuevo)
                registro.info("AUDITORIA consola: borrar historial de %s", d["mac"])
                print(" ✅ Listo.")

        elif op == "4":
            d = inv.buscar(inventario, pedir(" MAC, IP o nombre del dispositivo a eliminar: ", ""))
            if not d:
                print(" ❌ No encontrado.")
            elif confirmar(f" Se eliminará '{d['nombre']}' ({d['ip'] or d['mac']}) y su historial. ¿Continuar?"):
                servicio.eliminar_dispositivo(d["mac"] or d["ip"])
                registro.info("AUDITORIA consola: eliminar dispositivo %s", d["mac"] or d["ip"])
                print(" ✅ Dispositivo eliminado (hay copia en la carpeta 'respaldos').")

        elif op == "5":
            texto = pedir(" MAC, IP o nombre: ", "")
            with almacenamiento.bloqueo():
                inventario, _ = cargar_todo()
                d = inv.buscar(inventario, texto)
                if d:
                    d["protegido"] = not d["protegido"]
                    almacenamiento.guardar_inventario(inventario)
            if not d:
                print(" ❌ No encontrado.")
            else:
                estado = "está PROTEGIDO (nunca se dará de baja)" if d["protegido"] else "no está protegido"
                print(f" ✅ '{d['nombre']}' ahora {estado}.")

        elif op == "6":
            print(" 1. Borrar solo el historial")
            print(" 2. Borrar historial y dispositivos guardados")
            alcance = pedir(" Opción: ", "")
            if alcance not in ("1", "2"):
                continue
            incluir = alcance == "2"
            conservar = incluir and confirmar(" ¿Conservar los dispositivos protegidos?")
            if pedir(" Escriba BORRAR para confirmar: ", "") != "BORRAR":
                print(" Cancelado.")
                continue
            borrados = servicio.borrar_datos(incluir, conservar)
            registro.info("AUDITORIA consola: borrar %s", "historial y dispositivos" if incluir else "historial")
            extra = f" y {borrados} dispositivos" if incluir else ""
            print(f" ✅ Historial{extra} borrados (hay copia en la carpeta 'respaldos').")

        elif op == "7":
            cfg["limpieza_automatica"] = confirmar(" ¿Limpiar automáticamente tras cada escaneo?")
            cfg["retencion_historial_dias"] = pedir_entero(" Conservar eventos (días)", cfg["retencion_historial_dias"])
            cfg["max_eventos_historial"] = pedir_entero(" Máximo de eventos a guardar", cfg["max_eventos_historial"])
            cfg["dias_para_baja"] = pedir_entero(" Días sin verse para dar de baja", cfg["dias_para_baja"])
            cfg["dias_para_baja_mac_aleatoria"] = pedir_entero(
                " Días para celulares con MAC aleatoria", cfg["dias_para_baja_mac_aleatoria"])
            cfg["fallos_para_inactivo"] = max(1, pedir_entero(
                " Escaneos sin verse antes de marcar inactivo", cfg["fallos_para_inactivo"]))
            cfg["baja_automatica"] = confirmar(" ¿Dar de baja automáticamente, sin preguntar?")
            cfg["archivar_bajas"] = confirmar(" ¿Guardar copia de lo dado de baja en bajas.json?")
            almacenamiento.guardar_config(cfg)
            print(" ✅ Configuración guardada.")

        elif op == "0" or op is None:
            return


def actualizar_fabricantes():
    print(" Descargando la lista oficial de IEEE (unos 3 MB)...")
    try:
        cantidad = fabricantes.actualizar()
        print(f" ✅ {cantidad} fabricantes cargados.")
        registro.info("Lista OUI actualizada: %d fabricantes", cantidad)
        return True
    except Exception as error:     # sin internet, proxy, bloqueo del sitio...
        print(f" ❌ No se pudo descargar ({error}).")
        print(f"    Alternativa: descargue {fabricantes.URL_OUI} con el navegador y")
        print(f"    guárdelo como {config.ruta_archivo(fabricantes.ARCHIVO_OUI)}")
        registro.warning("Fallo al actualizar OUI: %s", error)
        return False


def menu_configuracion(cfg):
    print("\n⚙️ CONFIGURACIÓN")
    print(f" Carpeta de datos : {config.carpeta_datos()}")
    print(f" Perfil del router: {cfg['perfil_router']}")
    print(f" Red manual       : {cfg['red_manual'] or '(detectar sola)'}")
    print(f" Fabricantes      : {'cargados' if fabricantes.disponible() else 'no descargados'}")
    print(" Escriba F para descargar/actualizar la lista de fabricantes, o Enter para seguir.")
    if (pedir(" > ", "") or "").lower() == "f":
        actualizar_fabricantes()
    print("\n Perfiles: auto (recomendado) | baja (router económico) | media | alta (empresarial)")
    perfil = (pedir(f" Perfil [{cfg['perfil_router']}]: ", cfg["perfil_router"]) or "").lower()
    if perfil in ("auto", *config.PERFILES):
        cfg["perfil_router"] = perfil
    red = pedir(" Red manual, ej. 192.168.0.0/22 ('-' para quitarla) [Enter = no cambiar]: ")
    if red == "-":
        cfg["red_manual"] = ""
    elif red:
        try:
            cfg["red_manual"] = str(ipaddress.IPv4Network(red, strict=False))
        except ValueError:
            print(" Red no válida, no se cambió.")
    cfg["resolver_nombres"] = confirmar(" ¿Buscar nombres por DNS inverso?")
    cfg["descubrimiento_mdns"] = confirmar(" ¿Escuchar anuncios mDNS (impresoras, TV, celulares)?")
    cfg["descubrimiento_ssdp"] = confirmar(" ¿Escuchar anuncios SSDP/UPnP (routers, Smart TV)?")
    cfg["netbios"] = confirmar(" ¿Consultar nombres NetBIOS (Windows antiguos, NAS)?")
    almacenamiento.guardar_config(cfg)
    print(" ✅ Guardado.")


def menu():
    print("\n📋 MENÚ PRINCIPAL")
    print(" 1. Escanear red y actualizar inventario")
    print(" 2. Mostrar inventario")
    print(" 3. Agregar dispositivo manual")
    print(" 4. Buscar dispositivo (MAC, IP o nombre)")
    print(" 5. Renombrar dispositivo")
    print(" 6. Contar estados")
    print(" 7. Ver historial de eventos")
    print(" 8. Mantenimiento del historial")
    print(" 9. Configuración")
    print(" 0. Salir")
    return pedir(" Opción: ", "0")


def interactivo(cfg, perfil=None, red=None):
    while True:
        op = menu()
        try:
            if op == "1":
                escanear_y_actualizar(cfg, perfil, red)
            elif op == "2":
                mostrar_inventario(cargar_todo()[0])
            elif op == "3":
                agregar_manual()
            elif op == "4":
                buscar()
            elif op == "5":
                renombrar()
            elif op == "6":
                activos, inactivos = inv.contar_estados(cargar_todo()[0])
                print(f"\n 🟢 Activos: {activos}\n ⚪ Inactivos: {inactivos}")
            elif op == "7":
                ver_historial()
            elif op == "8":
                menu_mantenimiento(cfg)
            elif op == "9":
                menu_configuracion(cfg)
            elif op == "0" or op is None:
                print(" Hasta luego 👋")
                return
            else:
                print(" ⚠️ Opción no válida.")
        except almacenamiento.ArchivoOcupado as error:
            print(f" ⚠️ {error} Intente de nuevo en un momento.")


NOMBRE_REGLA_FIREWALL = "Detector de red"


def configurar_firewall(quitar=False):
    """Regla del Firewall de Windows que deja entrar las respuestas UDP de mDNS,
    SSDP y NetBIOS: solo para este programa y solo en redes privadas."""
    if os.name != "nt":
        print(" Esto solo es necesario en Windows.")
        return 0
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(" Se necesitan permisos de administrador. Abra 'Símbolo del sistema' con clic derecho →")
        print(" 'Ejecutar como administrador' y escriba:  DetectorRed.exe --configurar-firewall")
        return 1
    if not getattr(sys, "frozen", False):
        print(" ⚠️ Está ejecutando desde el código fuente: la regla se creará para python.exe,")
        print("    lo que permite respuestas UDP a CUALQUIER programa de Python. Se recomienda el .exe.")
    base = ["netsh", "advfirewall", "firewall"]
    subprocess.run(base + ["delete", "rule", f"name={NOMBRE_REGLA_FIREWALL}"], capture_output=True)
    if quitar:
        print(" ✅ Regla eliminada.")
        return 0
    r = subprocess.run(base + ["add", "rule", f"name={NOMBRE_REGLA_FIREWALL}", "dir=in", "action=allow",
                               f"program={sys.executable}", "protocol=UDP", "profile=private",
                               "enable=yes"], capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        print(f" ❌ No se pudo crear la regla: {r.stdout.strip() or r.stderr.strip()}")
        return 1
    print(" ✅ Regla creada (solo UDP, solo redes privadas).")
    print("    Si su red aparece como 'Pública' en Windows, cámbiela a 'Privada' en")
    print("    Configuración → Red e Internet → propiedades de la red.")
    return 0


def configurar_registro():
    """registro.log rotativo (1 MB x 3): lo que pasó en escaneos sin pantalla y auditoría."""
    manejador = RotatingFileHandler(config.ruta_archivo("registro.log"),
                                    maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    manejador.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    almacenamiento._solo_dueno(config.ruta_archivo("registro.log"))
    registro.addHandler(manejador)
    registro.setLevel(logging.INFO)


def aceptar_aviso(cfg, acepto_por_parametro=False):
    if cfg.get("aviso_aceptado"):
        return True
    if acepto_por_parametro:
        cfg["aviso_aceptado"] = True
    else:
        print(AVISO)
        if not confirmar(" ¿Entiende y acepta estas condiciones de uso?"):
            return False
        cfg["aviso_aceptado"] = True
    almacenamiento.guardar_config(cfg)
    return True


def main(argv=None):
    """Códigos de salida: 0 bien, 1 error, 2 aviso no aceptado, 3 datos ocupados."""
    # Evita que el programa se caiga al imprimir emojis en consolas antiguas
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(
        prog="detector-red",
        description="Inventario de dispositivos de la red local (ARP + mDNS + SSDP + NetBIOS). "
                    "Sin parámetros abre la interfaz web en el navegador.")
    parser.add_argument("--consola", action="store_true",
                        help="usa el menú de texto en vez de la interfaz web")
    parser.add_argument("--sin-navegador", action="store_true",
                        help="inicia la interfaz web sin abrir el navegador (servidores)")
    parser.add_argument("--puerto", type=int, help="puerto de la interfaz web (por defecto 8765)")
    parser.add_argument("--escanear", action="store_true",
                        help="escanea una vez y termina (para tareas programadas)")
    parser.add_argument("--listar", action="store_true", help="muestra el inventario y termina")
    parser.add_argument("--perfil", choices=["auto", *config.PERFILES], help="perfil del router")
    parser.add_argument("--red", help="red a escanear, ej. 192.168.0.0/22")
    parser.add_argument("--actualizar-fabricantes", action="store_true",
                        help="descarga la lista oficial de fabricantes (IEEE) y termina")
    parser.add_argument("--acepto-aviso", action="store_true",
                        help="acepta el aviso de uso/privacidad sin preguntar (instalaciones automáticas)")
    parser.add_argument("--datos", action="store_true", help="muestra la carpeta de datos y termina")
    parser.add_argument("--restablecer-clave", action="store_true",
                        help="borra la contraseña de la interfaz web (si se olvidó) y desactiva el acceso remoto")
    parser.add_argument("--configurar-firewall", action="store_true",
                        help="(Windows, administrador) permite las respuestas mDNS/SSDP/NetBIOS en redes privadas")
    parser.add_argument("--quitar-firewall", action="store_true",
                        help="(Windows, administrador) elimina la regla creada por --configurar-firewall")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if args.red:
        try:
            args.red = str(ipaddress.IPv4Network(args.red, strict=False))
        except ValueError:
            parser.error(f"red no válida: {args.red}")

    configurar_registro()
    copiados = almacenamiento.migrar_datos_antiguos()
    for ruta in copiados:
        print(f" ℹ️ Datos de la versión anterior importados desde {ruta}")
    cfg = almacenamiento.cargar_config()

    if args.datos:
        print(config.carpeta_datos())
        return 0
    if args.restablecer_clave:
        cfg.update(web_clave="", web_acceso_red=False, web_bloqueo_local=False)
        almacenamiento.guardar_config(cfg)
        registro.warning("AUDITORIA consola: contraseña web restablecida")
        print(" ✅ Contraseña borrada y acceso remoto desactivado. Defina una nueva en Configuración.")
        return 0
    if args.configurar_firewall or args.quitar_firewall:
        return configurar_firewall(quitar=args.quitar_firewall)
    if args.listar:
        mostrar_inventario(cargar_todo()[0])
        return 0
    if args.actualizar_fabricantes:
        return 0 if actualizar_fabricantes() else 1

    if args.escanear:
        # Sin pantalla no se puede preguntar: el aviso debe estar aceptado antes
        if not cfg.get("aviso_aceptado"):
            if not args.acepto_aviso:
                print(" Debe aceptar el aviso de uso: abra el programa una vez sin parámetros "
                      "o use --acepto-aviso.")
                return 2
            aceptar_aviso(cfg, True)
        try:
            return 0 if escanear_y_actualizar(cfg, args.perfil, args.red) is not None else 1
        except almacenamiento.ArchivoOcupado as error:
            print(f" ⚠️ {error}")
            registro.warning("Escaneo omitido: %s", error)
            return 3
        except Exception:
            registro.exception("Error inesperado en el escaneo")
            raise

    print(f"🔍 Detector de dispositivos v{__version__}   (datos en: {config.carpeta_datos()})")
    if args.acepto_aviso and not cfg.get("aviso_aceptado"):
        aceptar_aviso(cfg, True)

    if not args.consola:
        from detector_red import web
        return web.iniciar(cfg, abrir_navegador=not args.sin_navegador, puerto=args.puerto)

    if not aceptar_aviso(cfg, args.acepto_aviso):
        print(" No se aceptó el aviso. El programa se cerrará.")
        return 2
    try:
        interactivo(cfg, args.perfil, args.red)
    except KeyboardInterrupt:
        print("\n Hasta luego 👋")
    return 0


if __name__ == "__main__":
    sys.exit(main())
