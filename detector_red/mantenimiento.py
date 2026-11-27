"""Limpieza del historial (retención y tope) y baja o eliminación de dispositivos."""

from datetime import datetime, timedelta

from detector_red.inventario import INACTIVO, ahora_texto, leer_fecha, registrar_evento


def purgar_eventos_antiguos(historial, dias, ahora=None):
    """Devuelve (historial_nuevo, cantidad_borrada). Eventos con fecha ilegible se conservan."""
    limite = (ahora or datetime.now()) - timedelta(days=dias)
    conservados = []
    for e in historial:
        fecha = leer_fecha(e.get("fecha"))
        if fecha is None or fecha >= limite:
            conservados.append(e)
    return conservados, len(historial) - len(conservados)


def recortar_historial(historial, max_eventos):
    """Conserva solo los 'max_eventos' más recientes."""
    if max_eventos <= 0 or len(historial) <= max_eventos:
        return historial, 0
    return historial[-max_eventos:], len(historial) - max_eventos


def candidatos_baja(inventario, dias, dias_mac_aleatoria=None, ahora=None):
    """Dispositivos inactivos, no protegidos, que no se ven hace más de N días."""
    ahora = ahora or datetime.now()
    candidatos = []
    for d in inventario:
        if d.get("protegido") or d.get("estado") != INACTIVO:
            continue
        limite_dias = dias
        if d.get("mac_aleatoria") and dias_mac_aleatoria:
            limite_dias = min(dias, dias_mac_aleatoria)
        ultima = leer_fecha(d.get("ultima_vez"))
        if ultima is not None and ahora - ultima > timedelta(days=limite_dias):
            candidatos.append(d)
    return candidatos


def dar_de_baja(inventario, historial, dispositivos, bajas=None, ahora=None, max_bajas=2000):
    """Quita los dispositivos y sus eventos; si se pasa 'bajas', archiva una copia
    de cada uno. Deja un evento 'baja' por dispositivo."""
    ids = {id(d) for d in dispositivos}
    claves = {d["mac"] or d["ip"] for d in dispositivos}
    fecha = ahora_texto(ahora)

    def es_de_baja(evento):
        return (evento.get("mac") or evento.get("ip")) in claves

    if bajas is not None:
        for d in dispositivos:
            clave = d["mac"] or d["ip"]
            bajas.append({
                "fecha_baja": fecha,
                "dispositivo": dict(d),
                "eventos": [e for e in historial if (e.get("mac") or e.get("ip")) == clave],
            })
        if max_bajas and len(bajas) > max_bajas:
            del bajas[:len(bajas) - max_bajas]

    nuevo_inventario = [d for d in inventario if id(d) not in ids]
    nuevo_historial = [e for e in historial if not es_de_baja(e)]
    for d in dispositivos:
        registrar_evento(nuevo_historial, "baja", d, f"sin ver desde {d.get('ultima_vez')}", ahora=ahora)
    return nuevo_inventario, nuevo_historial


def eliminar_dispositivos(inventario, historial, dispositivos, ahora=None):
    """Quita los dispositivos del inventario junto con sus eventos.
    Deja un evento 'eliminado' por cada uno como rastro de auditoría."""
    ids = {id(d) for d in dispositivos}
    claves = {d["mac"] or d["ip"] for d in dispositivos}
    nuevo_inventario = [d for d in inventario if id(d) not in ids]
    nuevo_historial = [e for e in historial if (e.get("mac") or e.get("ip")) not in claves]
    for d in dispositivos:
        registrar_evento(nuevo_historial, "eliminado", d, "eliminado a mano", ahora=ahora)
    return nuevo_inventario, nuevo_historial


def borrar_todo(inventario, conservar_protegidos=True):
    """Devuelve (inventario, historial) vacíos, salvo los protegidos si se piden."""
    return [d for d in inventario if conservar_protegidos and d.get("protegido")], []


def borrar_historial_dispositivo(historial, mac):
    conservados = [e for e in historial if e.get("mac") != mac]
    return conservados, len(historial) - len(conservados)


def estado(inventario, historial, cfg, tamano_bytes=0, ahora=None):
    fechas = [f for f in (leer_fecha(e.get("fecha")) for e in historial) if f]
    viejos, _ = purgar_eventos_antiguos(historial, cfg["retencion_historial_dias"], ahora)
    return {
        "eventos": len(historial),
        "tamano_kb": round(tamano_bytes / 1024, 1),
        "mas_antiguo": min(fechas).strftime("%Y-%m-%d") if fechas else "-",
        "mas_reciente": max(fechas).strftime("%Y-%m-%d") if fechas else "-",
        "eventos_vencidos": len(historial) - len(viejos),
        "dispositivos": len(inventario),
        "protegidos": sum(1 for d in inventario if d.get("protegido")),
        "candidatos_baja": len(candidatos_baja(inventario, cfg["dias_para_baja"],
                                               cfg["dias_para_baja_mac_aleatoria"], ahora)),
    }


def limpieza_automatica(inventario, historial, bajas, cfg, ahora=None):
    """Se ejecuta después de cada escaneo si 'limpieza_automatica' está activa.
    Devuelve (inventario, historial, resumen)."""
    resumen = {"eventos_vencidos": 0, "eventos_recortados": 0, "bajas": 0}
    if cfg.get("baja_automatica"):
        candidatos = candidatos_baja(inventario, cfg["dias_para_baja"],
                                     cfg["dias_para_baja_mac_aleatoria"], ahora)
        if candidatos:
            inventario, historial = dar_de_baja(
                inventario, historial, candidatos,
                bajas if cfg.get("archivar_bajas") else None, ahora,
                cfg.get("max_bajas_archivadas", 2000))
            resumen["bajas"] = len(candidatos)
    historial, resumen["eventos_vencidos"] = purgar_eventos_antiguos(
        historial, cfg["retencion_historial_dias"], ahora)
    historial, resumen["eventos_recortados"] = recortar_historial(
        historial, cfg["max_eventos_historial"])
    return inventario, historial, resumen
