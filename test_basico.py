"""Pruebas sin red: python -m unittest discover tests"""

import ipaddress
import os
import tempfile
import unittest
from datetime import datetime, timedelta

os.environ["DETECTOR_RED_DATOS"] = tempfile.mkdtemp()

import socket  # noqa: E402
import struct  # noqa: E402

from detector_red import almacenamiento, descubrimiento, escaner, fabricantes  # noqa: E402
from detector_red import inventario as inv, mantenimiento  # noqa: E402

RED = ipaddress.IPv4Network("192.168.1.0/24")

IPCONFIG_ES = """
Configuración IP de Windows

   Nombre de host. . . . . . . . . : PC-CAMILO
   Tipo de nodo. . . . . . . . . . : híbrido

Adaptador de Ethernet Ethernet VirtualBox:

   Dirección física. . . . . . . . . . . . . : 0A-00-27-00-00-0C
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.56.1(Preferido)
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0
   Puerta de enlace predeterminada . . . . . :

Adaptador de LAN inalámbrica Wi-Fi:

   Sufijo DNS específico para la conexión. . : home
   Descripción . . . . . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   Dirección física. . . . . . . . . . . . . : 3C-A9-F4-12-34-56
   DHCP habilitado . . . . . . . . . . . . . : sí
   Vínculo: dirección IPv6 local. . . : fe80::1c2d:3e4f:5a6b:7c8d%12(Preferido)
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.1.37(Preferido)
   Máscara de subred . . . . . . . . . . . . : 255.255.252.0
   Concesión obtenida. . . . . . . . . . . . : lunes, 23 de noviembre de 2026 8:01:12
   La concesión expira . . . . . . . . . . . : martes, 24 de noviembre de 2026 8:01:12
   Puerta de enlace predeterminada . . . . . : fe80::1%12
                                       192.168.1.1
   Servidor DHCP . . . . . . . . . . . . . . : 192.168.1.1
   IAID DHCPv6 . . . . . . . . . . . . . . . : 54321
   DUID de cliente DHCPv6. . . . . . . . . . : 00-01-00-01-2A-BC-DE-F0-3C-A9-F4-12-34-56
"""

ARP_WINDOWS = """
Interfaz: 192.168.1.37 --- 0xc
  Dirección de Internet          Dirección física      Tipo
  192.168.1.1           94-02-6b-d8-ef-35     dinámico
  192.168.1.3           72-6f-65-b5-df-d3     dinámico
  192.168.1.11          0c-79-55-d2-08-3c     dinámico
  192.168.1.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  239.255.255.250       01-00-5e-7f-ff-fa     estático

Interfaz: 192.168.10.5 --- 0x9
  192.168.10.20         aa-bb-cc-dd-ee-ff     dinámico
"""

PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         94:02:6b:d8:ef:35     *        wlan0
192.168.1.40     0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.1.12     0x1         0x2         ac:de:48:00:11:22     *        wlan0
"""

ARP_MAC = """? (192.168.1.1) at 94:2:6b:d8:ef:35 on en0 ifscope [ethernet]
? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.12) at ac:de:48:0:11:22 on en0 ifscope [ethernet]
"""

IP_ADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 3c:a9:f4:12:34:56 brd ff:ff:ff:ff:ff:ff
    inet 10.67.210.101/23 brd 10.67.211.255 scope global dynamic wlan0
"""

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:a9:f4:12:34:56
\tinet 192.168.1.37 netmask 0xffffff00 broadcast 192.168.1.255
"""


class TestEscaner(unittest.TestCase):
    def test_normalizar_mac(self):
        self.assertEqual(escaner.normalizar_mac("94-2-6b-d8-ef-35"), "94:02:6B:D8:EF:35")
        self.assertIsNone(escaner.normalizar_mac("ff-ff-ff-ff-ff-ff"))
        self.assertIsNone(escaner.normalizar_mac("01-00-5e-00-00-16"))
        self.assertIsNone(escaner.normalizar_mac("XX:XX:XX:XX:XX:XX"))
        self.assertIsNone(escaner.normalizar_mac("00:00:00:00:00:00"))

    def test_mac_aleatoria(self):
        self.assertTrue(escaner.es_mac_aleatoria("72-6f-65-b5-df-d3"))
        self.assertTrue(escaner.es_mac_aleatoria("2a-61-0d-40-f8-20"))
        self.assertFalse(escaner.es_mac_aleatoria("94-02-6b-d8-ef-35"))

    def test_ipconfig_elige_adaptador_correcto(self):
        prefijo, gateway, mac = escaner.interpretar_ipconfig(IPCONFIG_ES, "192.168.1.37")
        self.assertEqual((prefijo, gateway, mac), (22, "192.168.1.1", "3C:A9:F4:12:34:56"))

    def test_ip_addr_linux(self):
        self.assertEqual(escaner.interpretar_ip_addr(IP_ADDR, "10.67.210.101"), (23, "3C:A9:F4:12:34:56"))

    def test_ifconfig_mac(self):
        self.assertEqual(escaner.interpretar_ifconfig(IFCONFIG, "192.168.1.37"), (24, "3C:A9:F4:12:34:56"))

    def test_arp_windows_filtra_broadcast_y_otra_red(self):
        r = escaner.interpretar_tabla_arp(ARP_WINDOWS, RED)
        self.assertEqual(set(r), {"192.168.1.1", "192.168.1.3", "192.168.1.11"})

    def test_arp_linux_y_mac(self):
        self.assertEqual(set(escaner.interpretar_tabla_arp(PROC_ARP, RED)), {"192.168.1.1", "192.168.1.12"})
        r = escaner.interpretar_tabla_arp(ARP_MAC, RED)
        self.assertEqual(r, {"192.168.1.1": "94:02:6B:D8:EF:35", "192.168.1.12": "AC:DE:48:00:11:22"})


class TestInventario(unittest.TestCase):
    def test_migracion_formato_anterior(self):
        viejo = [
            {"nombre": "Dispositivo_2", "ip": "192.168.1.2", "mac": "XX:XX:XX:XX:XX:XX", "estado": "activo"},
            {"nombre": "Dispositivo_1", "ip": "192.168.1.1", "mac": "94-02-6b-d8-ef-35", "estado": "activo"},
            {"nombre": "Dispositivo_255", "ip": "192.168.1.255", "mac": "ff-ff-ff-ff-ff-ff", "estado": "activo"},
        ]
        nuevo = inv.normalizar_inventario(viejo)
        self.assertEqual([d["ip"] for d in nuevo], ["192.168.1.2", "192.168.1.1"])
        self.assertIsNone(nuevo[0]["mac"])
        self.assertEqual(nuevo[1]["mac"], "94:02:6B:D8:EF:35")

    def test_ciclo_de_vida(self):
        inventario, historial = [], []
        t0 = datetime(2026, 1, 1, 10)
        r = inv.actualizar_con_escaneo(inventario, historial,
                                       {"192.168.1.1": "94:02:6B:D8:EF:35", "192.168.1.5": "AC:DE:48:00:11:22"},
                                       RED, {"192.168.1.5": "laptop-ana"}, ahora=t0)
        self.assertEqual(r["nuevos"], 2)
        self.assertEqual(inventario[1]["nombre"], "laptop-ana")
        # segundo escaneo: el portátil cambió de IP, el router igual
        r = inv.actualizar_con_escaneo(inventario, historial,
                                       {"192.168.1.1": "94:02:6B:D8:EF:35", "192.168.1.9": "AC:DE:48:00:11:22"},
                                       RED, ahora=t0 + timedelta(hours=1))
        self.assertEqual((r["nuevos"], r["cambios_ip"], r["sin_cambios"]), (0, 1, 1))
        self.assertEqual(len(inventario), 2)
        # tercer escaneo: el portátil se fue
        r = inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": "94:02:6B:D8:EF:35"},
                                       RED, ahora=t0 + timedelta(hours=2), fallos_para_inactivo=1)
        self.assertEqual(r["desconectados"], 1)
        self.assertEqual([e["evento"] for e in historial], ["nuevo", "nuevo", "cambio_ip", "desconectado"])

    def test_no_marca_inactivos_de_otra_red(self):
        inventario, historial = [], []
        otra = ipaddress.IPv4Network("10.67.210.0/24")
        inv.actualizar_con_escaneo(inventario, historial, {"10.67.210.110": "2A:61:0D:40:F8:20"}, otra)
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": "94:02:6B:D8:EF:35"}, RED)
        self.assertEqual(inventario[0]["estado"], inv.ACTIVO)


class TestMantenimiento(unittest.TestCase):
    def setUp(self):
        self.ahora = datetime(2026, 11, 23, 12)
        self.inventario = [
            {"nombre": "viejo", "ip": "192.168.1.20", "mac": "AC:DE:48:00:00:01", "estado": "inactivo",
             "ultima_vez": "2026-05-01 10:00:00", "protegido": False, "mac_aleatoria": False},
            {"nombre": "servidor", "ip": "192.168.1.2", "mac": "AC:DE:48:00:00:02", "estado": "inactivo",
             "ultima_vez": "2026-01-01 10:00:00", "protegido": True, "mac_aleatoria": False},
            {"nombre": "celular", "ip": "192.168.1.30", "mac": "72:6F:65:B5:DF:D3", "estado": "inactivo",
             "ultima_vez": "2026-10-01 10:00:00", "protegido": False, "mac_aleatoria": True},
            {"nombre": "activo", "ip": "192.168.1.1", "mac": "94:02:6B:D8:EF:35", "estado": "activo",
             "ultima_vez": "2026-11-23 10:00:00", "protegido": False, "mac_aleatoria": False},
        ]
        self.historial = [
            {"fecha": "2025-03-10 14:32:00", "evento": "nuevo", "mac": "AC:DE:48:00:00:01", "ip": "192.168.1.20"},
            {"fecha": "2026-11-01 14:32:00", "evento": "desconectado", "mac": "94:02:6B:D8:EF:35", "ip": "192.168.1.1"},
            {"fecha": "2026-11-20 14:32:00", "evento": "reconectado", "mac": "94:02:6B:D8:EF:35", "ip": "192.168.1.1"},
        ]

    def test_retencion_y_tope(self):
        h, n = mantenimiento.purgar_eventos_antiguos(self.historial, 180, self.ahora)
        self.assertEqual(n, 1)
        h, n = mantenimiento.recortar_historial(h, 1)
        self.assertEqual((n, h[0]["evento"]), (1, "reconectado"))

    def test_candidatos_respeta_protegidos_y_mac_aleatoria(self):
        c = mantenimiento.candidatos_baja(self.inventario, 90, 30, self.ahora)
        self.assertEqual({d["nombre"] for d in c}, {"viejo", "celular"})

    def test_baja_archiva_y_limpia(self):
        bajas = []
        c = mantenimiento.candidatos_baja(self.inventario, 90, 30, self.ahora)
        inv2, h2 = mantenimiento.dar_de_baja(self.inventario, self.historial, c, bajas, self.ahora)
        self.assertEqual({d["nombre"] for d in inv2}, {"servidor", "activo"})
        self.assertEqual(len(bajas), 2)
        self.assertEqual(len(bajas[0]["eventos"]), 1)
        self.assertEqual([e["evento"] for e in h2], ["desconectado", "reconectado", "baja", "baja"])


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Versión 0.3: descubrimiento y correcciones
# ---------------------------------------------------------------------------

def _rr(nombre_bytes, tipo, rdata):
    return nombre_bytes + struct.pack(">HHIH", tipo, 0x8001, 120, len(rdata)) + rdata


def _respuesta_mdns_ejemplo():
    cab = struct.pack(">HHHHHH", 0, 0x8400, 0, 3, 0, 0)
    meta = descubrimiento._codificar_nombre("_services._dns-sd._udp.local")
    ipp = descubrimiento._codificar_nombre("_ipp._tcp.local")
    pos_ipp = 12 + len(meta) + 10            # rdata del 1er registro empieza aquí
    r1 = _rr(meta, 12, ipp)
    # 2.º registro: el nombre es un PUNTERO al "_ipp._tcp.local" anterior
    puntero = struct.pack(">H", 0xC000 | pos_ipp)
    r2 = _rr(puntero, 12, bytes([11]) + b"HP LaserJet" + puntero)
    r3 = _rr(descubrimiento._codificar_nombre("impresora.local"), 1, socket.inet_aton("192.168.1.50"))
    return cab + r1 + r2 + r3


class TestDescubrimiento(unittest.TestCase):
    def test_consulta_dns_bit_qu(self):
        paquete = descubrimiento.consulta_dns("_services._dns-sd._udp.local", ident=7)
        self.assertEqual(paquete[:2], b"\x00\x07")
        self.assertEqual(paquete[-4:], b"\x00\x0c\x80\x01")

    def test_interpretar_dns_con_compresion(self):
        es_resp, regs = descubrimiento.interpretar_dns(_respuesta_mdns_ejemplo())
        self.assertTrue(es_resp)
        self.assertEqual(regs, [
            ("_services._dns-sd._udp.local", 12, "_ipp._tcp.local"),
            ("_ipp._tcp.local", 12, "HP LaserJet._ipp._tcp.local"),
            ("impresora.local", 1, "192.168.1.50"),
        ])

    def test_dns_malicioso_no_cuelga(self):
        bucle = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            descubrimiento.interpretar_dns(bucle)

    def test_nbstat(self):
        consulta = descubrimiento.consulta_nbstat(1)
        self.assertEqual(len(consulta), 50)
        nombres = (b"WORKGROUP      \x00" + b"\x84\x00"      # grupo: se ignora
                   + b"PC-CONTABILIDAD\x00" + b"\x04\x00"
                   + b"PC-CONTABILIDAD\x20" + b"\x04\x00")
        rdata = bytes([3]) + nombres + b"\x00" * 46
        resp = (struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0) + consulta[12:46]
                + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata)
        self.assertEqual(descubrimiento.interpretar_nbstat(resp), "PC-CONTABILIDAD")

    def test_ssdp_y_tipo(self):
        cab = descubrimiento.interpretar_ssdp(
            "HTTP/1.1 200 OK\r\nSERVER: Linux/4.4 UPnP/1.0 Roku/9.4\r\n"
            "ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n")
        info = {"servidor": cab["server"], "tipos": {cab["st"]}}
        self.assertEqual(descubrimiento.inferir_tipo((), info), "TV / Roku")
        self.assertEqual(descubrimiento.inferir_tipo({"ipp"}), "Impresora")
        self.assertEqual(descubrimiento.inferir_tipo((), None, es_gateway=True), "Router")


class TestCorrecciones(unittest.TestCase):
    ROUTER = "94:02:6B:D8:EF:35"
    CEL = "72:6F:65:B5:DF:D3"

    def test_no_parpadea_con_un_fallo(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": self.ROUTER, "192.168.1.30": self.CEL}, RED)
        r = inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": self.ROUTER}, RED)
        self.assertEqual(r["desconectados"], 0)              # 1 fallo: sigue activo
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": self.ROUTER, "192.168.1.30": self.CEL}, RED)
        self.assertNotIn("reconectado", [e["evento"] for e in historial])
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": self.ROUTER}, RED)
        r = inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": self.ROUTER}, RED)
        self.assertEqual(r["desconectados"], 1)              # 2 fallos seguidos: inactivo

    def test_mac_rotativa_mismo_nombre(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.30": self.CEL}, RED,
                                   {"192.168.1.30": "iPhone-de-Ana"})
        nueva = "3A:11:22:33:44:55"
        r = inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.31": nueva}, RED,
                                       {"192.168.1.31": "iPhone-de-Ana"})
        self.assertEqual((len(inventario), r["cambios_mac"]), (1, 1))
        self.assertEqual(inventario[0]["macs_anteriores"], [self.CEL])

    def test_nombre_generico_no_se_fusiona(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.30": self.CEL}, RED, {"192.168.1.30": "android"})
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.31": "3A:11:22:33:44:55"}, RED,
                                   {"192.168.1.31": "android"})
        self.assertEqual(len(inventario), 2)

    def test_repetidor_misma_mac_varias_ip(self):
        inventario, historial = [], []
        rep = "AC:DE:48:00:00:99"
        escaneo = {"192.168.1.40": rep, "192.168.1.41": rep, "192.168.1.42": rep}
        r1 = inv.actualizar_con_escaneo(inventario, historial, escaneo, RED)
        r2 = inv.actualizar_con_escaneo(inventario, historial, escaneo, RED)
        self.assertEqual(len(inventario), 1)
        self.assertEqual(inventario[0]["ip"], "192.168.1.40")
        self.assertEqual(inventario[0]["ips_extra"], ["192.168.1.41", "192.168.1.42"])
        self.assertEqual((len(r1["alertas"]), len(r2["alertas"]), r2["cambios_ip"]), (1, 0, 0))

    def test_alerta_si_cambia_mac_del_router(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": self.ROUTER}, RED, gateway="192.168.1.1")
        r = inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": "AC:DE:48:66:66:66"}, RED,
                                       gateway="192.168.1.1")
        self.assertEqual(len(r["alertas"]), 1)
        self.assertIn("alerta_router", [e["evento"] for e in historial])

    def test_bloqueo_impide_escrituras_simultaneas(self):
        with almacenamiento.bloqueo():
            with self.assertRaises(almacenamiento.ArchivoOcupado):
                with almacenamiento.bloqueo(espera=0.6):
                    pass
        with almacenamiento.bloqueo(espera=0.6):   # liberado correctamente
            pass

    def test_tope_de_bajas(self):
        bajas = [{"n": i} for i in range(5)]
        d = {"nombre": "x", "ip": "192.168.1.9", "mac": "AC:DE:48:00:00:09", "ultima_vez": "2026-01-01 00:00:00"}
        mantenimiento.dar_de_baja([d], [], [d], bajas, max_bajas=3)
        self.assertEqual(len(bajas), 3)
        self.assertEqual(bajas[-1]["dispositivo"]["ip"], "192.168.1.9")

    def test_fabricantes(self):
        tabla = fabricantes.interpretar_csv(
            'Registry,Assignment,Organization Name,Organization Address\n'
            'MA-L,94026B,"Fabricante Ejemplo S.A.",Shenzhen\nMA-L,ACDE48,Private,\n')
        self.assertEqual(tabla["94026B"], "Fabricante Ejemplo S.A.")
        fabricantes._tabla = tabla
        self.assertEqual(fabricantes.buscar("94-02-6b-d8-ef-35"), "Fabricante Ejemplo S.A.")
        self.assertEqual(fabricantes.buscar(self.CEL), "MAC privada")
        fabricantes._tabla = None


class TestIpReasignada(unittest.TestCase):
    def test_ip_tomada_por_otro_equipo_marca_inactivo_inmediato(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.30": "AC:DE:48:00:00:30"}, RED)
        r = inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.30": "AC:DE:48:00:00:31"}, RED)
        viejo = next(d for d in inventario if d["mac"] == "AC:DE:48:00:00:30")
        self.assertEqual((viejo["estado"], r["desconectados"]), (inv.INACTIVO, 1))
        self.assertEqual(historial[-1]["detalle"], "su IP ahora la usa otro equipo")

    def test_router_se_llama_router(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.1": "94:02:6B:D8:EF:35"}, RED,
                                   gateway="192.168.1.1")
        self.assertEqual((inventario[0]["nombre"], inventario[0]["tipo"]), ("Router", "Router"))


# ---------------------------------------------------------------------------
# Interfaz web
# ---------------------------------------------------------------------------

import http.client  # noqa: E402
import json  # noqa: E402
import threading  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402

from detector_red import web  # noqa: E402


class TestWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = almacenamiento.cargar_config()
        cls.servidor = ThreadingHTTPServer(("127.0.0.1", 0), web.Manejador)
        cls.servidor.app = web.Aplicacion(cfg, cls.servidor.server_address[1], False)
        cls.puerto = cls.servidor.server_address[1]
        threading.Thread(target=cls.servidor.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.servidor.shutdown()
        cls.servidor.server_close()

    def pedir(self, metodo, ruta, datos=None, cabeceras=None):
        con = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=5)
        cuerpo = json.dumps(datos) if datos is not None else None
        cabeceras = dict(cabeceras or {})
        if cuerpo is not None:
            cabeceras.setdefault("Content-Type", "application/json")
        con.request(metodo, ruta, body=cuerpo, headers=cabeceras)
        r = con.getresponse()
        texto = r.read().decode()
        con.close()
        return r.status, texto

    def test_pagina_incluye_token(self):
        estado, html = self.pedir("GET", "/")
        self.assertEqual(estado, 200)
        self.assertIn(self.servidor.app.token, html)

    def test_post_sin_token_rechazado(self):
        estado, _ = self.pedir("POST", "/api/escanear", {})
        self.assertEqual(estado, 403)

    def test_host_falso_rechazado(self):
        estado, _ = self.pedir("GET", "/api/estado", cabeceras={"Host": "atacante.com"})
        self.assertEqual(estado, 403)

    def test_dispositivos_y_config_sin_clave(self):
        estado, texto = self.pedir("GET", "/api/config")
        datos = json.loads(texto)
        self.assertEqual(estado, 200)
        self.assertNotIn("web_clave", datos)

    def test_config_invalida_no_cambia_nada(self):
        token = {"X-Token": self.servidor.app.token}
        antes = self.servidor.app.cfg["dias_para_baja"]
        estado, _ = self.pedir("POST", "/api/config", {"red_manual": "999.1.1.1/24", "dias_para_baja": 3}, token)
        self.assertEqual(estado, 400)
        self.assertEqual(self.servidor.app.cfg["dias_para_baja"], antes)

    def test_contrasena(self):
        guardada = web.cifrar_clave("claveSegura123")
        self.assertNotIn("claveSegura123", guardada)
        self.assertTrue(web.verificar_clave("claveSegura123", guardada))
        self.assertFalse(web.verificar_clave("otra", guardada))
        self.assertFalse(web.verificar_clave("x", ""))


# ---------------------------------------------------------------------------
# Versión 0.5: IPv6, tipo manual, validación
# ---------------------------------------------------------------------------

from detector_red import servicio, validacion  # noqa: E402

NETSH_ES = """
Interfaz 1: Loopback Pseudo-Interface 1

Dirección de Internet                         Dirección física   Tipo
--------------------------------------------  -----------------  -----------
ff02::1                                                          Permanente

Interfaz 7: Ethernet VirtualBox

Dirección de Internet                         Dirección física   Tipo
--------------------------------------------  -----------------  -----------
fe80::aaaa                                    0a-00-27-00-00-0c  Accesible

Interfaz 12: Wi-Fi

Dirección de Internet                         Dirección física   Tipo
--------------------------------------------  -----------------  -----------
2800:e2:1:2::1                                94-02-6b-d8-ef-35  Accesible (enrutador)
fe80::1c2d:3e4f:5a6b:7c8d                     72-6f-65-b5-df-d3  Obsoleto
fe80::9                                       ac-de-48-00-00-09  Accesible
fe80::10                                      00-00-00-00-00-00  Inaccesible
ff02::1                                       33-33-00-00-00-01  Permanente
"""

IP6_LINUX = """fe80::1 lladdr 94:02:6b:d8:ef:35 router REACHABLE
fe80::9 lladdr ac:de:48:00:00:09 STALE
fe80::77 FAILED
2800:e2:1:2::77 lladdr ac:de:48:00:00:77 DELAY
"""

NDP_MAC = """Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                     94:2:6b:d8:ef:35   en0 23h59m58s S  R
fe80::9%en0                     ac:de:48:0:0:9     en0 2s        R
fe80::5%bridge0                 ac:de:48:0:0:5     bridge0 2s    R
"""


class TestIPv6(unittest.TestCase):
    def test_nombre_interfaz(self):
        self.assertEqual(escaner.nombre_interfaz(IPCONFIG_ES, "192.168.1.37", "windows"),
                         "Adaptador de LAN inalámbrica Wi-Fi")
        self.assertEqual(escaner.nombre_interfaz(IP_ADDR, "10.67.210.101", "linux"), "wlan0")
        self.assertEqual(escaner.nombre_interfaz(IFCONFIG, "192.168.1.37", "mac"), "en0")

    def test_netsh_solo_interfaz_correcta(self):
        v = escaner.interpretar_vecinos_ipv6(NETSH_ES, "Adaptador de LAN inalámbrica Wi-Fi", "windows")
        self.assertEqual(set(v), {"94:02:6B:D8:EF:35", "72:6F:65:B5:DF:D3", "AC:DE:48:00:00:09"})
        self.assertTrue(v["94:02:6B:D8:EF:35"]["reciente"])
        self.assertFalse(v["72:6F:65:B5:DF:D3"]["reciente"])          # obsoleto
        self.assertNotIn("0A:00:27:00:00:0C", v)                        # VirtualBox excluido

    def test_linux_y_mac(self):
        v = escaner.interpretar_vecinos_ipv6(IP6_LINUX, "wlan0", "linux")
        self.assertEqual({m: x["reciente"] for m, x in v.items()},
                         {"94:02:6B:D8:EF:35": True, "AC:DE:48:00:00:09": False, "AC:DE:48:00:00:77": True})
        v = escaner.interpretar_vecinos_ipv6(NDP_MAC, "en0", "mac")
        self.assertEqual({m: x["reciente"] for m, x in v.items()},
                         {"94:02:6B:D8:EF:35": False, "AC:DE:48:00:00:09": True})

    def test_ipv6_mantiene_presente_y_crea_solo_ipv6(self):
        inventario, historial = [], []
        cel = "72:6F:65:B5:DF:D3"
        inv.actualizar_con_escaneo(inventario, historial, {"192.168.1.30": cel}, RED)
        vecinos = {cel: {"ipv6": {"fe80::7"}, "reciente": True},
                   "AC:DE:48:00:00:66": {"ipv6": {"2800:e2::66"}, "reciente": True}}
        for _ in range(3):   # el celular no contesta ARP pero sí aparece por IPv6
            r = inv.actualizar_con_escaneo(inventario, historial, {}, RED, vecinos6=vecinos,
                                           crear_solo_ipv6=True)
        celular = inv.buscar_por_mac(inventario, cel)
        self.assertEqual((celular["estado"], celular["ipv6"]), (inv.ACTIVO, ["fe80::7"]))
        solo6 = inv.buscar_por_mac(inventario, "AC:DE:48:00:00:66")
        self.assertEqual((solo6["ip"], solo6["estado"]), ("", inv.ACTIVO))
        self.assertEqual(r["desconectados"], 0)
        self.assertIs(inv.buscar(inventario, "2800:e2::66"), solo6)

    def test_sin_interfaz_no_crea_solo_ipv6(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial, {}, RED,
                                   vecinos6={"AC:DE:48:00:00:66": {"ipv6": {"fe80::66"}, "reciente": True}})
        self.assertEqual(inventario, [])

    def test_tipo_manual_se_respeta(self):
        inventario, historial = [], []
        ip = "192.168.1.50"
        inv.actualizar_con_escaneo(inventario, historial, {ip: "AC:DE:48:00:00:50"}, RED,
                                   detalles={ip: {"tipo": "Impresora"}})
        inventario[0]["tipo"], inventario[0]["tipo_manual"] = "Escáner de bodega", True
        inv.actualizar_con_escaneo(inventario, historial, {ip: "AC:DE:48:00:00:50"}, RED,
                                   detalles={ip: {"tipo": "Impresora"}})
        self.assertEqual(inventario[0]["tipo"], "Escáner de bodega")


LISTA_ROUTER = """DHCP Client List
ID  Client Name        MAC Address         Assigned IP     Lease Time
1   iPhone-de-Ana      72-6F-65-B5-DF-D3   192.168.1.30    23:59:01
2   PC-Contabilidad    AC:DE:48:00:00:15   192.168.1.15    22:10:44
3   Impresora          ac:de:48:00:00:50   192.168.1.50    Permanent
"""


class TestValidacion(unittest.TestCase):
    def test_extraer_y_comparar(self):
        macs = validacion.extraer_macs(LISTA_ROUTER)
        self.assertEqual(len(macs), 3)
        r = validacion.comparar(macs, ["72:6F:65:B5:DF:D3", "AC:DE:48:00:00:15", "94:02:6B:D8:EF:35"])
        self.assertEqual((r["coinciden"], r["en_router"], r["porcentaje"]), (2, 3, 66.7))
        self.assertEqual(r["faltan"], ["AC:DE:48:00:00:50"])
        self.assertEqual(r["extra"], ["94:02:6B:D8:EF:35"])

    def test_conteo(self):
        r = validacion.comparar_conteo(40, 38)
        self.assertEqual((r["metodo"], r["porcentaje"]), ("conteo", 95.0))
        with self.assertRaises(ValueError):
            validacion.comparar_conteo(0, 5)

    def test_registro_resumen_y_csv(self):
        almacenamiento.escribir_json(validacion.ARCHIVO_VALIDACIONES, [])
        ultimo = {"fecha": "2026-11-24 10:00:00", "red": "192.168.1.0/24", "perfil": "media", "duracion": 40}
        validacion.registrar(validacion.comparar_conteo(40, 38), ultimo, "casa")
        validacion.registrar(validacion.comparar_conteo(40, 34), ultimo)
        resumen = validacion.resumen_por_perfil(validacion.cargar())
        self.assertEqual(resumen["media"]["promedio"], 90.0)
        csv_texto = validacion.a_csv(validacion.cargar())
        self.assertTrue(csv_texto.startswith("﻿"))
        self.assertIn("95,0", csv_texto)


class TestWebValidacion(TestWeb):
    def test_validar_sin_escaneo_y_con_escaneo(self):
        token = {"X-Token": self.servidor.app.token}
        almacenamiento.escribir_json(servicio.ARCHIVO_ESTADO, {})
        estado, _ = self.pedir("POST", "/api/validar", {"texto": LISTA_ROUTER}, token)
        self.assertEqual(estado, 400)
        almacenamiento.escribir_json(servicio.ARCHIVO_ESTADO, {
            "fecha": "2026-11-24 10:00:00", "perfil": "baja",
            "macs": ["72:6F:65:B5:DF:D3", "AC:DE:48:00:00:15", "AC:DE:48:00:00:50"]})
        estado, texto = self.pedir("POST", "/api/validar", {"texto": LISTA_ROUTER, "nota": "prueba"}, token)
        self.assertEqual(estado, 200)
        self.assertEqual(json.loads(texto)["validacion"]["porcentaje"], 100.0)
        estado, texto = self.pedir("GET", "/api/validaciones.csv")
        self.assertEqual(estado, 200)
        self.assertIn("prueba", texto)


# ---------------------------------------------------------------------------
# Versión 0.6: seguridad
# ---------------------------------------------------------------------------

import socket  # noqa: E402,F811


class TestSeguridadDatos(unittest.TestCase):
    def test_limpiar_texto_quita_control_e_invisibles(self):
        self.assertEqual(escaner.limpiar_texto("PC\x1b[2J\x1b[31mHACK\x07"), "PC [2J [31mHACK")
        self.assertEqual(escaner.limpiar_texto("factura‮exe.pdf"), "factura exe.pdf")
        self.assertEqual(escaner.limpiar_texto("a" * 500), "a" * 63)
        self.assertIsNone(escaner.limpiar_texto("\x00\x01  "))

    def test_inventario_alterado_no_rompe(self):
        malos = [{"ip": 12345, "mac": "AC:DE:48:00:00:01"},
                 {"ip": "192.168.1.9", "nombre": ["lista"], "servicios": "no-es-lista",
                  "ultima_vez": "ayer", "fallos": "x", "mac": "AC:DE:48:00:00:02"}]
        n = inv.normalizar_inventario(malos)
        self.assertEqual(len(n), 1)
        self.assertEqual((n[0]["servicios"], n[0]["fallos"]), ([], 0))
        self.assertIsNotNone(inv.leer_fecha(n[0]["ultima_vez"]))

    def test_servicio_mdns_invalido_se_descarta(self):
        self.assertEqual(descubrimiento._servicio_corto("_ipp._tcp.local"), "ipp")
        self.assertIsNone(descubrimiento._servicio_corto("_<script>._tcp.local"))
        self.assertIsNone(descubrimiento._servicio_corto("_" + "a" * 60 + "._tcp.local"))

    def test_csv_sin_inyeccion_de_formulas(self):
        texto = validacion.a_csv([{"nota": "=HYPERLINK(\"http://x\")", "porcentaje": 90.0}])
        self.assertIn("'=HYPERLINK", texto)

    def test_respaldo_antes_de_borrar(self):
        almacenamiento.guardar_historial([{"fecha": "2026-01-01 00:00:00", "evento": "nuevo"}])
        for _ in range(7):
            ruta = almacenamiento.respaldar("historial.json")
        self.assertTrue(os.path.isfile(ruta))
        carpeta = os.path.dirname(ruta)
        self.assertLessEqual(len([f for f in os.listdir(carpeta) if f.startswith("historial-")]), 5)


class TestSeguridadWeb(TestWeb):
    def crudo(self, datos, espera=3):
        s = socket.create_connection(("127.0.0.1", self.puerto), timeout=espera)
        s.sendall(datos)
        try:
            return s.recv(200).decode(errors="replace").split("\r\n")[0]
        finally:
            s.close()

    def test_content_length_negativo_responde_400(self):
        t = self.servidor.app.token
        linea = self.crudo(f"POST /api/escanear HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Token: {t}\r\n"
                           f"Content-Length: -1\r\n\r\n".encode())
        self.assertIn("400", linea)

    def test_tipo_de_contenido_obligatorio(self):
        estado, _ = self.pedir("POST", "/api/config", {"dias_para_baja": 5},
                               {"X-Token": self.servidor.app.token, "Content-Type": "text/plain"})
        self.assertEqual(estado, 400)

    def test_csp_con_nonce_sin_unsafe_inline_en_scripts(self):
        con = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=5)
        con.request("GET", "/")
        r = con.getresponse()
        html = r.read().decode()
        csp = r.getheader("Content-Security-Policy")
        con.close()
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'<script nonce="{nonce}">', html)
        self.assertNotIn("unsafe-inline", csp.split("script-src")[1].split(";")[0])
        self.assertIsNotNone(r.getheader("Permissions-Policy"))

    def test_conexion_inactiva_se_cierra(self):
        anterior = web.Manejador.timeout
        web.Manejador.timeout = 1
        try:
            s = socket.create_connection(("127.0.0.1", self.puerto), timeout=5)
            self.assertEqual(s.recv(10), b"")      # el servidor cierra la conexión
            s.close()
        finally:
            web.Manejador.timeout = anterior

    def test_politica_de_contrasena(self):
        for mala in ("corta", "1234567890123", "aaaaaaaaaaaa", "Password2026!", "contraseña"):
            self.assertIsNotNone(web.problema_clave(mala), mala)
        self.assertIsNone(web.problema_clave("tres perros azules en Mariquita"))

    def test_clave_antigua_se_actualiza(self):
        vieja = web.cifrar_clave("frase segura de prueba", iteraciones=200_000)
        self.assertTrue(web.necesita_actualizar(vieja))
        self.assertFalse(web.necesita_actualizar(web.cifrar_clave("frase segura de prueba")))

    def test_sesiones_inactividad_y_cierre(self):
        app = self.servidor.app
        token = app.crear_sesion()
        self.assertTrue(app.sesion_valida(token))
        app.sesiones[token]["ultimo"] -= web.INACTIVIDAD_SESION + 1
        self.assertFalse(app.sesion_valida(token))               # expiró por inactividad
        token = app.crear_sesion()
        app.cerrar_todas_las_sesiones()
        self.assertFalse(app.sesion_valida(token))

    def test_limite_global_de_intentos(self):
        app = web.Aplicacion({}, 0, True)
        for i in range(web.INTENTOS_GLOBALES):
            app.registrar_fallo(f"192.168.1.{i % 250}")
        self.assertFalse(app.puede_intentar("192.168.1.251"))   # IP nueva, pero bloqueo global


# ---------------------------------------------------------------------------
# Versión 0.7: borrar dispositivos y empaquetado
# ---------------------------------------------------------------------------

from detector_red import empaquetado  # noqa: E402


class TestBorrarDispositivos(unittest.TestCase):
    def setUp(self):
        inventario, historial = [], []
        inv.actualizar_con_escaneo(inventario, historial,
                                   {"192.168.1.1": "94:02:6B:D8:EF:35", "192.168.1.5": "AC:DE:48:00:00:05",
                                    "192.168.1.6": "AC:DE:48:00:00:06"}, RED)
        inventario[1]["protegido"] = True
        servicio.guardar_todo(inventario, historial)

    def test_borrar_solo_historial(self):
        self.assertEqual(servicio.borrar_datos(False), 0)
        inventario, historial = servicio.cargar_todo()
        self.assertEqual((len(inventario), historial), (3, []))

    def test_borrar_todo_conservando_protegidos(self):
        self.assertEqual(servicio.borrar_datos(True, conservar_protegidos=True), 2)
        inventario, historial = servicio.cargar_todo()
        self.assertEqual([d["ip"] for d in inventario], ["192.168.1.5"])
        self.assertEqual(historial, [])

    def test_borrar_todo_sin_conservar(self):
        servicio.borrar_datos(True, conservar_protegidos=False)
        self.assertEqual(servicio.cargar_todo()[0], [])

    def test_eliminar_un_dispositivo(self):
        d = servicio.eliminar_dispositivo("192.168.1.6")
        inventario, historial = servicio.cargar_todo()
        self.assertEqual(d["mac"], "AC:DE:48:00:00:06")
        self.assertNotIn("AC:DE:48:00:00:06", [x["mac"] for x in inventario])
        self.assertEqual([e["evento"] for e in historial if e["mac"] == d["mac"]], ["eliminado"])
        self.assertIsNone(servicio.eliminar_dispositivo("no-existe"))


class TestWebEmpaquetado(TestWeb):
    def test_estado_y_descarga_inexistente(self):
        estado, texto = self.pedir("GET", "/api/empaquetado")
        datos = json.loads(texto)
        self.assertEqual(estado, 200)
        self.assertFalse(datos["congelado"])
        self.assertIn("pyinstaller", datos)
        estado, _ = self.pedir("GET", "/api/descargar?tipo=ejecutable")
        self.assertEqual(estado, 404 if not os.path.isfile(empaquetado.ruta_ejecutable()) else 200)
        estado, _ = self.pedir("GET", "/api/descargar?tipo=../../etc/passwd")
        self.assertEqual(estado, 404)

    def test_armar_sin_token_rechazado(self):
        estado, _ = self.pedir("POST", "/api/empaquetado/construir", {})
        self.assertEqual(estado, 403)


class TestBloqueoLocal(TestWeb):
    def test_contrasena_tambien_en_este_pc(self):
        app = self.servidor.app
        cfg = app.cfg
        token = {"X-Token": app.token}
        anterior = dict(cfg)
        try:
            cfg.update(web_clave="", web_bloqueo_local=False)
            estado, _ = self.pedir("POST", "/api/config", {"web_bloqueo_local": True}, token)
            self.assertEqual(estado, 400)                      # sin contraseña no se puede activar
            estado, _ = self.pedir("POST", "/api/config",
                                   {"nueva_clave": "tres perros azules en Mariquita",
                                    "web_bloqueo_local": True}, token)
            self.assertEqual(estado, 200)
            estado, _ = self.pedir("GET", "/api/estado")
            self.assertEqual(estado, 401)                      # ahora este PC también pide clave
            estado, _ = self.pedir("POST", "/api/login", {"clave": "otra cosa"}, token)
            self.assertEqual(estado, 403)
            con = http.client.HTTPConnection("127.0.0.1", self.puerto, timeout=5)
            con.request("POST", "/api/login", body=json.dumps({"clave": "tres perros azules en Mariquita"}),
                        headers=dict(token, **{"Content-Type": "application/json"}))
            r = con.getresponse(); r.read()
            cookie = r.getheader("Set-Cookie").split(";")[0]
            con.close()
            estado, texto = self.pedir("GET", "/api/estado", cabeceras={"Cookie": cookie})
            self.assertEqual(estado, 200)
            self.assertTrue(json.loads(texto)["bloqueo_local"])
        finally:
            cfg.clear(); cfg.update(anterior)
            app.intentos_fallidos.clear(); app.fallos_globales.clear()

    def test_restablecer_clave_por_consola(self):
        from detector_red import main as programa
        cfg = almacenamiento.cargar_config()
        cfg.update(web_clave=web.cifrar_clave("tres perros azules en Mariquita"),
                   web_bloqueo_local=True, web_acceso_red=True)
        almacenamiento.guardar_config(cfg)
        self.assertEqual(programa.main(["--restablecer-clave"]), 0)
        cfg = almacenamiento.cargar_config()
        self.assertEqual((cfg["web_clave"], cfg["web_bloqueo_local"], cfg["web_acceso_red"]), ("", False, False))
