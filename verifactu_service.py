"""
VeriFactu Microservicio - Agencia de IA (Autónomo)
Genera XML firmado, calcula hash encadenado y envía a la AEAT.

Requisitos:
    pip install flask lxml signxml cryptography requests pytz

Variables de entorno necesarias:
    CERT_P12_PATH   → ruta al certificado FNMT (.p12)
    CERT_P12_PASS   → contraseña del certificado
    NIF_EMISOR      → tu NIF de autónomo
    NOMBRE_EMISOR   → tu nombre/razón social
    ENTORNO         → PRE (pruebas) | PRO (producción)
    HASH_STORAGE    → ruta al JSON donde guardar el último hash (default: ultimo_hash.json)

Endpoints:
    POST /emitir       → emite factura y envía a AEAT
    POST /rectificar   → emite factura rectificativa R1
    GET  /health       → estado del servicio
"""

import hashlib
import json
import os
from datetime import datetime
from flask import Flask, request, jsonify
import pytz
import requests
from lxml import etree
from signxml import XMLSigner, methods
from cryptography.hazmat.primitives.serialization import pkcs12

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
app = Flask(__name__)

CERT_PATH    = os.getenv("CERT_P12_PATH", "certificado.p12")
CERT_PASS    = os.getenv("CERT_P12_PASS", "")
NIF_EMISOR   = os.getenv("NIF_EMISOR", "")
NOMBRE_EMISOR= os.getenv("NOMBRE_EMISOR", "")
ENTORNO      = os.getenv("ENTORNO", "PRE")      # PRE | PRO
HASH_FILE    = os.getenv("HASH_STORAGE", "ultimo_hash.json")

AEAT_URL = {
    "PRE": "https://prewww1.aeat.es/wlpl/TIKE-CONT/ws/SistemaFacturacion/FacturaSistemaFacturacion",
    "PRO": "https://www1.aeat.es/wlpl/TIKE-CONT/ws/SistemaFacturacion/FacturaSistemaFacturacion",
}

# Namespace oficial AEAT VeriFactu
NS = "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/SistemaFacturacion.xsd"
T  = f"{{{NS}}}"


# ---------------------------------------------------------------------------
# Utilidades de hash encadenado
# ---------------------------------------------------------------------------
def get_ultimo_hash() -> dict | None:
    """Recupera el hash de la última factura emitida."""
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return None


def guardar_hash(numero: str, fecha: str, huella: str) -> None:
    """Persiste el hash para poder encadenar la próxima factura."""
    data = {
        "IDEmisorFactura": NIF_EMISOR,
        "NumSerieFactura": numero,
        "FechaExpedicionFactura": fecha,
        "Huella": huella,
    }
    with open(HASH_FILE, "w") as f:
        json.dump(data, f, indent=2)


def calcular_huella(factura: dict, hash_anterior: str | None, timestamp: str) -> str:
    """
    Calcula SHA-256 encadenado según especificación AEAT VeriFactu.
    Formato: campo=valor&campo=valor...
    """
    tipo     = factura.get("tipo_factura", "F1")
    cuota    = f"{factura['cuota_iva']:.2f}"
    importe  = f"{factura['total']:.2f}"
    anterior = hash_anterior if hash_anterior else "SIN REGISTRO ANTERIOR"

    cadena = "&".join([
        f"IDEmisorFactura={NIF_EMISOR}",
        f"NumSerieFactura={factura['numero']}",
        f"FechaExpedicionFactura={factura['fecha']}",
        f"TipoFactura={tipo}",
        f"CuotaTotal={cuota}",
        f"ImporteTotal={importe}",
        f"Huella={anterior}",
        f"FechaHoraHusoGenRegistro={timestamp}",
    ])

    return hashlib.sha256(cadena.encode("utf-8")).hexdigest().upper()


# ---------------------------------------------------------------------------
# Generación del XML VeriFactu
# ---------------------------------------------------------------------------
def generar_xml(factura: dict, huella: str, hash_anterior_data: dict | None, timestamp: str) -> etree._Element:
    """Genera el árbol XML con la estructura requerida por la AEAT."""

    root = etree.Element(f"{T}RegFactuSistemaFacturacion", nsmap={"T": NS})

    # --- Cabecera ---
    cab   = etree.SubElement(root, f"{T}Cabecera")
    oblig = etree.SubElement(cab,  f"{T}ObligadoEmision")
    etree.SubElement(oblig, f"{T}NombreRazon").text = NOMBRE_EMISOR
    etree.SubElement(oblig, f"{T}NIF").text         = NIF_EMISOR

    # --- RegistroFactura → RegistroAlta ---
    reg_factura = etree.SubElement(root, f"{T}RegistroFactura")
    reg_alta    = etree.SubElement(reg_factura, f"{T}RegistroAlta")

    etree.SubElement(reg_alta, f"{T}IDVersion").text = "1.0"

    # IDFactura
    id_fac = etree.SubElement(reg_alta, f"{T}IDFactura")
    etree.SubElement(id_fac, f"{T}IDEmisorFactura").text      = NIF_EMISOR
    etree.SubElement(id_fac, f"{T}NumSerieFactura").text      = factura["numero"]
    etree.SubElement(id_fac, f"{T}FechaExpedicionFactura").text = factura["fecha"]

    etree.SubElement(reg_alta, f"{T}NombreRazonEmisor").text  = NOMBRE_EMISOR
    etree.SubElement(reg_alta, f"{T}TipoFactura").text        = factura.get("tipo_factura", "F1")
    etree.SubElement(reg_alta, f"{T}DescripcionOperacion").text = factura["concepto"]

    # Destinatarios
    dests  = etree.SubElement(reg_alta, f"{T}Destinatarios")
    id_dst = etree.SubElement(dests,    f"{T}IDDestinatario")
    etree.SubElement(id_dst, f"{T}NombreRazon").text = factura["cliente_nombre"]

    if factura.get("cliente_pais", "ES") == "ES":
        etree.SubElement(id_dst, f"{T}NIF").text = factura["cliente_nif"]
    else:
        # Cliente extranjero → IDOtro
        id_otro = etree.SubElement(id_dst, f"{T}IDOtro")
        etree.SubElement(id_otro, f"{T}CodigoPais").text = factura["cliente_pais"]
        etree.SubElement(id_otro, f"{T}IDType").text     = "02"  # NIF-IVA intracomunitario
        etree.SubElement(id_otro, f"{T}ID").text         = factura["cliente_nif"]

    # Desglose (IVA)
    desglose = etree.SubElement(reg_alta, f"{T}Desglose")
    detalle  = etree.SubElement(desglose, f"{T}DetalleDesglose")

    # ClaveRegimen: 01=normal, 09=inversión sujeto pasivo
    clave = "09" if factura.get("inversion_sujeto_pasivo") else "01"
    etree.SubElement(detalle, f"{T}ClaveRegimen").text = clave

    if factura.get("inversion_sujeto_pasivo"):
        # Exenta art. 84 LIVA - inversión sujeto pasivo
        etree.SubElement(detalle, f"{T}OperacionExenta").text = "E6"
    else:
        etree.SubElement(detalle, f"{T}TipoImpositivo").text  = str(factura.get("iva_pct", 21))
        etree.SubElement(detalle, f"{T}CuotaRepercutida").text = f"{factura['cuota_iva']:.2f}"

    etree.SubElement(detalle, f"{T}BaseImponibleOimporteNoSujeto").text = f"{factura['base']:.2f}"

    etree.SubElement(reg_alta, f"{T}CuotaTotal").text   = f"{factura['cuota_iva']:.2f}"
    etree.SubElement(reg_alta, f"{T}ImporteTotal").text = f"{factura['total']:.2f}"

    # Encadenamiento
    encaden = etree.SubElement(reg_alta, f"{T}Encadenamiento")
    if hash_anterior_data:
        reg_ant = etree.SubElement(encaden, f"{T}RegistroAnterior")
        etree.SubElement(reg_ant, f"{T}IDEmisorFactura").text       = hash_anterior_data["IDEmisorFactura"]
        etree.SubElement(reg_ant, f"{T}NumSerieFactura").text       = hash_anterior_data["NumSerieFactura"]
        etree.SubElement(reg_ant, f"{T}FechaExpedicionFactura").text= hash_anterior_data["FechaExpedicionFactura"]
        etree.SubElement(reg_ant, f"{T}Huella").text                = hash_anterior_data["Huella"]
    else:
        # Primera factura del registro
        etree.SubElement(encaden, f"{T}PrimerRegistro").text = "S"

    # Sistema Informático (datos de tu SIF)
    sis = etree.SubElement(reg_alta, f"{T}SistemaInformatico")
    etree.SubElement(sis, f"{T}NombreRazon").text              = NOMBRE_EMISOR
    etree.SubElement(sis, f"{T}NIF").text                      = NIF_EMISOR
    etree.SubElement(sis, f"{T}NombreSistemaInformatico").text = "SIF Facturacion n8n"
    etree.SubElement(sis, f"{T}IdSistemaInformatico").text     = "SIF001"
    etree.SubElement(sis, f"{T}Version").text                  = "1.0"
    etree.SubElement(sis, f"{T}NumeroInstalacion").text        = "1"
    etree.SubElement(sis, f"{T}TipoUsoPosibleSoloVerifactu").text = "S"
    etree.SubElement(sis, f"{T}TipoUsoPosibleMultiOT").text       = "N"
    etree.SubElement(sis, f"{T}IndicadorMultiplesOT").text         = "N"

    etree.SubElement(reg_alta, f"{T}FechaHoraHusoGenRegistro").text = timestamp
    etree.SubElement(reg_alta, f"{T}TipoHuella").text               = "01"  # SHA-256
    etree.SubElement(reg_alta, f"{T}Huella").text                   = huella

    return root


# ---------------------------------------------------------------------------
# Firma XMLDSig con certificado FNMT
# ---------------------------------------------------------------------------
def firmar_xml(root: etree._Element) -> etree._Element:
    """
    Firma el XML con el certificado digital del autónomo.
    Necesitas el fichero .p12 del FNMT (Fábrica Nacional de Moneda y Timbre).
    Precio orientativo certificado: ~15€/año en gestorías online, gratis directo en FNMT.
    """
    with open(CERT_PATH, "rb") as f:
        p12_data = f.read()

    private_key, certificate, chain = pkcs12.load_key_and_certificates(
        p12_data,
        CERT_PASS.encode("utf-8") if CERT_PASS else None,
    )

    signer = XMLSigner(
        method=methods.enveloped,
        digest_algorithm="sha256",
        signature_algorithm="rsa-sha256",
    )

    signed = signer.sign(
        root,
        key=private_key,
        cert=certificate,
        certchain=chain,
    )

    return signed


# ---------------------------------------------------------------------------
# Envío a la AEAT
# ---------------------------------------------------------------------------
def enviar_a_aeat(signed_xml: etree._Element) -> requests.Response:
    url     = AEAT_URL.get(ENTORNO, AEAT_URL["PRE"])
    xml_str = etree.tostring(signed_xml, xml_declaration=True, encoding="UTF-8")
    headers = {"Content-Type": "application/xml", "Accept": "application/xml"}
    return requests.post(url, data=xml_str, headers=headers, timeout=30)


# ---------------------------------------------------------------------------
# URL de verificación QR para el PDF
# ---------------------------------------------------------------------------
def generar_qr_url(numero: str, fecha: str, importe: float) -> str:
    base   = "https://www2.agenciatributaria.gob.es/wlpl/TIKE-CONT/ValidarQR"
    params = f"nif={NIF_EMISOR}&numserie={numero}&fecha={fecha}&importe={importe:.2f}"
    return f"{base}?{params}"


# ---------------------------------------------------------------------------
# Timestamp con huso horario España
# ---------------------------------------------------------------------------
def get_timestamp_spain() -> str:
    tz  = pytz.timezone("Europe/Madrid")
    now = datetime.now(tz)
    ts  = now.strftime("%Y-%m-%dT%H:%M:%S%z")
    return ts[:-2] + ":" + ts[-2:]  # Añadir : al offset → +01:00


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.route("/emitir", methods=["POST"])
def emitir_factura():
    """
    Cuerpo JSON esperado desde n8n:
    {
        "numero":          "2025-0001",
        "fecha":           "01-01-2025",     ← DD-MM-YYYY
        "concepto":        "Consultoría IA",
        "cliente_nombre":  "Empresa S.L.",
        "cliente_nif":     "B12345678",
        "cliente_pais":    "ES",             ← ISO 3166-1 alpha-2
        "cliente_vat":     "",               ← VAT EU si aplica
        "base":            1000.00,
        "iva_pct":         21,
        "cuota_iva":       210.00,
        "inversion_sujeto_pasivo": false,
        "irpf_pct":        15,
        "retencion_irpf":  150.00,
        "total":           1060.00          ← base + IVA - retención
    }
    """
    try:
        factura = request.get_json(force=True)

        hash_anterior_data = get_ultimo_hash()
        hash_anterior      = hash_anterior_data["Huella"] if hash_anterior_data else None
        timestamp          = get_timestamp_spain()

        huella   = calcular_huella(factura, hash_anterior, timestamp)
        xml_root = generar_xml(factura, huella, hash_anterior_data, timestamp)

        signed_xml = firmar_xml(xml_root)
        response   = enviar_a_aeat(signed_xml)

        if response.status_code not in (200, 201):
            return jsonify({
                "ok":     False,
                "error":  "Error en AEAT",
                "status": response.status_code,
                "detail": response.text,
            }), 502

        guardar_hash(factura["numero"], factura["fecha"], huella)

        qr_url = generar_qr_url(factura["numero"], factura["fecha"], factura["total"])

        return jsonify({
            "ok":           True,
            "numero":       factura["numero"],
            "huella":       huella,
            "qr_url":       qr_url,
            "timestamp":    timestamp,
            "aeat_response": response.text,
        })

    except FileNotFoundError:
        return jsonify({"ok": False, "error": "Certificado .p12 no encontrado. Revisa CERT_P12_PATH."}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/rectificar", methods=["POST"])
def rectificar_factura():
    """
    Genera una factura rectificativa R1.
    Cuerpo JSON: igual que /emitir pero añade:
    {
        "tipo_factura":            "R1",
        "factura_rectificada_num": "2025-0001",
        "factura_rectificada_fecha": "01-01-2025",
        "motivo_rectificacion":    "Error en importe"
    }
    """
    try:
        factura = request.get_json(force=True)
        factura["tipo_factura"] = "R1"
        request.environ["RAW_BODY"] = None

        # Reutilizamos la lógica de /emitir
        hash_anterior_data = get_ultimo_hash()
        hash_anterior      = hash_anterior_data["Huella"] if hash_anterior_data else None
        timestamp          = get_timestamp_spain()

        huella   = calcular_huella(factura, hash_anterior, timestamp)
        xml_root = generar_xml(factura, huella, hash_anterior_data, timestamp)
        signed_xml = firmar_xml(xml_root)
        response   = enviar_a_aeat(signed_xml)

        if response.status_code not in (200, 201):
            return jsonify({"ok": False, "error": response.text}), 502

        guardar_hash(factura["numero"], factura["fecha"], huella)
        qr_url = generar_qr_url(factura["numero"], factura["fecha"], factura["total"])

        return jsonify({
            "ok":        True,
            "tipo":      "R1",
            "numero":    factura["numero"],
            "huella":    huella,
            "qr_url":    qr_url,
            "timestamp": timestamp,
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    cert_ok = os.path.exists(CERT_PATH)
    return jsonify({
        "status":   "ok",
        "entorno":  ENTORNO,
        "nif":      NIF_EMISOR,
        "cert_ok":  cert_ok,
    })


# ---------------------------------------------------------------------------
# Arranque
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"VeriFactu Service - Entorno: {ENTORNO}")
    print(f"NIF Emisor: {NIF_EMISOR or 'NO CONFIGURADO'}")
    print(f"Certificado: {CERT_PATH} ({'OK' if os.path.exists(CERT_PATH) else 'NO ENCONTRADO'})")
    app.run(host="0.0.0.0", port=5000, debug=False)
