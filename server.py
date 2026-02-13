import os
import httpx
import logging
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

# Importamos las queries
from queries import SEARCH_QUERY, GET_OBSERVABLE_QUERY, GET_ENTITY_QUERY

# Cargar variables de entorno
load_dotenv()

# Configuración
OPENCTI_URL = os.getenv("OPENCTI_URL")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("opencti-mcp")

if not OPENCTI_URL or not OPENCTI_TOKEN:
    raise ValueError("Faltan OPENCTI_URL o OPENCTI_TOKEN en el archivo .env")

# Inicializar FastMCP
# FastMCP maneja automáticamente el servidor SSE y los endpoints
mcp = FastMCP("OpenCTI Manager")

class OpenCTIClient:
    """
    Cliente HTTP robusto para OpenCTI.
    Maneja la conexión, headers y errores de GraphQL.
    """
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/") + "/graphql"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "MCP-OpenCTI-Agent/1.0"
        }
    
    async def execute_query(self, query: str, variables: Dict[str, Any] = None) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                payload = {"query": query, "variables": variables or {}}
                logger.debug(f"Enviando query a OpenCTI: {variables}")
                
                response = await client.post(
                    self.base_url, 
                    json=payload, 
                    headers=self.headers
                )
                
                response.raise_for_status()
                data = response.json()
                
                if "errors" in data:
                    error_msg = f"Error GraphQL: {data['errors'][0]['message']}"
                    logger.error(error_msg)
                    raise ToolError(error_msg)
                
                return data.get("data", {})
                
            except httpx.HTTPStatusError as e:
                logger.error(f"Error HTTP {e.response.status_code}: {e.response.text}")
                raise ToolError(f"Error de conexión con OpenCTI: {e.response.status_code}")
            except httpx.RequestError as e:
                logger.error(f"Error de red: {str(e)}")
                raise ToolError(f"No se pudo conectar al servidor OpenCTI: {str(e)}")
            except Exception as e:
                logger.error(f"Error inesperado: {str(e)}")
                raise ToolError(f"Error interno: {str(e)}")

# Instancia del cliente
client = OpenCTIClient(OPENCTI_URL, OPENCTI_TOKEN)

# --- Definición de Herramientas (Tools) ---

@mcp.tool()
async def search_knowledge_base(keyword: str, limit: int = 10) -> str:
    """
    Busca en la base de conocimientos de OpenCTI cualquier entidad u observable.
    Útil para encontrar IDs o verificar si algo existe.
    
    Args:
        keyword: El término a buscar (nombre, IP, hash, etc.)
        limit: Número máximo de resultados (default 10)
    """
    data = await client.execute_query(SEARCH_QUERY, {"search": keyword, "first": limit})
    
    edges = data.get("globalSearch", {}).get("edges", [])
    if not edges:
        return "No se encontraron resultados."
    
    results = []
    for edge in edges:
        node = edge["node"]
        # Formateo simple para que el LLM lo entienda
        name = node.get("name") or node.get("observable_value") or "Desconocido"
        desc = node.get("description") or node.get("x_opencti_description") or "Sin descripción"
        results.append(f"- [{node['entity_type']}] {name} (ID: {node['id']}): {desc}")
        
    return "\n".join(results)

@mcp.tool()
async def get_observable_details(value: str) -> str:
    """
    Obtiene inteligencia detallada sobre un observable técnico (IP, Dominio, Hash SHA256, etc.).
    Devuelve indicadores relacionados y reportes donde aparece.
    
    Args:
        value: El valor del observable (ej. '8.8.8.8', 'wannacry.exe')
    """
    data = await client.execute_query(GET_OBSERVABLE_QUERY, {"value": value})
    
    edges = data.get("stixCyberObservables", {}).get("edges", [])
    if not edges:
        return f"No se encontró información para el observable: {value}"
    
    node = edges[0]["node"]
    
    # Procesar relaciones
    indicators = [i["node"]["name"] for i in node.get("indicators", {}).get("edges", [])]
    reports = [f"{r['node']['name']} ({r['node']['published']})" for r in node.get("reports", {}).get("edges", [])]
    
    output = [
        f"Tipo: {node['entity_type']}",
        f"Valor: {node['observable_value']}",
        f"Score: {node.get('x_opencti_score') or 'N/A'}",
        f"Descripción: {node.get('x_opencti_description') or 'N/A'}",
        f"Indicadores asociados: {', '.join(indicators) if indicators else 'Ninguno'}",
        f"Mencionado en reportes: {', '.join(reports) if reports else 'Ninguno'}"
    ]
    
    return "\n".join(output)

@mcp.tool()
async def get_threat_entity(name: str) -> str:
    """
    Obtiene información estratégica sobre una entidad (Threat Actor, Malware, Intrusion Set).
    
    Args:
        name: El nombre exacto o parcial de la entidad (ej. 'APT28', 'Emotet')
    """
    data = await client.execute_query(GET_ENTITY_QUERY, {"name": name})
    
    edges = data.get("stixDomainObjects", {}).get("edges", [])
    if not edges:
        return f"No se encontró la entidad: {name}"
    
    # Tomamos el primer resultado más relevante
    node = edges[0]["node"]
    
    output = [
        f"Nombre: {node['name']}",
        f"Tipo: {node['entity_type']}",
        f"Descripción: {node.get('description') or 'N/A'}",
        f"Creado: {node.get('created') or 'N/A'}"
    ]
    
    if node['entity_type'] == 'Threat-Actor':
        output.append(f"Tipos: {node.get('threat_actor_types', [])}")
        output.append(f"Objetivos: {node.get('goals', [])}")
    
    if node['entity_type'] == 'Malware':
        output.append(f"Familia de malware: {node.get('is_family', False)}")
    
    return "\n".join(output)

if __name__ == "__main__":
    # FastMCP expone el servidor SSE por defecto
    mcp.run()
