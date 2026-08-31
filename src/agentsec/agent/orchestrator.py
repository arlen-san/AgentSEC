import asyncio
from typing import Callable
from google import genai
from google.genai import types

from agentsec.agent.prompts import SYSTEM_PROMPT
from agentsec.agent import tools

class SecurityAgent:
    def __init__(self, settings, registry):
        self._settings = settings
        self._registry = registry
        self._model = settings.llm_model
        # Initialize client if API key exists
        if settings.gemini_api_key:
            self._client = genai.Client(api_key=settings.gemini_api_key)
        else:
            self._client = None
            
        self._history: list[types.Content] = []
        self._tool_functions = self._build_tool_functions()
        self._tool_map = self._build_tool_map()

    def _build_tool_functions(self):
        """Builds Python functions that don't require registry, for Gemini to call."""
        
        def search_alerts(severity: str = "", status: str = "", limit: int = 10) -> str:
            """Busca alertas de segurança do Microsoft Defender."""
            pass
            
        def get_incidents(status: str = "", limit: int = 10) -> str:
            """Busca incidentes de segurança do Microsoft Defender."""
            pass
            
        def get_defender_vulnerabilities(limit: int = 10) -> str:
            """Obtém as vulnerabilidades reportadas no ambiente via Defender TVM."""
            pass

        def lookup_cve(cve_id: str) -> str:
            """Busca detalhes de uma CVE no NVD."""
            pass

        def triage_cve(cve_id: str) -> str:
            """Faz a triagem inteligente de uma única CVE calculando o score composto."""
            pass

        def triage_cves(cve_ids: list[str]) -> str:
            """Faz a triagem em lote de múltiplas CVEs."""
            pass

        def search_iocs(query: str, ioc_type: str = "") -> str:
            """Busca por Indicadores de Comprometimento (IOCs) no QuimeraX."""
            pass

        def get_leaked_credentials(domain: str) -> str:
            """Verifica credenciais vazadas para um domínio específico."""
            pass

        def generate_summary(topic: str) -> str:
            """Gera um resumo executivo para um tópico específico ('alerts', 'threat_intel')."""
            pass

        return [
            search_alerts, get_incidents, get_defender_vulnerabilities,
            lookup_cve, triage_cve, triage_cves, search_iocs,
            get_leaked_credentials, generate_summary
        ]

    def _build_tool_map(self):
        """Maps function names to the actual async tool implementations."""
        return {
            "search_alerts": tools.search_alerts,
            "get_incidents": tools.get_incidents,
            "get_defender_vulnerabilities": tools.get_defender_vulnerabilities,
            "lookup_cve": tools.lookup_cve,
            "triage_cve": tools.triage_cve,
            "triage_cves": tools.triage_cves,
            "search_iocs": tools.search_iocs,
            "get_leaked_credentials": tools.get_leaked_credentials,
            "generate_summary": tools.generate_summary
        }

    async def _execute_tool(self, name: str, args: dict) -> str:
        """Executes the mapped tool function with the registry injected."""
        if name not in self._tool_map:
            return f"Error: Tool {name} not found."
            
        func = self._tool_map[name]
        try:
            return await func(self._registry, **args)
        except Exception as e:
            return f"Error executing {name}: {str(e)}"

    async def chat(self, user_message: str, status_callback: Callable[[str], None] | None = None) -> str:
        if not self._client:
            return "Erro: GEMINI_API_KEY não configurada. A geração de LLM está indisponível."
            
        # Initialize chat session if it doesn't exist
        if not hasattr(self, "_chat_session"):
            self._chat_session = self._client.chats.create(
                model=self._model,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    tools=self._tool_functions,
                )
            )
            
        if status_callback:
            status_callback("Analisando intenção e contexto...")
            
        response = self._chat_session.send_message(user_message)
        
        while response.function_calls:
            function_responses = []
            for fc in response.function_calls:
                if status_callback:
                    status_callback(f"Executando ferramenta de segurança: {fc.name}...")
                    
                args = fc.args if isinstance(fc.args, dict) else dict(fc.args)
                result = await self._execute_tool(fc.name, args)
                function_responses.append(
                    types.Part.from_function_response(
                        name=fc.name,
                        response={"result": result}
                    )
                )
            
            if status_callback:
                status_callback("Processando resultados obtidos...")
                
            # Send tool results back to the model
            response = self._chat_session.send_message(function_responses)
            
        return response.text
