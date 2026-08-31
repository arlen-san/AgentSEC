import asyncio
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.markdown import Markdown

from agentsec.config.settings import settings
from agentsec.connectors.registry import create_registry
from agentsec.agent.orchestrator import SecurityAgent

console = Console()

async def async_main():
    console.print(Panel.fit("[bold blue]🛡️ AgentSEC - Agente de Segurança com IA[/]", border_style="cyan"))
    
    # Initialize registry
    registry = create_registry(use_mock=settings.use_mock_data)
    
    # Status table
    table = Table(title="Status dos Conectores", show_header=True, header_style="bold magenta")
    table.add_column("Conector", style="cyan")
    table.add_column("Status", style="green")
    
    mode = "Mock" if settings.use_mock_data else "Real"
    table.add_row("Microsoft Defender", mode)
    table.add_row("NVD CVE", mode)
    table.add_row("CISA KEV", mode)
    table.add_row("EPSS", mode)
    table.add_row("QuimeraX CTI", mode)
    
    console.print(table)
    
    if not settings.gemini_api_key:
        console.print("[bold yellow]Aviso:[/] A variável GEMINI_API_KEY não está configurada. O LLM não responderá.")
        
    agent = SecurityAgent(settings, registry)
    
    console.print("\n[bold green]Agente inicializado. Digite /help para comandos ou faça uma pergunta.[/]\n")
    
    last_response = ""
    
    while True:
        try:
            user_input = Prompt.ask("[bold cyan]AgentSEC[/]")
            if not user_input.strip():
                continue
                
            cmd = user_input.strip().lower()
            if cmd == "/quit" or cmd == "exit":
                console.print("[bold yellow]Encerrando o AgentSEC...[/]")
                break
            elif cmd == "/help":
                help_text = """
**Comandos Disponíveis:**
- `/help`: Mostra esta ajuda
- `/status`: Mostra o status do sistema e conectores
- `/briefing`: Ranking priorizado de ameaças (Visão SOC)
- `/compliance`: Relatório Executivo de Risco (GRC, BACEN, Itaú/Rabobank)
- `/export`: Exporta a última resposta para um arquivo Markdown
- `/clear`: Limpa a tela
- `/quit`: Encerra o agente
                """
                console.print(Markdown(help_text))
                continue
            elif cmd == "/status":
                console.print(table)
                console.print(f"Modelo LLM: {settings.llm_model}")
                continue
            elif cmd == "/clear":
                console.clear()
                continue
            elif cmd == "/compliance":
                user_input = (
                    "Aja como o CISO (Chief Information Security Officer) ou Diretor de Risco da "
                    "Fintech/Agtech composta pela 'Nagro' e 'AgRisk'. Analise as ameaças ativas atuais "
                    "(colete dados no Defender e QuimeraX) sob uma ótica estrita de Governança, Risco e Compliance (GRC). "
                    "Correlacione as falhas encontradas com a **Resolução CMN 4.893/2021 do BACEN** (Política de Segurança Cibernética) "
                    "e com o Risco de reprovação em auditorias de Due Diligence de grandes investidores (como Itaú e Rabobank). "
                    "Gere um relatório executivo destacando os impactos de negócios (perda de credibilidade, vazamento de dados de "
                    "crédito rural) e forneça um plano de ação imediato para gerar evidências de auditoria."
                )
            elif cmd == "/export":
                if not last_response:
                    console.print("[bold red]Não há nenhuma análise anterior para exportar.[/]")
                    continue
                
                import datetime
                filename = f"relatorio_soc_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(last_response)
                console.print(f"[bold green]✅ Relatório exportado com sucesso para: {filename}[/]")
                continue
            elif cmd == "/briefing":
                user_input = (
                    "Faça um briefing detalhado do ambiente atual do SOC. "
                    "Primeiro, execute as ferramentas para coletar Alertas do Defender, "
                    "Vulnerabilidades do TVM (Defender) e IOCs/Alertas do QuimeraX. "
                    "Depois de coletar tudo, crie um **Ranking de Prioridade de Atuação (Top 5)** "
                    "para que os analistas saibam exatamente onde atuar agora. "
                    "Justifique as prioridades (ex: CVE crítica + presente na KEV, ou "
                    "credencial vazada no Quimera, etc). "
                    "Use emojis e seja muito direto na ação sugerida."
                )
                
            # Chat with agent with dynamic status update
            status = console.status("[bold green]AgentSEC está processando...[/]", spinner="bouncingBar")
            status.start()
            
            def update_status(msg: str):
                status.update(f"[bold green]AgentSEC[/]: {msg}")
                
            try:
                response = await agent.chat(user_input, status_callback=update_status)
                last_response = response # Salva para o /export
            finally:
                status.stop()
                
            console.print(Markdown(response))
            console.print()
        
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Encerrando...[/]")
            break
        except Exception as e:
            console.print(f"[bold red]Erro:[/] {str(e)}")

def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
