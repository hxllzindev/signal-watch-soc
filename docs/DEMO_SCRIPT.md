# Roteiro de demonstração

## Pitch de 5 minutos

**00:00 - Contexto**

“O Signal Watch é um Mini SIEM que construí para mostrar o fluxo completo de uma operação de segurança: telemetria entra, é normalizada, passa por regras, vira alerta e pode evoluir para uma investigação.”

**00:40 - Visão geral**

Mostre métricas, severidade, táticas MITRE e saúde das fontes. Explique que os dados iniciais incluem identidade, web, endpoint, rede e cloud.

**01:20 - Detecção em tempo real**

Clique em **Simular ataque**. A sequência gera cinco falhas e um login bem-sucedido. O motor cria um alerta T1110 e outro T1078, correlacionando usuário e IP dentro da janela temporal.

**02:10 - Triagem**

Abra o alerta crítico, percorra as evidências cronológicas, mude o status para Investigando, atribua um responsável e registre uma nota.

**03:00 - Resposta a incidente**

Clique em **Criar caso**. Mostre o vínculo entre alerta, responsável, severidade e timeline da investigação.

**03:40 - Threat hunt**

Pesquise pelo usuário `demo.user1` ou pelo IP apresentado no alerta. Destaque que eventos diferentes compartilham um esquema normalizado.

**04:15 - Detection engineering e RBAC**

Troque para **Líder SOC**, altere o limite da regra de brute force e depois use **Visualizador** para mostrar que escrita é bloqueada pela API, não apenas pela interface.

**04:50 - Encerramento**

“Eu mantive o núcleo sem dependências para deixar visíveis as decisões de segurança. A documentação descreve como evoluir para Kafka, OpenSearch e autenticação OIDC em produção.”

## Perguntas que o projeto ajuda a responder

- Como você evita alertas duplicados?
- Como correlaciona eventos em uma janela temporal?
- Como preserva evidência para investigação?
- Qual a diferença entre regra de match e de correlação?
- Como escalaria ingestão e armazenamento?
- Onde aplicaria autenticação e isolamento multi-tenant?
