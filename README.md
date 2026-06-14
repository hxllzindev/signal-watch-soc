# Signal Watch SOC

Mini SIEM full stack criado para demonstrar engenharia de detecção, investigação de alertas e resposta a incidentes. A aplicação ingere eventos heterogêneos, normaliza a telemetria, executa regras de correlação e organiza o trabalho de um SOC em alertas e casos.

## O que este projeto demonstra

- Pipeline de eventos para identidade, web, endpoint, rede, cloud e JSON genérico.
- Esquema normalizado inspirado em ECS, preservando o evento bruto para investigação.
- Seis regras de detecção com mapeamento MITRE ATT&CK.
- Correlação temporal, agregação por entidade e deduplicação por fingerprint.
- Triagem com status, responsável, notas, evidências e trilha de auditoria.
- Casos de investigação vinculados a alertas e linha do tempo.
- Threat hunting por IP, usuário, host, processo, fonte, categoria e resultado.
- RBAC demonstrável por perfis Analista, Líder SOC e Visualizador.
- Container sem privilégios, filesystem somente leitura e pipeline de segurança.

## Executar

Com Docker:

```bash
docker compose up --build -d
```

Acesse [http://localhost:5000](http://localhost:5000). Para encerrar:

```bash
docker compose down
```

Com Node.js 20 ou superior:

```bash
node src/server.js
```

## Testes

```bash
node --test
node --check src/server.js
node --check src/public/app.js
```

A suíte cobre normalização, regras de match e correlação, deduplicação, headers de segurança, ingestão, simulação, triagem, casos e autorização.

## Demonstração rápida

1. Abra **Visão geral** para apresentar telemetria e postura operacional.
2. Clique em **Simular ataque** para gerar cinco falhas seguidas por um login válido.
3. Abra o alerta crítico, atribua um analista, registre uma nota e crie um caso.
4. Use **Threat hunt** para pesquisar o IP ou usuário da simulação.
5. Troque para **Líder SOC** e altere o limite de uma regra.
6. Troque para **Visualizador** e demonstre o bloqueio de ações de escrita.

O roteiro completo está em [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).

## Documentação

- [Arquitetura](docs/ARCHITECTURE.md)
- [API e esquema de eventos](docs/API.md)
- [Roteiro de demonstração](docs/DEMO_SCRIPT.md)
- [Estudo de caso para portfólio](docs/PORTFOLIO_CASE_STUDY.md)
- [Política de segurança](SECURITY.md)

## Decisões técnicas

O projeto usa apenas APIs nativas do Node.js. Isso reduz a superfície de dependências e deixa explícitos os componentes centrais: servidor HTTP, normalização, motor de detecção e armazenamento em memória. Em produção, o contrato da API permite substituir o armazenamento por OpenSearch, ClickHouse, PostgreSQL ou um data lake sem reescrever a interface.

Os dados são sintéticos e reservados para demonstração. Não use o projeto como substituto direto de um SIEM de produção.
