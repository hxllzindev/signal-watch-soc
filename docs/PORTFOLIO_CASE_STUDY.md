# Estudo de caso: Signal Watch SOC

## Problema

Certificados mostram estudo, mas vagas de segurança também exigem evidência de raciocínio operacional. O objetivo foi construir um projeto que conectasse experiência full stack a tarefas reais de Blue Team: engenharia de detecção, triagem, hunting e resposta a incidentes.

## Solução

Criei uma plataforma independente que recebe eventos de fontes diferentes e os converte em um esquema comum. Um motor executa regras simples e correlações temporais, preserva as evidências que explicam cada decisão e apresenta os resultados em um console operacional.

## Decisões relevantes

- **Explicabilidade:** todo alerta aponta para eventos concretos e uma regra MITRE.
- **Baixa superfície de supply chain:** o runtime não possui dependências npm.
- **Defesa em profundidade:** validação no servidor, CSP, RBAC e container restrito.
- **Demonstração reproduzível:** um botão cria uma cadeia de ataque determinística.
- **Separação de responsabilidades:** normalizadores, regras, engine, API e interface são módulos distintos.

## Resultado mensurável

- 5 formatos de fonte especializados e 1 formato genérico.
- 6 regras mapeadas ao MITRE ATT&CK.
- 2 regras de correlação temporal.
- 3 papéis de autorização.
- 11 testes automatizados cobrindo engine, normalização e API.
- 1 fluxo completo de alerta até caso de investigação.

## Aprendizados

Uma detecção útil não é apenas uma expressão que encontra texto. Ela precisa de contexto, janela temporal, entidades estáveis, deduplicação, evidência e um fluxo de trabalho para o analista. A maior parte do valor do projeto está nessa conexão entre engenharia de software e operação de segurança.
